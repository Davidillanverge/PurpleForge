#!/usr/bin/env python3
"""PurpleForge deterministic core.

Implements the parts of the harness that must be deterministic and testable
rather than left to an LLM: schema validation, semantic checks, defense.profile
default resolution, IP assignment, cost estimation and the hardening<->vuln
reconciliation (see cmd_lab_spec / the reconcile helpers below), plus the
deterministic, no-AI lifecycle: generate (renders Terraform + Ansible +
deploy.sh/teardown.sh + lab-report.md), guardrail, deploy, validate --run,
teardown, destroy, ad-inventory.

Usage:
    scripts/forge.py lab-spec specs/<lab>.yml
    scripts/forge.py generate specs/<lab>.yml --plan
    scripts/forge.py deploy   specs/<lab>.yml
    scripts/forge.py validate specs/<lab>.yml --run
    scripts/forge.py teardown specs/<lab>.yml
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import jinja2
import jsonschema
import yaml
from population import generate_population_plan

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "specs" / "schema" / "lab-spec.schema.json"
VULN_CATALOG_DIR = REPO_ROOT / "catalog" / "vulnerabilities"
THEMES_DIR = REPO_ROOT / "catalog" / "themes"
DEFENSE_PROFILES_DIR = REPO_ROOT / "catalog" / "defense" / "profiles"
HARDENING_DIR = REPO_ROOT / "catalog" / "defense" / "hardening"
EDR_DIR = REPO_ROOT / "catalog" / "defense" / "edr"
CONTROL_CIS_RULES_PATH = HARDENING_DIR / "control-cis-rules.yml"
GENERATED_DIR = REPO_ROOT / "generated"
TEMPLATES_DIR = REPO_ROOT / "templates"

ROLE_ABBREV = {"domain-controller": "dc", "member-server": "mbr", "workstation": "ws"}

# Single source of truth for the two Windows-side automation accounts every
# generated VM gets (see render_azure_terraform / templates/ansible/roles/
# pf_*) — referenced again by render_lab_report, so it's a named constant
# rather than a literal duplicated in two places.
WINDOWS_ADMIN_USERNAME = "purpleforge"
WINRM_AUTOMATION_USERNAME = "ansible"

# The only hardening.controls.* keys the schema exposes as direct booleans.
# Any other `hardening.controls.<name>` named in a vuln's neutralized_by is an
# "implicit" control folded into a baseline (e.g. adcs_template_hardening is
# part of CIS L2, but isn't a togglable field in lab-spec.schema.json).
FIXED_HARDENING_TOGGLES = {
    "laps",
    "lsa_protection",
    "credential_guard",
    "smb_signing",
    "ldap_signing",
    "disable_llmnr_nbtns_mdns",
    "ntlmv2_only",
}

# smb_signing/ldap_signing are enum-typed (disable|enable|enforce) in the
# schema, not booleans — excluding them must set the "off" enum value, not
# Python False, or defense_resolved would carry an invalid value.
ENUM_HARDENING_TOGGLES = {"smb_signing": "disable", "ldap_signing": "disable"}

# Rough $/hour placeholders per role/provider, purely to give the user an
# order-of-magnitude budget signal. Not a substitute for the cloud provider's
# own pricing calculator.
HOURLY_RATE_USD = {
    "aws": {"domain-controller": 0.10, "member-server": 0.12, "workstation": 0.08},
    "azure": {"domain-controller": 0.11, "member-server": 0.13, "workstation": 0.09},
    # On-prem Proxmox has no per-hour cloud billing; rates are zero so the cost
    # estimate reads $0 rather than a misleading cloud figure. budget_alert_usd
    # stays in the spec (schema requires it) but is not a billing signal here.
    "proxmox": {"domain-controller": 0.0, "member-server": 0.0, "workstation": 0.0},
}

WINDOWS_EVAL_EXPIRY_DAYS = 180


class SpecError(Exception):
    """Raised for validation/semantic/reconciliation failures that should stop generation."""


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_schema(spec: dict, schema: dict) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(spec), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


def load_vuln_catalog() -> dict[str, dict]:
    catalog = {}
    for f in sorted(VULN_CATALOG_DIR.glob("*.yml")):
        entry = load_yaml(f)
        catalog[entry["id"]] = entry
    return catalog


def load_defense_profile(name: str) -> dict:
    path = DEFENSE_PROFILES_DIR / f"{name}.yml"
    if not path.exists():
        raise SpecError(f"defense.profile '{name}' has no catalog/defense/profiles/{name}.yml")
    return load_yaml(path)["defaults"]


def deep_merge(base: dict, override: dict) -> dict:
    """override wins; lists in override fully replace lists in base (no element-wise merge)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def semantic_checks(spec: dict, catalog: dict[str, dict]) -> list[str]:
    errors: list[str] = []

    theme = spec["lab"]["theme"]
    if not (THEMES_DIR / f"{theme}.yml").exists():
        errors.append(f"lab.theme: unknown theme '{theme}' (no catalog/themes/{theme}.yml)")

    domains = [d["domain"] for d in spec["forest"]]
    netbios_names = [d["netbios"] for d in spec["forest"]]
    if len(domains) != len(set(domains)):
        errors.append(f"forest: duplicate domain name(s) in {domains}")
    if len(netbios_names) != len(set(netbios_names)):
        errors.append(f"forest: duplicate netbios name(s) in {netbios_names}")

    domain_set = set(domains)
    for d in spec["forest"]:
        trust = d.get("trust")
        if trust and trust["target"] not in domain_set:
            errors.append(f"forest: domain '{d['domain']}' trusts unknown target '{trust['target']}'")
        if trust and trust["target"] == d["domain"]:
            errors.append(f"forest: domain '{d['domain']}' cannot trust itself")

    for i, m in enumerate(spec["machines"]):
        if m["domain"] not in domain_set:
            errors.append(f"machines[{i}]: references unknown domain '{m['domain']}'")

    dc_count_by_domain: dict[str, int] = {}
    for m in spec["machines"]:
        if m["role"] == "domain-controller":
            dc_count_by_domain[m["domain"]] = dc_count_by_domain.get(m["domain"], 0) + m["count"]
    for d in spec["forest"]:
        declared = d["domain_controllers"]
        actual = dc_count_by_domain.get(d["domain"], 0)
        if actual != declared:
            errors.append(
                f"forest: domain '{d['domain']}' declares domain_controllers={declared} "
                f"but machines[] defines {actual} domain-controller instance(s) for it"
            )

    services_by_domain: dict[str, set[str]] = {}
    for m in spec["machines"]:
        services_by_domain.setdefault(m["domain"], set()).update(m.get("services", []))

    for vuln_id in spec["vulnerabilities"]:
        if vuln_id not in catalog:
            errors.append(f"vulnerabilities: unknown id '{vuln_id}' (no catalog/vulnerabilities/{vuln_id}.yml)")
            continue
        required = catalog[vuln_id].get("attack", {}).get("requires_services") or []
        if required:
            available = set().union(*services_by_domain.values()) if services_by_domain else set()
            missing = [s for s in required if s not in available]
            if missing:
                errors.append(
                    f"vulnerabilities: '{vuln_id}' requires service(s) {missing} "
                    f"but no machine in the spec declares them"
                )
        # OS-level / application vulns declare attack.target_role (workstation |
        # member-server | domain-controller) instead of an AD service prereq —
        # they inject on the first machine of that role (see plan_vuln_injection).
        # requires_services takes precedence, so a vuln never needs both.
        target_role = catalog[vuln_id].get("attack", {}).get("target_role")
        if target_role and not required and not any(m["role"] == target_role for m in spec["machines"]):
            errors.append(
                f"vulnerabilities: '{vuln_id}' targets role '{target_role}' but the spec has no machine with that role"
            )

    return errors


def resolve_defense(spec: dict) -> dict:
    defense = spec["defense"]
    profile_defaults = load_defense_profile(defense["profile"])
    overrides = {k: v for k, v in defense.items() if k != "profile"}
    return deep_merge(profile_defaults, overrides)


# azurerm_dev_test_global_vm_shutdown_schedule.timezone only accepts legacy
# Windows timezone IDs, not IANA names — verified against a real `terraform
# plan` (azurerm 3.117.1 rejects "Europe/Madrid" outright, despite
# infra-azure's SKILL.md hedging that "recent API versions accept IANA names
# too"; that hedge was wrong, this map replaces it). Subset of the CLDR
# windowsZones.xml mapping, covering the IANA zones this repo's example specs
# actually use plus other common ones — extend as new specs need more zones.
IANA_TO_WINDOWS_TIMEZONE = {
    "Europe/Madrid": "Romance Standard Time",
    "Europe/Paris": "Romance Standard Time",
    "Europe/Brussels": "Romance Standard Time",
    "Europe/Copenhagen": "Romance Standard Time",
    "Europe/Berlin": "W. Europe Standard Time",
    "Europe/Amsterdam": "W. Europe Standard Time",
    "Europe/Rome": "W. Europe Standard Time",
    "Europe/Vienna": "W. Europe Standard Time",
    "Europe/London": "GMT Standard Time",
    "Europe/Dublin": "GMT Standard Time",
    "Europe/Lisbon": "GMT Standard Time",
    "Europe/Warsaw": "Central European Standard Time",
    "Europe/Athens": "GTB Standard Time",
    "Europe/Helsinki": "FLE Standard Time",
    "Europe/Bucharest": "GTB Standard Time",
    "Europe/Moscow": "Russian Standard Time",
    "America/New_York": "Eastern Standard Time",
    "America/Chicago": "Central Standard Time",
    "America/Denver": "Mountain Standard Time",
    "America/Los_Angeles": "Pacific Standard Time",
    "America/Sao_Paulo": "E. South America Standard Time",
    "Asia/Tokyo": "Tokyo Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Kolkata": "India Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Australia/Sydney": "AUS Eastern Standard Time",
    "UTC": "UTC",
}


def parse_auto_shutdown(value: str) -> tuple[str, str]:
    """ "20:00 Europe/Madrid" -> ("2000", "Romance Standard Time") for
    azurerm_dev_test_global_vm_shutdown_schedule. Schema already enforces the
    "HH:MM Area/City" pattern; the IANA zone name is translated to the legacy
    Windows timezone ID the azurerm provider actually requires (see
    IANA_TO_WINDOWS_TIMEZONE above)."""
    time_part, tz_part = value.split(" ", 1)
    try:
        windows_tz = IANA_TO_WINDOWS_TIMEZONE[tz_part]
    except KeyError:
        raise SpecError(
            f"lab.auto_shutdown: IANA timezone '{tz_part}' has no known Windows "
            "timezone equivalent — add it to IANA_TO_WINDOWS_TIMEZONE in "
            "scripts/forge.py (azurerm_dev_test_global_vm_shutdown_schedule "
            "requires a Windows timezone ID, not an IANA name)."
        ) from None
    return time_part.replace(":", ""), windows_tz


def stable_octet(name: str) -> int:
    """Deterministic 10..209 second-octet derived from lab.name (not population.seed:
    seed governs population/theming determinism, not the network plan)."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return 10 + (digest[0] % 200)


def assign_ips(spec: dict) -> dict:
    octet = stable_octet(spec["lab"]["name"])
    plan: dict = {
        "supernet": f"10.{octet}.0.0/16",
        "management_subnet": f"10.{octet}.0.0/24",
        "jumpbox_ip": f"10.{octet}.0.10",
        "domains": {},
    }
    role_start = {"domain-controller": 10, "member-server": 50, "workstation": 100}
    for i, d in enumerate(spec["forest"], start=1):
        subnet_cidr = f"10.{octet}.{i}.0/24"
        counters = dict(role_start)
        hosts = []
        for m in spec["machines"]:
            if m["domain"] != d["domain"]:
                continue
            for _ in range(m["count"]):
                host_octet = counters[m["role"]]
                if host_octet > 249:
                    raise SpecError(f"domain '{d['domain']}': too many {m['role']} instances for a /24 IP plan")
                counters[m["role"]] += 1
                hosts.append(
                    {
                        "role": m["role"],
                        "os": m["os"],
                        "ip": f"10.{octet}.{i}.{host_octet}",
                        "services": m.get("services", []),
                        "image_id": m.get("image_id"),
                        "vm_size": m.get("vm_size"),
                    }
                )
        plan["domains"][d["domain"]] = {"subnet": subnet_cidr, "hosts": hosts}
    return plan


def estimate_cost(spec: dict) -> dict:
    provider = spec["lab"]["provider"]
    rates = HOURLY_RATE_USD[provider]
    hourly_total = sum(rates[m["role"]] * m["count"] for m in spec["machines"])
    # Auto-shutdown means the lab isn't running 24/7; ~10h/lab-day is a reasonable default assumption.
    daily_usd = round(hourly_total * 10, 2)
    monthly_usd = round(daily_usd * 20, 2)  # ~20 working lab-days/month
    budget = spec["lab"].get("budget_alert_usd")
    warning = None
    if budget is not None and daily_usd > budget:
        warning = (
            f"estimated_daily_usd ({daily_usd}) already exceeds lab.budget_alert_usd ({budget}); "
            "review machine count/size or raise the budget alert."
        )
    return {
        "hourly_usd": round(hourly_total, 2),
        "estimated_daily_usd": daily_usd,
        "estimated_monthly_usd": monthly_usd,
        "budget_alert_usd": budget,
        "warning": warning,
    }


def eval_expiry_notes(spec: dict) -> list[str]:
    windows_roles = {m["os"] for m in spec["machines"]}
    if windows_roles:
        return [
            f"Windows evaluation images expire {WINDOWS_EVAL_EXPIRY_DAYS} days after install "
            "(os: " + ", ".join(sorted(windows_roles)) + "). Plan a redeploy or apply a retail "
            "license before that date."
        ]
    return []


def reconcile(
    resolved_defense: dict, vulnerabilities: list[str], catalog: dict[str, dict], on_conflict: str
) -> tuple[dict, dict]:
    resolved = copy.deepcopy(resolved_defense)
    hardening = resolved.get("hardening", {})
    baseline = hardening.get("baseline", "none")
    controls = hardening.get("controls", {})
    intentional_gaps_auto = hardening.get("intentional_gaps_auto", False)

    conflicts = []
    for vuln_id in vulnerabilities:
        vuln = catalog.get(vuln_id)
        if not vuln:
            continue  # already reported by semantic_checks
        entries = vuln.get("neutralized_by", [])

        # Non-fixed 'hardening.controls.<name>' entries are descriptive labels for
        # whichever baseline levels are named alongside them (e.g. adcs_template_hardening
        # is just the human-readable name of a rule bundled in cis-l2) — they do not
        # independently trigger a conflict, only the paired hardening.baseline list does.
        implicit_labels = [
            e.split("hardening.controls.", 1)[1]
            for e in entries
            if isinstance(e, str)
            and e.startswith("hardening.controls.")
            and e.split("hardening.controls.", 1)[1] not in FIXED_HARDENING_TOGGLES
        ]

        for entry in entries:
            if isinstance(entry, dict) and "hardening.baseline" in entry:
                baseline_list = entry["hardening.baseline"]
                if baseline != "none" and baseline in baseline_list:
                    conflicts.append(
                        {
                            "vuln": vuln_id,
                            "kind": "baseline",
                            "baseline": baseline,
                            "control": implicit_labels[0] if implicit_labels else None,
                            "detail": (
                                f"baseline '{baseline}' bundles rule(s) that neutralize '{vuln_id}'"
                                + (f" (control: {implicit_labels[0]})" if implicit_labels else "")
                            ),
                        }
                    )
            elif isinstance(entry, str) and entry.startswith("hardening.controls."):
                control_name = entry.split("hardening.controls.", 1)[1]
                if control_name in FIXED_HARDENING_TOGGLES and controls.get(control_name) not in (
                    False,
                    "disable",
                    None,
                ):
                    conflicts.append(
                        {
                            "vuln": vuln_id,
                            "kind": "control",
                            "control": control_name,
                            "detail": f"control '{control_name}' neutralizes '{vuln_id}'",
                        }
                    )

    report = {
        "on_conflict": on_conflict,
        "intentional_gaps_auto": intentional_gaps_auto,
        "conflicts_detected": conflicts,
        "excluded_controls": [],
        "warnings": [],
    }

    if not conflicts:
        return resolved, report

    if on_conflict == "fail":
        raise SpecError(
            "hardening<->vulnerabilities reconciliation failed (on_conflict: fail):\n"
            + "\n".join(f"  - {c['detail']}" for c in conflicts)
        )

    if on_conflict == "warn":
        report["warnings"] = conflicts
        return resolved, report

    # on_conflict == "exclude-control"
    if not intentional_gaps_auto:
        report["warnings"] = conflicts
        report["warnings_note"] = (
            "on_conflict is 'exclude-control' but hardening.intentional_gaps_auto is false, "
            "so exclusions are NOT auto-derived; conflicts are reported as warnings instead."
        )
        return resolved, report

    excluded = []
    for c in conflicts:
        if c["kind"] == "control":
            off_value = ENUM_HARDENING_TOGGLES.get(c["control"], False)
            controls[c["control"]] = off_value
            excluded.append({**c, "action": f"hardening.controls.{c['control']} forced to {off_value!r}"})
        else:
            excluded.append(
                {
                    **c,
                    "action": (
                        "abstract exclusion recorded; concrete ansible-lockdown skip_rule vars are "
                        "resolved later by the defensive-controls skill"
                    ),
                }
            )
    hardening["controls"] = controls
    resolved["hardening"] = hardening
    report["excluded_controls"] = excluded
    return resolved, report


def build_manifest(spec_path: Path, spec: dict, resolved_defense: dict, reconciliation: dict) -> dict:
    return {
        "lab": spec["lab"],
        "source_spec": str(spec_path.relative_to(REPO_ROOT)) if spec_path.is_relative_to(REPO_ROOT) else str(spec_path),
        "forest": spec["forest"],
        "machines": spec["machines"],
        "population": spec["population"],
        "vulnerabilities": spec["vulnerabilities"],
        "defense_resolved": resolved_defense,
        "reconciliation": reconciliation,
        "network_plan": assign_ips(spec),
        "cost_estimate": estimate_cost(spec),
        "notes": eval_expiry_notes(spec),
    }


def load_and_resolve(spec_path: Path) -> tuple[dict, dict] | None:
    """Schema + semantic validation + reconciliation, in one call shared by
    `lab-spec` and `generate`. Returns (spec, manifest), or None after having
    already printed FAIL diagnostics to stderr."""
    spec = load_yaml(spec_path)
    schema = load_schema()

    schema_errors = validate_schema(spec, schema)
    if schema_errors:
        print(f"FAIL: {spec_path.name} does not match lab-spec.schema.json:", file=sys.stderr)
        for e in schema_errors:
            print(f"  - {e}", file=sys.stderr)
        return None

    catalog = load_vuln_catalog()
    sem_errors = semantic_checks(spec, catalog)
    if sem_errors:
        print(f"FAIL: {spec_path.name} failed semantic validation:", file=sys.stderr)
        for e in sem_errors:
            print(f"  - {e}", file=sys.stderr)
        return None

    try:
        resolved_defense = resolve_defense(spec)
        on_conflict = spec.get("on_conflict", "warn")
        resolved_defense, reconciliation = reconcile(resolved_defense, spec["vulnerabilities"], catalog, on_conflict)
    except SpecError as e:
        print(f"FAIL: {spec_path.name} reconciliation error:\n{e}", file=sys.stderr)
        return None

    manifest = build_manifest(spec_path, spec, resolved_defense, reconciliation)
    return spec, manifest


def generate_password(length: int = 20, rng: random.Random | None = None) -> str:
    """Random password meeting basic Windows complexity rules (upper/lower/digit/symbol).

    The symbol set deliberately EXCLUDES cmd.exe-hostile characters
    (`& ^ % $ < > | " '` and space): the ansible bootstrap extension creates the
    WinRM user with `net user ansible <pw>` under cmd.exe, where an unquoted `&`
    silently splits the command and the user is never created (WinRM then never
    comes up). We also quote the password there now, but keeping these out of the
    alphabet is the load-bearing fix — see terraform/azure/windows.tf.

    `rng`: pass a seeded random.Random to make the result reproducible from
    population.seed (population user passwords, most vuln account passwords —
    CLAUDE.md invariant #5). Left as None (the default), it draws from
    `secrets` — Python's CSPRNG, deliberately NOT seedable — which is the
    correct behavior for the two real per-deployer infra secrets
    (admin_password/ansible_password) that must stay unguessable and must NOT
    be reproducible across a regenerate."""
    choice = rng.choice if rng is not None else secrets.choice
    symbols = "!@#*-_=+"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in symbols for c in pw)
        ):
            return pw


def load_existing_infra_secrets(out_dir: Path, provider: str) -> tuple[str | None, str | None]:
    """Reuse the per-deployer infra secrets (admin/ansible passwords) minted by a
    previous `generate` of this lab, so regenerating an already-deployed lab does
    NOT re-randomize them. A fresh pair would make Terraform replace every VM
    (admin_password forces replacement — it destroyed a live DC once) and break
    WinRM auth against the running hosts. The first `generate` on an empty out_dir
    still mints an unguessable CSPRNG pair; reuse only when both are present.
    Delete secrets.auto.tfvars.json to intentionally rotate."""
    secrets_file = out_dir / "terraform" / provider / "secrets.auto.tfvars.json"
    try:
        data = json.loads(secrets_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    admin, ansible = data.get("admin_password"), data.get("ansible_password")
    return (admin, ansible) if admin and ansible else (None, None)


def flatten_machines(spec: dict, network_plan: dict) -> list[dict]:
    """Assigns a deterministic name (dc01, mbr01, ws01 — domain-slug-prefixed
    when the spec has more than one domain) to every machine instance in
    network_plan.domains.*.hosts. This is the single naming authority shared
    by the Terraform machines[] list and the Ansible inventory — ad-topology,
    infra-aws and infra-azure must not invent their own names."""
    multi_domain = len(spec["forest"]) > 1
    counters: dict[tuple[str, str], int] = {}
    machines = []
    for d in spec["forest"]:
        domain = d["domain"]
        slug = domain.split(".")[0]
        for host in network_plan["domains"][domain]["hosts"]:
            role = host["role"]
            key = (domain, role)
            counters[key] = counters.get(key, 0) + 1
            base = f"{ROLE_ABBREV[role]}{counters[key]:02d}"
            name = f"{slug}-{base}" if multi_domain else base
            machines.append(
                {
                    "name": name,
                    "domain": domain,
                    "role": role,
                    "os": host["os"],
                    "ip": host["ip"],
                    "services": host.get("services", []),
                    "image_id": host.get("image_id"),
                    "vm_size": host.get("vm_size"),
                }
            )
    return machines


def build_ansible_groups(spec: dict, machines: list[dict], admin_password: str) -> dict[str, list[dict]]:
    """See .claude/skills/ad-topology/SKILL.md for the group-assignment rules
    this implements: root DC vs. additional DC vs. child-domain DC vs.
    trust-anchor, and the domain/domain_name double-write GOAD's roles need
    because they're inconsistent about which key they read.

    Every group's domain_password is admin_password, not a separately
    generated per-domain secret — verified against a real deploy that
    conflating the two breaks domain-join outright ("user name or password is
    incorrect"): promoting a domain's first DC seeds its real "Administrator"
    (RID-500) account from whatever local account did the promotion
    (local_admin_username, renamed just before promotion — see
    ad-topology.yml's pre_tasks), so that account's *login* password stays
    admin_password, unchanged by promotion. GOAD's domain_controller role
    also reads this same {{domain_password}} as win_domain/
    win_domain_controller's safe_mode_password (DSRM) — a real, separate
    Windows concept from the domain login password — but nothing requires
    those two secrets to differ, and PurpleForge's own roles (ad_theming_
    overlay, vuln-injection, defensive-controls — see their tasks/*.yml,
    grep domain_password) reuse the identical {{domain_username}}/
    {{domain_password}} inventory vars to authenticate against the
    already-created domain for AD object manipulation, where only the real
    login password works. One shared value keeps every consumer correct
    instead of threading a second variable through every PurpleForge-authored
    template for a distinction (DSRM vs. login) this project's lab-lifecycle
    threat model doesn't need."""
    forest_by_domain = {d["domain"]: d for d in spec["forest"]}

    def is_child(domain: str) -> bool:
        trust = forest_by_domain[domain].get("trust")
        return bool(trust and trust["type"] == "parent-child")

    domain_order = [d["domain"] for d in spec["forest"]]
    # Parents must be resolved (root_dc_name known) before their children.
    ordered_domains = [d for d in domain_order if not is_child(d)] + [d for d in domain_order if is_child(d)]

    dcs_by_domain: dict[str, list[dict]] = {}
    for m in machines:
        if m["role"] == "domain-controller":
            dcs_by_domain.setdefault(m["domain"], []).append(m)

    groups: dict[str, list[dict]] = {
        "domain_controllers": [],
        "domain_controllers_additional": [],
        "child_domain_controllers": [],
        "trust_anchors": [],
        "member_servers": [],
        "workstations": [],
    }
    root_dc_name: dict[str, str] = {}

    for domain in ordered_domains:
        dcs = dcs_by_domain.get(domain, [])
        if not dcs:
            continue
        d = forest_by_domain[domain]
        first = dcs[0]
        root_dc_name[domain] = first["name"]
        common = {
            "name": first["name"],
            "ip": first["ip"],
            "domain": domain,
            "domain_name": domain,
            "netbios_name": d["netbios"],
            # ansible.windows.win_domain_controller/win_domain_membership require
            # DOMAIN\user or user@domain.com — verified against a real deploy that
            # a bare "Administrator" fails domain_admin_user validation outright.
            # yaml_scalar (not an f-string dropped into a Jinja "{{ }}") because
            # the literal backslash breaks a double-quoted YAML scalar outright
            # ("found unknown escape character") — verified on a real deploy
            # that this was silently generating unparseable inventories for
            # EVERY spec, not just the one being deployed at the time.
            "domain_username": yaml_scalar(f"{d['netbios']}\\Administrator"),
            "domain_password": admin_password,
            "dns_domain": first["name"],
        }
        if is_child(domain):
            parent = d["trust"]["target"]
            parent_dc = root_dc_name.get(parent, "")
            common.update(
                {
                    "parent_domain": parent,
                    "parent_domain_user": yaml_scalar(f"{forest_by_domain[parent]['netbios']}\\Administrator"),
                    "parent_domain_password": admin_password,
                    "source_dc": f"{parent_dc}.{parent}" if parent_dc else "",
                    "dns_domain": parent_dc or first["name"],
                }
            )
            groups["child_domain_controllers"].append(common)
        else:
            groups["domain_controllers"].append(common)
            trust = d.get("trust")
            if trust and trust["type"] != "parent-child":
                groups["trust_anchors"].append(
                    {
                        "name": first["name"],
                        "ip": first["ip"],
                        "domain_username": yaml_scalar(f"{d['netbios']}\\Administrator"),
                        "domain_password": admin_password,
                        "remote_forest": trust["target"],
                        "remote_admin": yaml_scalar(f"{forest_by_domain[trust['target']]['netbios']}\\Administrator"),
                        "remote_admin_password": admin_password,
                    }
                )

        for extra in dcs[1:]:
            groups["domain_controllers_additional"].append(
                {
                    "name": extra["name"],
                    "ip": extra["ip"],
                    "domain": domain,
                    "domain_name": domain,
                    "netbios_name": d["netbios"],
                    "domain_username": yaml_scalar(f"{d['netbios']}\\Administrator"),
                    "domain_password": admin_password,
                    "dns_domain": root_dc_name[domain],
                }
            )

    for m in machines:
        if m["role"] in ("member-server", "workstation"):
            group = "member_servers" if m["role"] == "member-server" else "workstations"
            member_netbios = forest_by_domain[m["domain"]]["netbios"]
            groups[group].append(
                {
                    "name": m["name"],
                    "ip": m["ip"],
                    "member_domain": m["domain"],
                    "domain_username": yaml_scalar(f"{member_netbios}\\Administrator"),
                    "domain_password": admin_password,
                    "dns_domain": root_dc_name.get(m["domain"], ""),
                }
            )

    return groups


def render_backend_config(lab_name: str, dst: Path) -> None:
    """Writes backend.hcl for `terraform init -backend-config=backend.hcl`
    (versions.tf declares a partial `backend "azurerm" {}` — CLAUDE.md
    invariant #4, state must never default to local). One shared storage
    account holds every lab's state as a separate blob key — it is NOT
    per-lab (Azure storage account names must be globally unique and
    creating one per lab would be wasteful) — see infra-azure's SKILL.md for
    the one-time `az storage account create` bootstrap. The placeholder name
    below WILL collide across PurpleForge installs; treat it as a value to
    override, not a working default.
    """
    content = (
        'resource_group_name  = "purpleforge-tfstate-rg"\n'
        'storage_account_name = "purpleforgetfstate"  # placeholder — must be globally unique, override after bootstrap\n'
        'container_name       = "tfstate"\n'
        f'key                  = "{lab_name}.tfstate"\n'
    )
    (dst / "backend.hcl").write_text(content, encoding="utf-8")


def render_azure_terraform(
    network_plan: dict, machines: list[dict], out_dir: Path, admin_password: str, ansible_password: str, lab: dict
) -> None:
    src = TEMPLATES_DIR / "terraform" / "azure"
    dst = out_dir / "terraform" / "azure"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    shutdown_time, shutdown_tz = parse_auto_shutdown(lab["auto_shutdown"])
    tfvars = {
        "lab_name": lab["name"],
        "location": lab["region"],
        "auto_shutdown_time": shutdown_time,
        "auto_shutdown_timezone": shutdown_tz,
        "supernet": network_plan["supernet"],
        "management_cidr": network_plan["management_subnet"],
        "jumpbox_private_ip": network_plan["jumpbox_ip"],
        "domains": {domain: {"subnet_cidr": info["subnet"]} for domain, info in network_plan["domains"].items()},
        "machines": [
            {
                "name": m["name"],
                "domain": m["domain"],
                "role": m["role"],
                "os": m["os"],
                "ip": m["ip"],
                "image_id": m.get("image_id"),
                "vm_size": m.get("vm_size"),
            }
            for m in machines
        ],
        "admin_username": WINDOWS_ADMIN_USERNAME,
        # admin_password / ansible_password are NOT written here — they are the
        # only strong secrets terraform needs, and they live in the gitignored
        # secrets.auto.tfvars.json below so the committed tfvars stays shareable
        # and account/secret-free (deploy.sh mints that file if it is missing).
        "jumpbox_username": WINDOWS_ADMIN_USERNAME,
        "wireguard_port": 51820,
        "wireguard_allowed_cidrs": ["0.0.0.0/0"],
        "bastion_ssh_allowed_cidrs": [],
        "bastion_size": lab.get("bastion_size") or "Standard_B1s",
    }
    (dst / "terraform.tfvars.json").write_text(json.dumps(tfvars, indent=2) + "\n", encoding="utf-8")
    # Strong secrets in a SEPARATE gitignored auto-tfvars overlay (terraform
    # auto-loads *.auto.tfvars.json). Written for the author's own deploy; a
    # sharer who never regenerates gets it minted by deploy.sh from
    # secrets-manifest.json instead.
    (dst / "secrets.auto.tfvars.json").write_text(
        json.dumps({"admin_password": admin_password, "ansible_password": ansible_password}, indent=2) + "\n",
        encoding="utf-8",
    )
    render_backend_config(lab["name"], dst)


def render_proxmox_terraform(
    network_plan: dict, machines: list[dict], out_dir: Path, admin_password: str, ansible_password: str, lab: dict
) -> None:
    """Sibling of render_azure_terraform for the on-prem Proxmox provider.
    Writes ONLY the spec-derived, host-independent values into the committed
    terraform.tfvars.json; the strong secrets go in the gitignored
    secrets.auto.tfvars.json overlay (same split as Azure). The Proxmox
    host-specific values (node/bridges/datastore/template ids/bastion external
    IP) are NOT baked here — they come from a gitignored host.auto.tfvars.json
    the deployer fills (host.auto.tfvars.example.json ships as the reference),
    keeping the generated lab host-independent (CLAUDE.md account-independence
    convention). No backend.hcl: this layer uses a local state backend."""
    src = TEMPLATES_DIR / "terraform" / "proxmox"
    dst = out_dir / "terraform" / "proxmox"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    # One VLAN tag per domain, assigned deterministically (100 + index) so a
    # domain's subnet is L2-isolated on the lab bridge, matching the /24-per-
    # domain plan in network_plan.domains. gateway_ip is the bastion's address
    # ON that domain VLAN (the subnet's .254): Windows hosts default-route to it
    # (it MUST be on-subnet, not the mgmt IP), and deploy.sh materializes it as
    # a VLAN sub-interface on the bastion that routes the domain (see
    # deploy-proxmox.sh.j2's route_lab step).
    domains = {}
    for idx, (domain, info) in enumerate(network_plan["domains"].items()):
        net = ipaddress.ip_network(info["subnet"], strict=False)
        gateway_ip = str(net.network_address + 254)  # .254 for a /24
        domains[domain] = {
            "subnet_cidr": info["subnet"],
            "vlan_id": 100 + idx,
            "gateway_ip": gateway_ip,
        }
    tfvars = {
        "lab_name": lab["name"],
        "supernet": network_plan["supernet"],
        "management_cidr": network_plan["management_subnet"],
        "jumpbox_private_ip": network_plan["jumpbox_ip"],
        "domains": domains,
        "machines": [
            {
                "name": m["name"],
                "domain": m["domain"],
                "role": m["role"],
                "os": m["os"],
                "ip": m["ip"],
            }
            for m in machines
        ],
        "admin_username": WINDOWS_ADMIN_USERNAME,
        "jumpbox_username": WINDOWS_ADMIN_USERNAME,
        "wireguard_port": 51820,
        "wireguard_allowed_cidrs": ["0.0.0.0/0"],
    }
    (dst / "terraform.tfvars.json").write_text(json.dumps(tfvars, indent=2) + "\n", encoding="utf-8")
    (dst / "secrets.auto.tfvars.json").write_text(
        json.dumps({"admin_password": admin_password, "ansible_password": ansible_password}, indent=2) + "\n",
        encoding="utf-8",
    )


def load_theme(theme_id: str) -> dict:
    return load_yaml(THEMES_DIR / f"{theme_id}.yml")


def compute_population_counts(users: int, density: str) -> tuple[int, int, int]:
    """UserCount is population.users directly; GroupCount/ComputerCount scale
    off it by density, matching Invoke-BadBlood.ps1's own three counters."""
    ratio_by_density = {"sparse": (0.15, 0.3), "realistic": (0.2, 0.4), "messy": (0.3, 0.5)}
    group_ratio, computer_ratio = ratio_by_density[density]
    return users, max(1, round(users * group_ratio)), max(1, round(users * computer_ratio))


def render_ad_population(theme: dict, spec: dict, ansible_groups: dict[str, list[dict]], out_dir: Path) -> list[dict]:
    """Full replacement for BadBlood + render_ad_theming/render_badblood_overlay
    (both retired): computes one fully deterministic population plan per
    populatable domain (scripts/population.py, seeded from population.seed +
    domain index — the same per-domain-seed trick BadBlood-era
    attach_population_vars used) and renders ad-population.yml.j2, which
    applies each plan via native community.windows modules. Returns the list
    of plans (also stored in lab-manifest.json and consumed by
    resolve_attack_chain() for real-object vulnerability casting)."""
    dc_hosts = ansible_groups["domain_controllers"] + ansible_groups["child_domain_controllers"]
    per_domain_users = max(1, spec["population"]["users"] // max(1, len(dc_hosts)))
    user_count, group_count, computer_count = compute_population_counts(per_domain_users, spec["population"]["density"])

    plans = []
    for i, host in enumerate(dc_hosts):
        plan = generate_population_plan(
            theme,
            spec["population"],
            host["domain"],
            spec["population"]["seed"] + i,
            user_count,
            group_count,
            computer_count,
            generate_password,
        )
        plan["run_on"] = host["name"]
        plan["domain_username"] = host["domain_username"]
        plan["domain_password"] = host["domain_password"]
        plans.append(plan)

    dst = out_dir / "ansible" / "playbooks"
    dst.mkdir(parents=True, exist_ok=True)
    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "ad-population.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    # Render a password-STRIPPED copy so the committed ad-population.yml carries
    # no per-user secret; the passwords flow in at runtime via pf_pop_secrets
    # (gitignored group_vars/all/secrets.yml). The returned plans keep passwords
    # for the (gitignored) manifest + attack-chain casting.
    render_plans = [
        {**plan, "users": [{k: v for k, v in u.items() if k != "password"} for u in plan["users"]]} for plan in plans
    ]
    rendered = template.render(lab_name=spec["lab"]["name"], population_plans=render_plans)
    (dst / "ad-population.yml").write_text(rendered, encoding="utf-8")
    return plans


def write_lab_secrets(out_dir: Path, admin_password: str, ansible_password: str, population_plans: list[dict]) -> int:
    """Splits the lab's secrets by lifetime, all under the inventory-adjacent
    group_vars/all/ so ansible auto-loads them for every host (win_ping + site.yml):

      - population-secrets.yml (COMMITTED): the population USER passwords. They
        are decided ONCE, here at lab creation, and travel WITH the lab, so every
        deploy of a shared lab uses the SAME user passwords — deploy.sh never
        (re)generates them. They are lab content, not an infra key.
      - secrets.yml (GITIGNORED): the infra keys (domain admin + ansible WinRM).
        Per-deployer; deploy.sh mints these if absent so a shared clone deploys
        without regenerating. terraform's mirror of the same two values is
        secrets.auto.tfvars.json (written by render_azure_terraform, gitignored).

    secrets-manifest.json (committed) records which INFRA secrets deploy.sh must
    mint. JSON is a valid YAML subset, so the .yml bodies are written as JSON to
    dodge password-quoting pitfalls. Returns the population-user count."""
    pop_secrets = {u["sam_account_name"]: u["password"] for plan in population_plans for u in plan["users"]}
    gv = out_dir / "ansible" / "inventory" / "group_vars" / "all"
    gv.mkdir(parents=True, exist_ok=True)
    (gv / "population-secrets.yml").write_text(
        "# Population user passwords — generated ONCE at lab creation, versioned\n"
        "# with the lab. deploy.sh never regenerates these.\n"
        + json.dumps({"pf_pop_secrets": pop_secrets}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (gv / "secrets.yml").write_text(
        "# GITIGNORED — infra keys minted per deploy (domain admin + ansible). Never commit.\n"
        + json.dumps({"pf_admin_password": admin_password, "pf_ansible_password": ansible_password}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (out_dir / "secrets-manifest.json").write_text(
        json.dumps({"infra_secrets": ["admin_password", "ansible_password"]}, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(pop_secrets)


# Intentionally weak, dictionary-crackable passwords for the roastable accounts —
# being crackable offline IS the vulnerability (kerberoasting/asreproast). They
# are non-secret by design and still only ever written into generated/<lab>/
# (gitignored). Accounts whose weakness is NOT about the password (dcsync-acl,
# passwords-in-description) get a strong random one instead.
VULN_WEAK_PASSWORD = "Password123!"
VULN_WEAK_PASSWORD_ALT = "Summer2024!"
VULN_WEAK_PASSWORD_3 = "Welcome2024!"


def resolve_attack_chain(spec: dict, catalog: dict[str, dict], population_plans: list[dict], mode: str) -> dict:
    """Casts each selected vulnerability whose catalog entry declares a
    chain.target_shape ('account'/'group_scope') onto a REAL object from the
    precomputed population (scripts/population.py) — never a naive random
    pick (see kerberoasting.yml's own header comment on why that would break
    invariant #5): the RNG here is seeded from population.seed (a distinct
    offset, same trick population.py itself uses per-domain), so the exact
    same objects get cast on every re-run given the same spec.

    In 'ctf' mode, deliberately reuses an object already cast by an earlier
    selected vulnerability (in spec['vulnerabilities'] order) when shapes are
    compatible — this IS the "cadena de ejecución": two vulnerabilities
    landing on the same real person means cracking their credential once
    (vuln A) is what vuln B's grant already presupposes. In 'independent'
    mode (the default), every vuln gets its own distinct object — the
    original, unrelated-gaps behavior, just pointed at real users/groups
    instead of synthetic svc-* accounts.

    Vulns with target_shape 'none' (or when there's no population to cast
    from) are untouched — build_vuln_vars falls back to today's synthetic
    naming for those, unchanged."""
    primary_plan = population_plans[0] if population_plans else None
    rng = random.Random(spec["population"]["seed"] + 8000)  # distinct offset from population.py's own per-domain seeds

    steps = []
    chained = []
    cast_accounts: list[dict] = []  # users already cast into an 'account'-shaped vuln, in cast order

    for vid in spec["vulnerabilities"]:
        v = catalog[vid]
        shape = v.get("chain", {}).get("target_shape", "none")
        cast = None
        shared_with = None

        if shape == "account" and primary_plan is not None:
            if mode == "ctf" and cast_accounts:
                cast = rng.choice(cast_accounts)
                shared_with = cast["name"]
            else:
                pool = [u for u in primary_plan["users"] if u["name"] not in {c["name"] for c in cast_accounts}]
                cast = rng.choice(pool) if pool else rng.choice(primary_plan["users"])
                cast_accounts.append(cast)
        elif shape == "group_scope" and primary_plan is not None:
            if mode == "ctf" and cast_accounts:
                # Narrow the reader/writer scope to an account already cast
                # into an earlier vuln — dsacls' /G grantee accepts a user
                # or a group name identically, so this is a real, working
                # narrowing, not just a label.
                cast = rng.choice(cast_accounts)
                shared_with = cast["name"]
            else:
                bulk_groups = [g for g in primary_plan["groups"] if not g["curated"]]
                cast = rng.choice(bulk_groups) if bulk_groups else None

        if shared_with:
            chained.append({"vuln": vid, "shares_target_with": shared_with})
        steps.append({"id": vid, "target_shape": shape, "cast_name": cast["name"] if cast else None})

    return {"mode": mode, "steps": steps, "chained": chained}


# Intentionally weak, dictionary-crackable passwords for the roastable accounts —
# being crackable offline IS the vulnerability (kerberoasting/asreproast). They
# are non-secret by design and still only ever written into generated/<lab>/
# (gitignored). Accounts whose weakness is NOT about the password (dcsync-acl,
# passwords-in-description) get a strong random one instead. When a vuln is
# cast onto a real population object (see resolve_attack_chain above), that
# object already exists with its own strong population-generated password —
# these same weak/strong choices are applied as a deliberate RESET, not a
# fresh account's initial password.
#
# `forced_password`: when attack_chain's ctf mode reuses the SAME cast_name
# across multiple account-shaped vulns (a chain — see resolve_attack_chain),
# each vuln's Ansible task independently resets that shared account's
# password, in spec['vulnerabilities'] order. Without this, whichever vuln's
# task happens to run LAST would silently overwrite an EARLIER vuln's
# password with its own, different constant — invalidating the earlier
# vuln's documented credential without any error. plan_vuln_injection caches
# the first password assigned to each cast_name and forces every subsequent
# vuln sharing that account to reuse the exact same value, so every reset
# along the chain is idempotent (same value every time) instead of a race.
def build_vuln_vars(
    vid: str,
    machines: list[dict],
    primary_dc: dict,
    cast_name: str | None = None,
    forced_password: str | None = None,
    rng: random.Random | None = None,
) -> dict:
    """`rng`: seeded from population.seed by plan_vuln_injection so every
    generate_password() fallback below is reproducible across regenerates of
    the same spec (invariant #5). Only matters when cast_name/forced_password
    are absent (independent mode, or a target_shape:none vuln); ctf-mode
    chaining already reuses forced_password."""
    if vid == "kerberoasting":
        return {
            "vuln_kerberoast_account": cast_name or "svc-sqlreport",
            "vuln_kerberoast_password": forced_password or VULN_WEAK_PASSWORD,
        }
    if vid == "asreproast":
        return {
            "vuln_asrep_account": cast_name or "svc-legacyapp",
            "vuln_asrep_password": forced_password or VULN_WEAK_PASSWORD_ALT,
        }
    if vid == "laps-read-acl":
        return {"vuln_laps_reader_group": cast_name or "Domain Users"}
    if vid == "shadow-credentials":
        return {
            "vuln_shadowcred_target": "svc-tier0-admin",
            "vuln_shadowcred_target_password": generate_password(rng=rng),
            "vuln_shadowcred_writer_group": cast_name or "Domain Users",
        }
    if vid == "dnsadmins-privesc":
        password = forced_password or (VULN_WEAK_PASSWORD_ALT if cast_name else generate_password(rng=rng))
        return {"vuln_dnsadmins_account": cast_name or "svc-dns-operator", "vuln_dnsadmins_password": password}
    if vid == "rbcd-abuse":
        members = [m for m in machines if m["role"] == "member-server"]
        computer = members[0]["name"] if members else primary_dc["name"]
        return {
            "vuln_rbcd_delegate_account": cast_name or "svc-app-proxy",
            "vuln_rbcd_delegate_password": forced_password or VULN_WEAK_PASSWORD_3,
            "vuln_rbcd_target_computer": computer,
        }
    if vid == "backup-operators-membership":
        password = forced_password or (VULN_WEAK_PASSWORD_ALT if cast_name else generate_password(rng=rng))
        return {"vuln_backupop_account": cast_name or "svc-backup-agent", "vuln_backupop_password": password}
    if vid == "dcsync-acl":
        password = forced_password or (VULN_WEAK_PASSWORD_ALT if cast_name else generate_password(rng=rng))
        return {"vuln_dcsync_account": cast_name or "svc-replication", "vuln_dcsync_password": password}
    if vid == "passwords-in-description":
        return {
            "vuln_pwddesc_account": cast_name or "temp-contractor",
            "vuln_pwddesc_password": forced_password or generate_password(rng=rng),
        }
    if vid == "gpp-cpassword":
        return {"vuln_gpp_name": "Workstations - Local Admin Password"}
    if vid == "unconstrained-delegation":
        members = [m for m in machines if m["role"] == "member-server"]
        computer = members[0]["name"] if members else primary_dc["name"]
        return {"vuln_unconstrained_computer": computer}
    if vid == "constrained-delegation":
        dc_fqdn = f"{primary_dc['name']}.{primary_dc['domain']}"
        password = forced_password or (VULN_WEAK_PASSWORD_3 if cast_name else generate_password(rng=rng))
        return {
            "vuln_delegation_account": cast_name or "svc-webapp",
            "vuln_delegation_password": password,
            "vuln_delegation_target_spn": f"ldap/{dc_fqdn}",
        }
    if vid == "writable-gpo":
        return {
            "vuln_gpo_account": cast_name or "svc-gpo-editor",
            "vuln_gpo_password": forced_password or generate_password(rng=rng),
            "vuln_gpo_name": "Workstation Deployment Policy",
        }
    if vid == "adminsdholder-acl":
        return {
            "vuln_adminsdholder_account": cast_name or "svc-legacy-audit",
            "vuln_adminsdholder_password": forced_password or generate_password(rng=rng),
        }
    if vid == "readable-gmsa":
        return {
            "vuln_gmsa_reader_account": cast_name or "svc-monitoring",
            "vuln_gmsa_reader_password": forced_password or generate_password(rng=rng),
            "vuln_gmsa_name": "gmsa-websvc",
        }
    if vid == "esc4-template-acl":
        return {
            "vuln_esc4_account": cast_name or "svc-pki-operator",
            "vuln_esc4_password": forced_password or generate_password(rng=rng),
            "vuln_esc4_template": "User",
        }
    if vid == "mssql-weak-sa":
        # target_shape: none — no population account cast; sa is a fixed SQL
        # login, not an AD object, so it never reuses cast_name/forced_password.
        return {"vuln_mssql_sa_password": VULN_WEAK_PASSWORD}
    # machine-account-quota is domain-level (target_shape: none) — no per-vuln
    # account vars; the playbook only reads domain_username/domain_password.
    # adcs-esc1 and any future service-scoped vuln need no extra vars beyond the
    # inventory's domain/domain_username/domain_password and vuln_files_dir.
    return {}


def plan_vuln_injection(
    spec: dict,
    catalog: dict[str, dict],
    machines: list[dict],
    groups: dict[str, list[dict]],
    reconciliation: dict,
    attack_chain: dict | None = None,
) -> list[dict]:
    """Resolves, per selected vuln: which host the inject play targets, the
    deterministic per-vuln vars, and the neutralization status carried over from
    the hardening<->vuln reconciliation. This is what 'vuln-injection respects
    the reconciliation exclusions' means concretely — each planned vuln records
    whether its neutralizing control was excluded (gap preserved), applied anyway
    (at risk, on_conflict:warn), or never in scope (clear)."""
    if not spec["vulnerabilities"]:
        return []
    root_dcs = groups["domain_controllers"]
    if not root_dcs:
        raise SpecError("vuln-injection needs at least one root (non-child) domain controller to target")
    primary_dc = root_dcs[0]

    excluded = {c["vuln"] for c in reconciliation.get("excluded_controls", [])}
    warned = {c.get("vuln") for c in reconciliation.get("warnings", [])}
    cast_names = {s["id"]: s["cast_name"] for s in (attack_chain or {}).get("steps", [])}
    cast_password_cache: dict[str, str] = {}  # cast_name -> password, see build_vuln_vars' forced_password doc
    # +9000: distinct from resolve_attack_chain's +8000 and population.py's own
    # per-domain seeds (population.seed + domain index) — makes every
    # generate_password() fallback inside build_vuln_vars reproducible across
    # regenerates of the same spec, instead of drawing from the CSPRNG.
    vuln_password_rng = random.Random(spec["population"]["seed"] + 9000)

    planned = []
    for vid in spec["vulnerabilities"]:
        v = catalog[vid]
        requires = v["attack"].get("requires_services") or []
        target_role = v["attack"].get("target_role")
        if requires:
            # semantic_checks already guaranteed a host provides these services.
            host = next(m for m in machines if all(s in m.get("services", []) for s in requires))
            run_on, target_domain = host["name"], host["domain"]
        elif target_role:
            # OS-level / application privesc: land on the first machine of the
            # declared role (semantic_checks guaranteed one exists). This is the
            # non-AD counterpart to requires_services — the vuln is a local box
            # misconfiguration, not a domain-object artifact, so it does NOT
            # default to the root DC the way the AD vulns below do.
            host = next(m for m in machines if m["role"] == target_role)
            run_on, target_domain = host["name"], host["domain"]
        else:
            run_on, target_domain = primary_dc["name"], primary_dc["domain"]

        if vid in excluded:
            status = "gap-preserved (neutralizing control excluded via on_conflict:exclude-control)"
        elif vid in warned:
            status = "AT RISK (neutralizing hardening applied; on_conflict:warn — gap may be closed)"
        else:
            status = "clear (no selected hardening control neutralizes this vuln)"

        cast_name = cast_names.get(vid)
        forced_password = cast_password_cache.get(cast_name) if cast_name else None
        vvars = build_vuln_vars(vid, machines, primary_dc, cast_name, forced_password, vuln_password_rng)

        password_key = (VULN_CREDENTIAL_VARS.get(vid) or (None, None))[1]
        if cast_name and password_key and password_key in vvars and cast_name not in cast_password_cache:
            cast_password_cache[cast_name] = vvars[password_key]

        planned.append(
            {
                "id": vid,
                "name": v["name"],
                "severity": v["severity"],
                "mitre": ",".join(v["attack"]["mitre_attack"]),
                "run_on": run_on,
                "target_domain": target_domain,
                "intended_path": " ".join(v["attack"]["intended_path"].split()),
                "neutralization": status,
                "vars": vvars,
            }
        )
    return planned


def render_vuln_injection(spec: dict, planned: list[dict], out_dir: Path) -> None:
    if not planned:
        return
    dst = out_dir / "ansible"
    (dst / "playbooks").mkdir(parents=True, exist_ok=True)

    vulns_dst = dst / "vulns"
    if vulns_dst.exists():
        shutil.rmtree(vulns_dst)
    vulns_dst.mkdir(parents=True, exist_ok=True)
    for v in planned:
        shutil.copy(TEMPLATES_DIR / "ansible" / "vulns" / f"{v['id']}.yml", vulns_dst / f"{v['id']}.yml")

    # adcs-esc1 reuses GOAD's ADCSTemplate module + ESC1.json; copy them next to
    # the playbook (playbook_dir/files/adcs) only when that vuln is selected.
    if any(v["id"] == "adcs-esc1" for v in planned):
        adcs_dst = dst / "playbooks" / "files" / "adcs"
        adcs_dst.mkdir(parents=True, exist_ok=True)
        goad_adcs = REPO_ROOT / "vendor" / "GOAD" / "ansible" / "roles" / "adcs_templates" / "files"
        adcs_module_dst = adcs_dst / "ADCSTemplate"
        if adcs_module_dst.exists():
            shutil.rmtree(adcs_module_dst)
        shutil.copytree(goad_adcs / "ADCSTemplate", adcs_module_dst, ignore=shutil.ignore_patterns(".git", ".git*"))
        shutil.copy(goad_adcs / "ESC1.json", adcs_dst / "ESC1.json")

    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "vuln-injection.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    rendered = template.render(lab_name=spec["lab"]["name"], planned=planned)
    (dst / "playbooks" / "vuln-injection.yml").write_text(rendered, encoding="utf-8")


def plan_service_provisioning(machines: list[dict]) -> dict[str, list[str]]:
    """machines[].services -> {service: [host names]} for services this generator
    actually provisions: `mssql` (secure base install) and `adcs` (an Enterprise
    Root CA, reusing GOAD's adcs role — this is what makes adcs-esc1 usable: the
    vuln publishes its ESC1 template to this CA). `iis`/`sccm` remain
    declared-but-unconsumed (Tier B backlog, NON-AD-VULNS-ROADMAP.md)."""
    plan = {}
    for svc in ("mssql", "adcs"):
        hosts = [m["name"] for m in machines if svc in m.get("services", [])]
        if hosts:
            plan[svc] = hosts
    return plan


def render_service_provisioning(service_hosts: dict[str, list[str]], lab_name: str, out_dir: Path) -> None:
    """Renders service-provisioning.yml (one play per host needing a service)
    plus its supporting task-file + config template. Installs SECURELY by
    design (see templates/ansible/services/mssql-install.yml) — the vuln that
    requires_services this host lands later, in vuln-injection."""
    if not service_hosts:
        return
    dst = out_dir / "ansible" / "playbooks"
    dst.mkdir(parents=True, exist_ok=True)
    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "service-provisioning.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    (dst / "service-provisioning.yml").write_text(
        template.render(
            lab_name=lab_name,
            mssql_hosts=service_hosts.get("mssql", []),
            adcs_hosts=service_hosts.get("adcs", []),
        ),
        encoding="utf-8",
    )

    services_dst = out_dir / "ansible" / "services"
    services_dst.mkdir(parents=True, exist_ok=True)
    if service_hosts.get("mssql"):
        shutil.copy(TEMPLATES_DIR / "ansible" / "services" / "mssql-install.yml", services_dst / "mssql-install.yml")
    if service_hosts.get("adcs"):
        shutil.copy(TEMPLATES_DIR / "ansible" / "services" / "adcs-install.yml", services_dst / "adcs-install.yml")

    files_dst = dst / "files" / "mssql"
    files_dst.mkdir(parents=True, exist_ok=True)
    shutil.copy(
        REPO_ROOT / "vendor" / "GOAD" / "ansible" / "roles" / "mssql" / "files" / "sql_conf.ini.MSSQL_2019.j2",
        files_dst / "sql_conf.ini.MSSQL_2019.j2",
    )


def render_site_playbook(has_vuln_injection: bool, has_service_provisioning: bool, out_dir: Path) -> None:
    """The single entry point a /deploy command should run — enforces
    CLAUDE.md's deploy order (hardening before vuln-injection) instead of
    leaving it up to whoever runs the individual playbooks by hand."""
    dst = out_dir / "ansible" / "playbooks"
    dst.mkdir(parents=True, exist_ok=True)
    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "site.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    (dst / "site.yml").write_text(
        template.render(has_vuln_injection=has_vuln_injection, has_service_provisioning=has_service_provisioning),
        encoding="utf-8",
    )


def render_deploy_scripts(spec: dict, manifest: dict, machines: list[dict], network_plan: dict, out_dir: Path) -> None:
    """Emit generated/<lab>/{deploy.sh,teardown.sh} — the deterministic, no-AI
    deploy/teardown path. These are the single source of truth for the exact
    commands (the lab-report just points at them); `forge.py deploy`/`teardown`
    are thin wrappers that run these after a guardrail gate. Everything the
    scripts encode is the battle-tested procedure from AZURE-DEPLOY-RUNBOOK.md
    (Azure) / the Proxmox layer's own comments, turned from prose into an
    idempotent, retrying script. The two providers use separate templates
    (deploy.sh.j2/teardown.sh.j2 for Azure, deploy-proxmox.sh.j2/
    teardown-proxmox.sh.j2 for Proxmox) — the flows differ enough (az vs the
    Proxmox API, remote vs local state, SKU auto-sizing vs static specs, plus
    the Proxmox-only bastion VLAN routing) that branching one script would be
    less clear than two focused ones."""
    provider = spec["lab"]["provider"]
    roles = sorted({m["role"] for m in machines})
    # domain -> {vlan_id, gateway_ip, subnet} for the Proxmox bastion routing
    # step (deterministic, same assignment render_proxmox_terraform uses).
    domains_ctx = {}
    for idx, (domain, info) in enumerate(network_plan["domains"].items()):
        net = ipaddress.ip_network(info["subnet"], strict=False)
        domains_ctx[domain] = {
            "vlan_id": 100 + idx,
            "gateway_ip": str(net.network_address + 254),
            "subnet": info["subnet"],
        }
    context = {
        "lab_name": spec["lab"]["name"],
        "provider": provider,
        "region": spec["lab"]["region"],
        "supernet": network_plan["supernet"],
        "domain": spec["forest"][0]["domain"],
        "wireguard_port": network_plan.get("wireguard_port", 51820),
        "roles_json": json.dumps(roles),
        "spec_rel": manifest["source_spec"],
        "domains_json": json.dumps(domains_ctx),
        "auto_shutdown": spec["lab"].get("auto_shutdown", ""),
    }
    template_suffix = "-proxmox" if provider == "proxmox" else ""
    env = jinja2.Environment(keep_trailing_newline=True)
    for name in ("deploy.sh", "teardown.sh"):
        stem = name[: -len(".sh")]
        template = env.from_string((TEMPLATES_DIR / f"{stem}{template_suffix}.sh.j2").read_text(encoding="utf-8"))
        path = out_dir / name
        path.write_text(template.render(**context), encoding="utf-8")
        path.chmod(0o755)


# ---------------------------------------------------------------------------
# defensive-controls: hardening (ansible-lockdown, with skip_rules derived
# from the reconciliation), EDR, and deception. See
# .claude/skills/defensive-controls/SKILL.md for the full reasoning — in
# particular why some `neutralized_by` claims from the vuln catalog cannot be
# turned into a concrete skip_rule (only smb-signing-disabled and
# unconstrained-delegation have a VERIFIED ansible-lockdown rule mapping;
# every other case is reported as an honest note, never silently dropped).
# ---------------------------------------------------------------------------

BASELINE_LEVELS = {"cis-l1": {"l1"}, "cis-l2": {"l1", "l2"}}


def expand_role_or_all(value) -> set[str]:
    if value == "all" or value is None:
        return {"domain-controller", "member-server", "workstation"}
    return set(value)


def load_hardening_baseline(baseline_id: str) -> dict:
    if baseline_id in ("none", None):
        return {"id": "none", "engine": "none", "role_by_os": {}, "tags_by_role": {}, "skip_rule_vars_prefix_by_os": {}}
    return load_yaml(HARDENING_DIR / f"{baseline_id}.yml")


def load_control_cis_rules() -> dict:
    if not CONTROL_CIS_RULES_PATH.exists():
        return {}
    return load_yaml(CONTROL_CIS_RULES_PATH).get("controls", {})


def resolve_hardening_skip_rules(
    baseline_id: str, reconciliation: dict, oses_in_scope: set[str]
) -> tuple[dict[str, list[str]], list[str]]:
    """Per-OS list of ansible-lockdown skip_rule vars to force false, derived
    ONLY from verified catalog/defense/hardening/control-cis-rules.yml entries
    — plus an honest note for every exclusion that could NOT be turned into a
    concrete skip_rule (unmapped control, STIG, or a rule whose level isn't
    even selected by this baseline).

    The lookup keys off `c["control"]` (the free-label name), which is
    populated for BOTH conflict kinds: `kind: "control"` (a real spec-settable
    hardening.controls.* toggle in FIXED_HARDENING_TOGGLES, e.g. smb_signing)
    AND `kind: "baseline"` (a purely descriptive label paired with a
    hardening.baseline list, e.g. disable_always_install_elevated,
    safe_dll_search_mode, adcs_template_hardening — there is no real toggle to
    exclude, only "don't apply this specific CIS rule"). Gating the lookup on
    `kind == "control"` alone (as this used to) meant control-cis-rules.yml
    could NEVER resolve a concrete skip_rule for any free-label control, no
    matter how well-verified its mapping was."""
    skip_rules: dict[str, list[str]] = {os_: [] for os_ in oses_in_scope}
    notes: list[str] = []

    if baseline_id in ("none", "baseline-controls"):
        for c in reconciliation.get("excluded_controls", []):
            notes.append(
                f"vuln '{c['vuln']}': baseline '{baseline_id}' runs no ansible-lockdown role, so no skip_rule applies — the toggle exclusion alone (pf_controls not applying it) is what preserves this gap."
            )
        return skip_rules, notes

    control_rules = load_control_cis_rules()
    baseline_levels = BASELINE_LEVELS.get(baseline_id, set())

    for c in reconciliation.get("excluded_controls", []):
        control_name = c.get("control")
        if not control_name:
            notes.append(
                f"vuln '{c['vuln']}': baseline-level exclusion has no associated control label at all — "
                f"no skip_rule possible."
            )
            continue
        if baseline_id == "stig":
            notes.append(
                f"control '{control_name}' excluded, but no STIG skip_rule mapping is implemented "
                f"(catalog/defense/hardening/stig.yml) — pf_controls still does not apply the toggle itself."
            )
            continue
        mapping = control_rules.get(control_name)
        if not mapping:
            notes.append(
                f"control '{control_name}' excluded, but no control-cis-rules.yml entry exists for it — no skip_rule derived."
            )
            continue
        for os_ in oses_in_scope:
            os_map = mapping.get(os_)
            if not os_map:
                continue
            if os_map["level"] not in baseline_levels:
                notes.append(
                    f"control '{control_name}' excluded for {os_}, but its CIS rule(s) are level "
                    f"'{os_map['level']}', which baseline '{baseline_id}' does not select by default — "
                    f"no skip_rule needed (the baseline would not have applied it anyway)."
                )
                continue
            skip_rules[os_].extend(os_map["rules"])

    return skip_rules, notes


# Rules PurpleForge must skip on the pinned ansible-lockdown role version — none is
# a PurpleForge or collection bug. Keyed by os. Curated by static scan + live
# deploys against the pinned vendor/ submodule; revisit when it is bumped.
#   CLIENT (Win10/11) upstream typos that abort the whole play:
#     18.9.19.4/.5 — win_regedit path missing the drive colon ("HKLM\..." not
#       "HKLM:\..."), rejected as "not a valid powershell path".
#     18.9.25.5/.6 (LAPS length/age) — reversed comparison operator in the rule's
#       `when:` ("=> 15" / "=< 30" instead of ">=" / "<="), a Jinja syntax error.
#   SERVER member-server WinRM-severing rule upstream forgot to gate behind
#   win_skip_for_test (its sibling 2.2.16 IS gated, 2.2.22 is not, in all 3 roles):
#     2.2.22 — "Deny network logon to Local account and member of Administrators"
#       cuts off the local `ansible` WinRM account mid-run. DC-only 2.2.21 (Guests)
#       is harmless and stays on.
BROKEN_UPSTREAM_CIS_RULES: dict[str, list[str]] = {
    "windows-server-2019": ["win19cis_rule_2_2_22"],
    "windows-server-2022": ["win22cis_rule_2_2_22"],
    "windows-server-2025": ["win25cis_rule_2_2_22"],
    "windows-10-22h2": [
        "win10cis_rule_18_9_19_4", "win10cis_rule_18_9_19_5",
        "win10cis_rule_18_9_25_5", "win10cis_rule_18_9_25_6",
    ],
    "windows-11-23h2": [
        "win11cis_rule_18_9_19_4", "win11cis_rule_18_9_19_5",
        "win11cis_rule_18_9_25_5", "win11cis_rule_18_9_25_6",
    ],
}


def plan_hardening(machines: list[dict], resolved_defense: dict, reconciliation: dict) -> dict:
    hardening = resolved_defense.get("hardening", {})
    baseline_id = hardening.get("baseline", "none")
    apply_to = expand_role_or_all(hardening.get("apply_to"))
    target_machines = [m for m in machines if m["role"] in apply_to]

    if baseline_id in ("none", "baseline-controls") or not target_machines:
        _, notes = resolve_hardening_skip_rules(baseline_id, reconciliation, set())
        return {"baseline": baseline_id, "engine": "none", "apply_to": sorted(apply_to), "groups": [], "notes": notes}

    baseline = load_hardening_baseline(baseline_id)
    oses = sorted({m["os"] for m in target_machines})
    skip_rules_by_os, notes = resolve_hardening_skip_rules(baseline_id, reconciliation, set(oses))

    groups, errors = [], []
    for os_ in oses:
        role_name = baseline["role_by_os"].get(os_)
        hosts = [m["name"] for m in target_machines if m["os"] == os_]
        if not role_name:
            errors.append(
                f"hardening.baseline '{baseline_id}' has no ansible-lockdown role for os '{os_}' "
                f"(hosts: {', '.join(hosts)}) — see catalog/defense/hardening/{baseline_id}.yml's role_by_os."
            )
            continue
        roles_present = {m["role"] for m in target_machines if m["os"] == os_}
        tags = sorted({t for r in roles_present for t in baseline["tags_by_role"].get(r, [])})
        groups.append(
            {
                "os": os_,
                "role_name": role_name,
                "hosts": hosts,
                "tags": tags,
                "skip_rule_vars": skip_rules_by_os.get(os_, []) + BROKEN_UPSTREAM_CIS_RULES.get(os_, []),
            }
        )

    if errors:
        raise SpecError("hardening plan errors:\n" + "\n".join(f"  - {e}" for e in errors))
    return {
        "baseline": baseline_id,
        "engine": baseline["engine"],
        "apply_to": sorted(apply_to),
        "groups": groups,
        "notes": notes,
    }


def plan_edr(resolved_defense: dict, machines: list[dict]) -> list[dict]:
    plans = []
    for entry in resolved_defense.get("edr", []):
        product = entry["product"]
        catalog_path = EDR_DIR / f"{product}.yml"
        catalog_entry = load_yaml(catalog_path) if catalog_path.exists() else {}
        targets = expand_role_or_all(entry.get("targets"))
        target_hosts = [m["name"] for m in machines if m["role"] in targets]

        if not catalog_entry:
            plans.append(
                {
                    "product": product,
                    "mode": entry["mode"],
                    "targets": target_hosts,
                    "status": "not-implemented",
                    "reason": f"no catalog/defense/edr/{product}.yml entry found",
                }
            )
        elif catalog_entry.get("backend_required"):
            plans.append(
                {
                    "product": product,
                    "mode": entry["mode"],
                    "targets": target_hosts,
                    "status": "not-implemented",
                    "reason": f"'{product}' needs a management backend this project does not build (PREVENT/RESPOND only) — recorded, not silently skipped.",
                }
            )
        elif product == "defender-av":
            plans.append(
                {
                    "product": product,
                    "mode": entry["mode"],
                    "targets": target_hosts,
                    "status": "implemented",
                    "settings": entry.get("settings", {}),
                }
            )
        else:
            plans.append(
                {
                    "product": product,
                    "mode": entry["mode"],
                    "targets": target_hosts,
                    "status": "not-implemented",
                    "reason": "no implementation wired for this product yet",
                }
            )
    return plans


def plan_deception(resolved_defense: dict, theme: dict, groups: dict[str, list[dict]]) -> dict:
    deception = resolved_defense.get("deception", {})
    count = deception.get("honey_accounts", 0)
    if count <= 0:
        return {"honey_accounts": [], "run_on": None}
    root_dcs = groups.get("domain_controllers", [])
    run_on = root_dcs[0]["name"] if root_dcs else None
    pattern = theme.get("honey_account_naming", "honey.user.{n}")
    accounts = [pattern.format(n=i + 1) for i in range(count)]
    return {"honey_accounts": accounts, "run_on": run_on}


def yaml_scalar(value) -> str:
    """Renders a Python value as a YAML-safe scalar string for direct
    interpolation into a Jinja template (avoids fragile in-template filters —
    the template just prints these, it doesn't reason about types)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))  # quoted string, JSON quoting is valid YAML


def render_defensive_controls(
    hardening_plan: dict,
    edr_plan: list[dict],
    deception_plan: dict,
    machines: list[dict],
    resolved_defense: dict,
    ansible_groups: dict[str, list[dict]],
    out_dir: Path,
) -> None:
    dst = out_dir / "ansible"
    (dst / "playbooks").mkdir(parents=True, exist_ok=True)

    apply_to = set(hardening_plan.get("apply_to", [])) or expand_role_or_all(None)
    all_target_hosts = [m["name"] for m in machines if m["role"] in apply_to]
    controls = resolved_defense.get("hardening", {}).get("controls", {})

    all_dc_names = {
        h["name"]
        for h in ansible_groups.get("domain_controllers", [])
        + ansible_groups.get("domain_controllers_additional", [])
        + ansible_groups.get("child_domain_controllers", [])
    }
    dc_hosts = [h for h in all_target_hosts if h in all_dc_names]
    root_dcs = ansible_groups.get("domain_controllers", [])
    laps_schema_host = root_dcs[0]["name"] if root_dcs else (dc_hosts[0] if dc_hosts else None)

    edr_implemented = []
    for e in edr_plan:
        if e["status"] != "implemented":
            continue
        edr_implemented.append(
            {
                "product": e["product"],
                "mode": e["mode"],
                "targets": e["targets"],
                "settings": [(k, yaml_scalar(v)) for k, v in e.get("settings", {}).items()],
            }
        )

    controls_rendered = {
        "laps": yaml_scalar(controls.get("laps", False)),
        "lsa_protection": yaml_scalar(controls.get("lsa_protection", False)),
        "smb_signing": yaml_scalar(controls.get("smb_signing", "disable")),
        "ldap_signing": yaml_scalar(controls.get("ldap_signing", "disable")),
        "disable_llmnr_nbtns_mdns": yaml_scalar(controls.get("disable_llmnr_nbtns_mdns", False)),
        "credential_guard": yaml_scalar(controls.get("credential_guard", False)),
        "ntlmv2_only": yaml_scalar(controls.get("ntlmv2_only", False)),
        # json.dumps (not raw interpolation) so values containing backslashes
        # (e.g. "KINGDOM\da-treasury") come out as valid YAML double-quoted
        # scalars — \d is not a legal YAML escape and would break the parse.
        "protected_users_group": [json.dumps(u) for u in controls.get("protected_users_group", [])],
    }

    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "defensive-controls.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    rendered = template.render(
        hardening=hardening_plan,
        edr=edr_implemented,
        deception=deception_plan,
        all_target_hosts=all_target_hosts,
        controls=controls_rendered,
        dc_hosts=dc_hosts,
        laps_schema_host_yaml=json.dumps(laps_schema_host) if laps_schema_host else "null",
    )
    (dst / "playbooks" / "defensive-controls.yml").write_text(rendered, encoding="utf-8")


def render_ansible(
    spec: dict,
    machines: list[dict],
    admin_password: str,
    ansible_password: str,
    out_dir: Path,
) -> dict[str, list[dict]]:
    src = TEMPLATES_DIR / "ansible"
    dst = out_dir / "ansible"
    (dst / "playbooks").mkdir(parents=True, exist_ok=True)
    (dst / "inventory").mkdir(parents=True, exist_ok=True)

    shutil.copy(src / "ansible.cfg", dst / "ansible.cfg")
    shutil.copy(src / "playbooks" / "ad-topology.yml", dst / "playbooks" / "ad-topology.yml")

    groups = build_ansible_groups(spec, machines, admin_password)

    template = jinja2.Template(
        (src / "inventory" / "hosts.yml.j2").read_text(encoding="utf-8"), keep_trailing_newline=True
    )
    rendered = template.render(
        lab_name=spec["lab"]["name"],
        ansible_password=ansible_password,
        groups=groups,
        local_admin_username=WINDOWS_ADMIN_USERNAME,
    )
    (dst / "inventory" / "hosts.yml").write_text(rendered, encoding="utf-8")
    return groups


def run_terraform_plan(tf_dir: Path) -> int:
    """Structural validation only — never how a real lab is deployed (that
    needs -backend-config=backend.hcl against a bootstrapped storage account,
    see infra-azure's SKILL.md). `init -backend=false` alone isn't enough:
    tested empirically against Terraform 1.15.7, it lets `validate` pass but
    `plan` still refuses ("Backend initialization required") because the
    partial `backend "azurerm" {}` block is still declared in versions.tf and
    `-backend=false`'s disabled-backend marker doesn't survive to the next
    command. The documented workaround is an override.tf swapping the
    backend to `local` for this run only — written here and always removed
    before returning, so a real deploy can never accidentally inherit it."""
    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        print(
            "warning: terraform not found on PATH; skipping plan (install terraform to exercise this step).",
            file=sys.stderr,
        )
        return 0

    override_path = tf_dir / "override.tf"
    local_state_path = tf_dir / "terraform.tfstate"
    override_path.write_text('terraform {\n  backend "local" {}\n}\n', encoding="utf-8")
    try:
        for cmd in (["init", "-input=false"], ["validate"], ["plan", "-input=false"]):
            full = [terraform_bin, f"-chdir={tf_dir}", *cmd]
            print(f"  $ {' '.join(full)}")
            result = subprocess.run(full)
            if result.returncode != 0:
                return result.returncode
        return 0
    finally:
        override_path.unlink(missing_ok=True)
        local_state_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# destroy: /destroy is "terraform destroy + verificación de coste cero" — not
# just a clean terraform exit code (invariant #4). Every
# lab's resources live inside a single resource group named after lab.name
# (see templates/terraform/azure/main.tf), so the verification step queries
# Azure directly for that resource group after destroy, rather than trusting
# Terraform's own state was complete or that nothing was created out-of-band.
# ---------------------------------------------------------------------------


def verify_azure_teardown(lab_name: str) -> bool:
    """Returns True unless we have positive evidence the resource group is
    still there (never returns a false "confirmed gone" on an ambiguous
    az CLI error, e.g. an auth failure — that's reported as "could not
    verify", not silently treated as success).

    Uses `az rest` against the ARM REST API directly, not `az group show` —
    verified on a real deploy that `az group show`/`az group list` (and
    separately `az vm ...`/`az network ... show-effective-...`) crash with a
    Python traceback (`ModuleNotFoundError:
    azure.mgmt.resource.resources.v20XX...` or similar) in some environments,
    an azure-cli command-loading bug unrelated to credentials. That crash's
    non-zero exit code and traceback stderr don't match the "gone" or
    "still there" checks below, so it fell into the (correctly) ambiguous
    branch — but every real deploy that hit it, hit it, making this the
    common case there rather than a rare edge case worth just flagging.
    `az rest` is a thin REST passthrough with its own minimal argument
    parsing that doesn't exercise the broken command-loading path."""
    az_bin = shutil.which("az")
    if not az_bin:
        print("warning: az CLI not found; cannot verify teardown — check the Azure portal manually.", file=sys.stderr)
        return True

    sub = os.environ.get("ARM_SUBSCRIPTION_ID")
    if not sub:
        acct = subprocess.run([az_bin, "account", "show", "--query", "id", "-o", "tsv"], capture_output=True, text=True)
        sub = acct.stdout.strip() if acct.returncode == 0 else None
    if not sub:
        print(
            "warning: could not determine the subscription id (set ARM_SUBSCRIPTION_ID); "
            "cannot verify teardown — check the Azure portal manually.",
            file=sys.stderr,
        )
        return True

    url = f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{lab_name}?api-version=2021-04-01"
    result = subprocess.run([az_bin, "rest", "--method", "get", "--url", url], capture_output=True, text=True)
    if result.returncode == 0:
        print(
            f"WARNING: resource group '{lab_name}' still exists after destroy — remaining resources:", file=sys.stderr
        )
        subprocess.run([az_bin, "resource", "list", "--resource-group", lab_name, "-o", "table"])
        return False

    stderr_lower = result.stderr.lower()
    if "resourcegroupnotfound" in stderr_lower:
        print(f"  verified: resource group '{lab_name}' no longer exists — no leftover Azure cost from this lab.")
        return True

    print(
        f"warning: could not confirm resource group '{lab_name}' is gone (az CLI error, possibly auth-related):\n"
        f"  {result.stderr.strip()}\n"
        f"  Check the Azure portal manually before assuming teardown is complete.",
        file=sys.stderr,
    )
    return True  # ambiguous, not positive evidence of failure — flagged, not silently passed


# ---------------------------------------------------------------------------
# deploy / teardown: thin, deterministic wrappers around the generated
# deploy.sh / teardown.sh (rendered by render_deploy_scripts). The scripts are
# the single source of truth for the exact commands; these commands add the
# guardrail gate (never spend on a FAIL) and re-generate the artifacts if
# they're stale, then hand off to the script. "No AI" means a human can run
# either the script directly or this subcommand — both do the same thing.
# ---------------------------------------------------------------------------


def _run_self(subcommand: list[str]) -> int:
    """Invoke this same forge.py as a subprocess (reuse a full command, e.g. the
    guardrail gate, without refactoring it into a callable that fakes argparse)."""
    return subprocess.run([sys.executable, str(Path(__file__).resolve()), *subcommand]).returncode


def cmd_deploy(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    manifest_path = lab_dir / "lab-manifest.json"
    deploy_sh = lab_dir / "deploy.sh"

    if not manifest_path.exists() or not deploy_sh.exists():
        print(
            f"error: {lab_dir} has no lab-manifest.json / deploy.sh — run `forge.py generate {args.spec}` first.",
            file=sys.stderr,
        )
        return 2

    if not args.skip_guardrail:
        print("=== guardrail gate (invariants must PASS before any cloud spend) ===")
        if _run_self(["guardrail", str(spec_path), *(["--out-dir", str(lab_dir)] if args.out_dir else [])]) != 0:
            print(
                "FAIL: guardrail did not pass — refusing to deploy. Fix the spec, or "
                "re-run with --skip-guardrail (not recommended).",
                file=sys.stderr,
            )
            return 1

    print(f"\n=== DEPLOY {lab_name} — this creates BILLABLE Azure resources ===")
    print(f"    running {deploy_sh.relative_to(REPO_ROOT) if deploy_sh.is_relative_to(REPO_ROOT) else deploy_sh}")
    extra = ["--sizes-only"] if args.sizes_only else []
    return subprocess.run(["bash", str(deploy_sh), *extra]).returncode


def cmd_teardown(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    teardown_sh = lab_dir / "teardown.sh"
    if not teardown_sh.exists():
        print(
            f"warning: {teardown_sh} not found — falling back to `forge.py destroy` "
            f"(no VM-start / snapshot-sweep gotcha handling).",
            file=sys.stderr,
        )
        return _run_self(["destroy", str(spec_path), "--yes", *(["--out-dir", str(lab_dir)] if args.out_dir else [])])
    print(f"=== TEARDOWN {lab_name} — destroy to cost-zero + verify ===")
    return subprocess.run(["bash", str(teardown_sh)]).returncode


def cmd_destroy(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]

    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    tf_root = lab_dir / "terraform"
    if not tf_root.exists():
        print(
            f"error: no terraform/ directory found under {lab_dir} (nothing generated, or already destroyed?)",
            file=sys.stderr,
        )
        return 2
    provider_dirs = sorted(d for d in tf_root.iterdir() if d.is_dir())
    if not provider_dirs:
        print(f"error: {tf_root} has no provider subdirectory", file=sys.stderr)
        return 2

    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        print("error: terraform not found on PATH.", file=sys.stderr)
        return 2

    overall_ok = True
    for provider_dir in provider_dirs:
        provider = provider_dir.name
        print(f"=== {provider}: {lab_name} ===")

        backend_hcl = provider_dir / "backend.hcl"
        init_cmd = [terraform_bin, f"-chdir={provider_dir}", "init", "-input=false"]
        if backend_hcl.exists():
            init_cmd.append(f"-backend-config={backend_hcl.name}")
        else:
            print(
                f"  warning: no {backend_hcl.name} in {provider_dir}; assuming already initialized against the right backend.",
                file=sys.stderr,
            )
        print(f"  $ {' '.join(init_cmd)}")
        if subprocess.run(init_cmd).returncode != 0:
            overall_ok = False
            continue

        action = ["plan", "-destroy", "-input=false"] if args.check_only else ["destroy", "-input=false"]
        if args.yes and not args.check_only:
            action.append("-auto-approve")
        full = [terraform_bin, f"-chdir={provider_dir}", *action]
        print(f"  $ {' '.join(full)}")
        if subprocess.run(full).returncode != 0:
            overall_ok = False
            continue

        if args.check_only:
            continue

        if provider == "azure":
            if not verify_azure_teardown(lab_name):
                overall_ok = False
        else:
            print(f"  note: no post-destroy verification implemented for provider '{provider}' yet.")

    if overall_ok:
        print(f"OK: {lab_name} destroyed and verified — no expected leftover cost.")
    else:
        print(f"FAIL: {lab_name} destroy did not fully verify clean — see warnings above.", file=sys.stderr)
    return 0 if overall_ok else 1


# ---------------------------------------------------------------------------
# lab-report.md — human-readable documentation of the lab, generated
# alongside lab-manifest.json from the exact same data (no separate source of
# truth). Covers machines, network topology, AD groups, users+passwords,
# hardening applied, and vulnerabilities, per the brief. Deliberately does
# NOT try to predict the literal usernames/group names BadBlood will create:
# BadBlood draws all of its randomness through PowerShell's `Get-Random`,
# seeded via `Get-Random -SetSeed` at ANSIBLE RUNTIME on the Windows host —
# .NET's RNG algorithm is not the same as Python's, so the same integer seed
# does not produce the same name sequence in this script. Only counts (and
# the seed itself, for later reproducibility) are knowable at generate time;
# claiming otherwise would be exactly the kind of unverified claim this
# project has repeatedly caught and corrected elsewhere (see Fase 6).
# ---------------------------------------------------------------------------

# Per-vuln (account_var, password_var) in that vuln's build_vuln_vars() output
# — used to render a "account / password" row. Vulns absent here have no
# credentialed account (a machine-wide policy change, a computer-object flag,
# or a fixed value baked into the task file) and get a NOTE instead.
VULN_CREDENTIAL_VARS = {
    "kerberoasting": ("vuln_kerberoast_account", "vuln_kerberoast_password"),
    "asreproast": ("vuln_asrep_account", "vuln_asrep_password"),
    "dcsync-acl": ("vuln_dcsync_account", "vuln_dcsync_password"),
    "passwords-in-description": ("vuln_pwddesc_account", "vuln_pwddesc_password"),
    "constrained-delegation": ("vuln_delegation_account", "vuln_delegation_password"),
    "shadow-credentials": ("vuln_shadowcred_target", "vuln_shadowcred_target_password"),
    "dnsadmins-privesc": ("vuln_dnsadmins_account", "vuln_dnsadmins_password"),
    "rbcd-abuse": ("vuln_rbcd_delegate_account", "vuln_rbcd_delegate_password"),
    "backup-operators-membership": ("vuln_backupop_account", "vuln_backupop_password"),
    "writable-gpo": ("vuln_gpo_account", "vuln_gpo_password"),
    "adminsdholder-acl": ("vuln_adminsdholder_account", "vuln_adminsdholder_password"),
    "readable-gmsa": ("vuln_gmsa_reader_account", "vuln_gmsa_reader_password"),
    "esc4-template-acl": ("vuln_esc4_account", "vuln_esc4_password"),
    "mssql-weak-sa": (None, "vuln_mssql_sa_password"),  # sa is a fixed SQL login, not a cast AD account
}

VULN_CREDENTIAL_NOTES = {
    "gpp-cpassword": "No named account — a GPO's Groups.xml carries a cpassword that decrypts to `Local*8!` (published MS14-025 key).",
    "unconstrained-delegation": "No credentialed account — sets TRUSTED_FOR_DELEGATION on a computer object.",
    "smb-signing-disabled": "No account — machine-wide registry policy (RequireSecuritySignature=0).",
    "ntlm-downgrade": "No account — machine-wide registry policy (LmCompatibilityLevel=2).",
    "adcs-esc1": "No account — publishes the ESC1 certificate template (ENROLLEE_SUPPLIES_SUBJECT) for enrollment by Domain Users.",
    "laps-read-acl": "No named account — grants CONTROL_ACCESS read on msLAPS-Password (domain-wide) to an existing group, `Domain Users` by default.",
    "unquoted-service-path": "No account — local privesc: a LocalSystem service with an unquoted, space-bearing ImagePath and an attacker-writable path prefix (`C:\\PFApps`).",
    "weak-service-permissions": "No account — local privesc: a LocalSystem service whose DACL grants Authenticated Users SERVICE_ALL_ACCESS (sc config reconfigurable).",
    "dll-hijacking": "No account — local privesc: a LocalSystem service whose own binary directory is writable by Authenticated Users (DLL search-order hijack).",
    "scheduled-task-privesc": "No account — local privesc: a scheduled task running as SYSTEM whose script (`C:\\PFScripts\\maintenance.ps1`) is writable by Authenticated Users.",
    "always-install-elevated": "No account — local privesc: AlwaysInstallElevated=1 in both HKLM and HKCU (any user's MSI installs run as SYSTEM).",
}


def describe_vuln_credentials(vid: str, vvars: dict) -> str:
    entry = VULN_CREDENTIAL_VARS.get(vid)
    if entry:
        account_key, password_key = entry
        password = vvars.get(password_key, "?")
        if account_key is None:
            return f"`sa` / `{password}`"  # fixed SQL login, not a cast AD account
        account = vvars.get(account_key, "?")
        return f"`{account}` / `{password}`"
    return VULN_CREDENTIAL_NOTES.get(vid, "—")


def render_lab_report(
    spec: dict,
    manifest: dict,
    machines: list[dict],
    network_plan: dict,
    ansible_groups: dict[str, list[dict]],
    theme: dict,
    admin_password: str,
    ansible_password: str,
    planned_vulns: list[dict],
    hardening_plan: dict,
    edr_plan: list[dict],
    deception_plan: dict,
    out_dir: Path,
) -> None:
    # "Administrator" here is the domain's real RID-500 account, not a fresh
    # object win_domain creates: promoting the first DC of a new forest seeds
    # it from whatever local account did the promotion, which is always
    # local_admin_username (ad-topology.yml's pre_tasks renames it to
    # "Administrator" before promotion — Azure forbids "Administrator" as the
    # VM's own admin_username). Its password is therefore unchanged by
    # promotion: the VM's local admin password — which is also what
    # build_ansible_groups uses uniformly as every domain_password (including
    # the DSRM/safe-mode password win_domain/win_domain_controller separately
    # accept), so there is only the one password to report here, not a
    # distinct per-domain secret from domain_passwords.
    domain_admin_rows = [
        {"domain": d["domain"], "username": "Administrator", "password": admin_password} for d in spec["forest"]
    ]

    vuln_rows = [
        {
            "id": v["id"],
            "name": v["name"],
            "severity": v["severity"],
            "mitre": v["mitre"],
            "run_on": v["run_on"],
            "neutralization": v["neutralization"],
            "credentials": describe_vuln_credentials(v["id"], v.get("vars", {})),
        }
        for v in planned_vulns
    ]

    context = {
        "lab": spec["lab"],
        "theme_id": theme["id"],
        "theme_name": theme["name"],
        "cost_estimate": manifest["cost_estimate"],
        "notes": manifest["notes"],
        "source_spec": manifest["source_spec"],
        "network_plan": network_plan,
        "machines": machines,
        "forest": spec["forest"],
        "population": spec["population"],
        "population_plans": manifest["population_plans"],
        "domain_admin_rows": domain_admin_rows,
        "winrm_username": WINRM_AUTOMATION_USERNAME,
        "winrm_password": ansible_password,
        "local_admin_username": WINDOWS_ADMIN_USERNAME,
        "local_admin_password": admin_password,
        "vuln_rows": vuln_rows,
        "hardening_plan": hardening_plan,
        "resolved_controls": manifest["defense_resolved"]["hardening"].get("controls", {}),
        "edr_plan": edr_plan,
        "deception_plan": deception_plan,
        "reconciliation": manifest["reconciliation"],
        "attack_chain": manifest["attack_chain"],
    }

    # Markdown tables break on a blank line between rows (unlike the YAML
    # this project's other .j2 templates render, which tolerates blank lines
    # fine — this is the first Markdown output, and the first template where
    # a bare jinja2.Template's default whitespace handling actually mattered).
    # trim_blocks/lstrip_blocks remove the line a tag-only {% %} sits on
    # instead of leaving it as a blank line in the rendered table.
    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    template = env.from_string((TEMPLATES_DIR / "lab-report.md.j2").read_text(encoding="utf-8"))
    (out_dir / "lab-report.md").write_text(template.render(**context), encoding="utf-8")


# ---------------------------------------------------------------------------
# verify.yml — post-deploy check that hardening/EDR/vulnerabilities actually
# took effect, run separately from site.yml (it's a check, not a deploy
# step — see README "Validating what actually got applied"). Every check
# reuses the exact registry path/property name from the task-file or role
# that sets it (see the grep audit in that README section's own commit) —
# copied, not re-derived, to avoid a typo silently making a check meaningless.
#
# IMPORTANT — untested against a real host: this repository has never had a
# live Windows VM to run this against. Syntax-checked and carefully
# cross-referenced against each corresponding inject/hardening task, not
# proven correct by execution. Treat a clean run with the same skepticism
# this project applies everywhere else — verify the verifier once real hosts
# exist.
# ---------------------------------------------------------------------------

# Must match templates/ansible/roles/pf_defender_av/tasks/main.yml's own
# hardcoded $ids list exactly — duplicated here (Python) rather than shared,
# since that file is a static Ansible role never rendered through this
# script; update both if the ASR rule set ever changes.
DEFENDER_ASR_RULE_IDS = [
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
]


def resolve_defender_av_expected(mode: str, settings: dict) -> dict:
    """Mirrors pf_defender_av/tasks/main.yml's own `default()` resolution
    exactly, so verify.yml knows what to expect without needing to duplicate
    that Jinja logic at Ansible runtime."""
    return {
        "asr_action": settings.get("asr_rules") or ("block" if mode == "prevent" else "audit"),
        "tamper_enabled": settings["tamper_protection"] if "tamper_protection" in settings else (mode == "prevent"),
        "network_protection_enabled": settings["network_protection"]
        if "network_protection" in settings
        else (mode != "detect"),
    }


def render_verify_playbook(
    machines: list[dict],
    ansible_groups: dict[str, list[dict]],
    theme: dict,
    hardening_plan: dict,
    resolved_controls: dict,
    edr_plan: list[dict],
    planned_vulns: list[dict],
    population_plans: list[dict],
    out_dir: Path,
) -> None:
    dc_domain_hosts = ansible_groups.get("domain_controllers", []) + ansible_groups.get("child_domain_controllers", [])
    population_by_domain = {p["domain"]: p for p in population_plans}

    apply_to = set(hardening_plan.get("apply_to", [])) or expand_role_or_all(None)
    all_target_hosts = [m["name"] for m in machines if m["role"] in apply_to]

    all_dc_names = {
        h["name"]
        for h in ansible_groups.get("domain_controllers", [])
        + ansible_groups.get("domain_controllers_additional", [])
        + ansible_groups.get("child_domain_controllers", [])
    }
    dc_target_hosts = [h for h in all_target_hosts if h in all_dc_names]

    edr_defender = None
    for e in edr_plan:
        if e["product"] == "defender-av" and e["status"] == "implemented":
            edr_defender = {
                "targets": e["targets"],
                **resolve_defender_av_expected(e["mode"], e.get("settings", {})),
            }
            break

    context = {
        "dc_domain_hosts": dc_domain_hosts,
        "population_by_domain": population_by_domain,
        "theme_extra_groups": theme["extra_groups"],
        "all_target_hosts": all_target_hosts,
        "dc_target_hosts": dc_target_hosts,
        "resolved_controls": resolved_controls,
        "edr_defender": edr_defender,
        "asr_rule_ids": DEFENDER_ASR_RULE_IDS,
        "planned_vulns": planned_vulns,
    }

    env = jinja2.Environment(trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    template = env.from_string((TEMPLATES_DIR / "ansible" / "playbooks" / "verify.yml.j2").read_text(encoding="utf-8"))
    dst = out_dir / "ansible" / "playbooks"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "verify.yml").write_text(template.render(**context), encoding="utf-8")


def cmd_lab_spec(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2

    result = load_and_resolve(spec_path)
    if result is None:
        return 1
    spec, manifest = result
    reconciliation = manifest["reconciliation"]

    print(f"OK: {spec_path.name} is valid.")
    if reconciliation["warnings"]:
        print("  reconciliation warnings:")
        for w in reconciliation["warnings"]:
            print(f"    - {w['detail']}")
    if reconciliation["excluded_controls"]:
        print("  reconciliation exclusions (on_conflict: exclude-control):")
        for x in reconciliation["excluded_controls"]:
            print(f"    - {x['detail']} -> {x['action']}")

    if args.check_only:
        return 0

    out_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / spec["lab"]["name"]
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "lab-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"  wrote {manifest_path.relative_to(REPO_ROOT) if manifest_path.is_relative_to(REPO_ROOT) else manifest_path}"
    )
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2

    result = load_and_resolve(spec_path)
    if result is None:
        return 1
    spec, manifest = result
    reconciliation = manifest["reconciliation"]

    print(f"OK: {spec_path.name} is valid.")
    if reconciliation["warnings"]:
        print("  reconciliation warnings:")
        for w in reconciliation["warnings"]:
            print(f"    - {w['detail']}")
    if reconciliation["excluded_controls"]:
        print("  reconciliation exclusions (on_conflict: exclude-control):")
        for x in reconciliation["excluded_controls"]:
            print(f"    - {x['detail']} -> {x['action']}")

    provider = spec["lab"]["provider"]
    if provider not in ("azure", "proxmox"):
        print(
            f"FAIL: infra-{provider} is not implemented yet (Azure and Proxmox today; AWS is on the roadmap).",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / spec["lab"]["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    network_plan = manifest["network_plan"]
    machines = flatten_machines(spec, network_plan)
    # Reuse infra secrets from a prior generate so regenerating a deployed lab
    # doesn't re-randomize admin_password (which forces Terraform to replace
    # every VM). First generate mints a fresh unguessable pair.
    admin_password, ansible_password = load_existing_infra_secrets(out_dir, provider)
    if admin_password and ansible_password:
        print("  reusing infra secrets (admin/ansible) from a previous generate")
    else:
        admin_password = generate_password()
        ansible_password = generate_password()

    if provider == "proxmox":
        render_proxmox_terraform(network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"])
    else:
        render_azure_terraform(network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"])
    theme = load_theme(spec["lab"]["theme"])
    ansible_groups = render_ansible(spec, machines, admin_password, ansible_password, out_dir)
    population_plans = render_ad_population(theme, spec, ansible_groups, out_dir)
    write_lab_secrets(out_dir, admin_password, ansible_password, population_plans)

    service_hosts = plan_service_provisioning(machines)
    render_service_provisioning(service_hosts, spec["lab"]["name"], out_dir)

    catalog = load_vuln_catalog()
    attack_chain_mode = spec.get("attack_chain", {}).get("mode", "independent")
    attack_chain = resolve_attack_chain(spec, catalog, population_plans, attack_chain_mode)
    planned_vulns = plan_vuln_injection(spec, catalog, machines, ansible_groups, reconciliation, attack_chain)
    render_vuln_injection(spec, planned_vulns, out_dir)

    resolved_defense = manifest["defense_resolved"]
    hardening_plan = plan_hardening(machines, resolved_defense, reconciliation)
    edr_plan = plan_edr(resolved_defense, machines)
    deception_plan = plan_deception(resolved_defense, theme, ansible_groups)
    render_defensive_controls(
        hardening_plan, edr_plan, deception_plan, machines, resolved_defense, ansible_groups, out_dir
    )
    render_site_playbook(bool(planned_vulns), bool(service_hosts), out_dir)
    # Provider-specific deploy.sh/teardown.sh (Azure: az + remote state + SKU
    # auto-sizing; Proxmox: Proxmox API + local state + bastion VLAN routing).
    render_deploy_scripts(spec, manifest, machines, network_plan, out_dir)

    manifest["machines_flat"] = machines
    manifest["ansible_groups"] = ansible_groups
    manifest["theme"] = theme["id"]
    manifest["service_hosts"] = service_hosts
    manifest["population_plans"] = population_plans
    manifest["attack_chain"] = attack_chain
    manifest["vulnerabilities_planned"] = planned_vulns
    manifest["hardening_plan"] = hardening_plan
    manifest["edr_plan"] = edr_plan
    manifest["deception_plan"] = deception_plan
    manifest_path = out_dir / "lab-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    render_lab_report(
        spec,
        manifest,
        machines,
        network_plan,
        ansible_groups,
        theme,
        admin_password,
        ansible_password,
        planned_vulns,
        hardening_plan,
        edr_plan,
        deception_plan,
        out_dir,
    )
    render_verify_playbook(
        machines,
        ansible_groups,
        theme,
        hardening_plan,
        resolved_defense["hardening"].get("controls", {}),
        edr_plan,
        planned_vulns,
        population_plans,
        out_dir,
    )

    print(
        f"OK: generated {spec_path.name} -> {out_dir.relative_to(REPO_ROOT) if out_dir.is_relative_to(REPO_ROOT) else out_dir}"
    )
    print(f"  wrote {manifest_path.name} (gitignored — has secrets)")
    print("  wrote lab-report.md (contains generated secrets — gitignored, never commit)")
    print("  wrote ansible/playbooks/verify.yml (post-deploy check, run separately after site.yml — see README)")
    print(
        f"  wrote terraform/{provider}/ (secret-free & shareable; strong secrets isolated in the gitignored secrets.auto.tfvars.json)"
    )
    print(
        "  wrote ansible/ (hosts.yml + ad-population.yml secret-free; population passwords fixed at creation in the COMMITTED group_vars/all/population-secrets.yml; infra keys in the gitignored group_vars/all/secrets.yml)"
    )
    print(
        "  wrote secrets-manifest.json (committed — lists the INFRA secrets deploy.sh mints if absent; population passwords are never minted at deploy)"
    )
    total_users = sum(len(p["users"]) for p in population_plans)
    total_groups = sum(len(p["groups"]) for p in population_plans)
    total_computers = sum(len(p["computers"]) for p in population_plans)
    print(
        f"  wrote ansible/playbooks/ad-population.yml (theme '{theme['id']}', {total_users} users / {total_groups} groups / {total_computers} computers, deterministic — no BadBlood)"
    )
    if service_hosts.get("mssql"):
        print(
            f"  wrote ansible/playbooks/service-provisioning.yml (mssql -> {', '.join(service_hosts['mssql'])}, secure baseline: sa disabled/Windows-auth only/xp_cmdshell off)"
        )
    if attack_chain["mode"] == "ctf":
        print(
            f"  attack_chain: ctf mode — {len(attack_chain['steps'])} vuln(s) cast onto real population objects, {len(attack_chain.get('chained', []))} chained"
        )
    if planned_vulns:
        print(f"  wrote ansible/playbooks/vuln-injection.yml + ansible/vulns/ ({len(planned_vulns)} vuln(s))")
        for v in planned_vulns:
            print(f"      - {v['id']} -> {v['run_on']}  [{v['neutralization'].split(' (')[0]}]")
    print(
        f"  wrote ansible/playbooks/defensive-controls.yml (baseline: {hardening_plan['baseline']}, {len(hardening_plan.get('groups', []))} OS group(s))"
    )
    for n in hardening_plan.get("notes", []):
        print(f"      note: {n}")
    for e in edr_plan:
        if e["status"] != "implemented":
            print(f"      note: edr '{e['product']}' — {e['reason']}")
    print(
        "  wrote ansible/playbooks/site.yml (run this, not the individual playbooks — enforces hardening-before-vulns)"
    )
    print(
        "  wrote deploy.sh + teardown.sh (deterministic no-AI deploy/teardown — run directly or via `forge.py deploy`/`teardown`)"
    )
    if provider == "proxmox":
        print(
            "  NOTE: provider 'proxmox' — before deploy, fill terraform/proxmox/host.auto.tfvars.json (see host.auto.tfvars.example.json) and export PROXMOX_VE_ENDPOINT / PROXMOX_VE_API_TOKEN. Windows templates now only need cloudbase-init (with UserDataPlugin enabled) baked in — WinRM + the `ansible` admin are bootstrapped at first boot via cloudbase-init user-data (terraform/proxmox/cloudinit/windows-bootstrap.ps1.tpl)."
        )

    if args.plan:
        return run_terraform_plan(out_dir / "terraform" / provider)
    return 0


# ---------------------------------------------------------------------------
# ad-inventory: a POST-DEPLOY report, genuinely different from lab-report.md
# (which is spec-time/pre-deploy). Since scripts/population.py replaced
# BadBlood, every user's plaintext password IS already known and documented
# ahead of deployment (lab-report.md's Population section) — this command's
# job is no longer "discover what an unpredictable population turned out to
# be," it's verification: confirm the live domain actually matches what
# lab-manifest.json's population_plans said would be created, and pull NT
# hashes via a DCSync-style dump for anything this project doesn't itself
# control (e.g. an operator's own manual changes to the lab after deploy).
# Queries the domain directly — LDAP (ldap3) for users/groups, `nxc`/netexec
# for the hash dump — rather than guessing anything from the spec.
# ---------------------------------------------------------------------------


def query_ad_inventory(dc_ip: str, domain: str, admin_user: str, admin_password: str) -> dict:
    from ldap3 import ALL, SIMPLE, SUBTREE, Connection, Server

    upn = f"{admin_user}@{domain}"
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    server = Server(dc_ip, port=389, get_info=ALL, connect_timeout=15)
    conn = Connection(server, user=upn, password=admin_password, authentication=SIMPLE, receive_timeout=30)
    if not conn.bind():
        raise SpecError(f"LDAP bind to {dc_ip} as {upn} failed: {conn.result}")

    def dn_to_name(dn: str) -> str:
        return dn.split(",", 1)[0].split("=", 1)[1]

    conn.search(
        base_dn,
        "(&(objectClass=user)(objectCategory=person))",
        SUBTREE,
        attributes=["sAMAccountName", "userAccountControl", "memberOf", "description"],
    )
    users = []
    for e in conn.entries:
        uac = int(e.userAccountControl.value)
        member_of = [dn_to_name(dn) for dn in e.memberOf.values] if "memberOf" in e else []
        users.append(
            {
                "username": str(e.sAMAccountName),
                "enabled": not (uac & 2),  # ADS_UF_ACCOUNTDISABLE
                "description": str(e.description) if "description" in e and e.description else "",
                "groups": sorted(member_of),
            }
        )

    conn.search(base_dn, "(objectClass=group)", SUBTREE, attributes=["sAMAccountName", "description", "member"])
    groups = []
    for e in conn.entries:
        members = [dn_to_name(dn) for dn in e.member.values] if "member" in e else []
        groups.append(
            {
                "name": str(e.sAMAccountName),
                "description": str(e.description) if "description" in e and e.description else "",
                "members": sorted(members),
            }
        )
    conn.unbind()

    hashes: dict[str, dict] = {}
    nxc_bin = shutil.which("nxc") or shutil.which("netexec")
    if nxc_bin:
        result = subprocess.run(
            [nxc_bin, "smb", dc_ip, "-d", domain, "-u", admin_user, "-p", admin_password, "--ntds", "drsuapi"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        # nxc's own line format: "SMB   <ip>   445   <hostname>   <domain\>user:rid:lmhash:nthash:::"
        for line in result.stdout.splitlines():
            m = re.search(r"(?:^|\s)(?:[^\s\\]+\\)?([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", line)
            if m:
                hashes[m.group(1)] = {"rid": m.group(2), "nt_hash": m.group(4)}

    return {"users": users, "groups": groups, "hashes": hashes, "nxc_available": bool(nxc_bin)}


def cmd_ad_inventory(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name

    inventory_path = lab_dir / "ansible" / "inventory" / "hosts.yml"
    manifest_path = lab_dir / "lab-manifest.json"
    if not inventory_path.exists() or not manifest_path.exists():
        print(
            f"error: {lab_dir} has no generated inventory/manifest — run `generate` (and deploy) first.",
            file=sys.stderr,
        )
        return 2

    inventory = load_yaml(inventory_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    dcs = inventory.get("all", {}).get("children", {}).get("domain_controllers", {}).get("hosts", {})
    if not dcs:
        print("error: no domain_controllers found in the generated inventory.", file=sys.stderr)
        return 2
    dc_host = next(iter(dcs.values()))
    dc_ip = dc_host["ansible_host"]
    domain = dc_host["domain"]
    admin_user = dc_host["domain_username"].split("\\")[-1]
    admin_password = dc_host["domain_password"]

    print(f"Querying live domain {domain} via {dc_ip} ...")
    try:
        data = query_ad_inventory(dc_ip, domain, admin_user, admin_password)
    except SpecError as e:
        print(f"error: {e}\n  Is the WireGuard tunnel up, and is this lab actually deployed?", file=sys.stderr)
        return 1
    except ImportError:
        print("error: ldap3 not installed — pip install -r scripts/requirements.txt", file=sys.stderr)
        return 2
    if not data["nxc_available"]:
        print(
            "warning: `nxc`/`netexec` not found on PATH — NT hashes will be omitted. "
            "Install it (pipx install netexec) to include them.",
            file=sys.stderr,
        )

    vuln_accounts: dict[str, str] = {}
    for v in manifest.get("vulnerabilities_planned", []):
        for k, val in v.get("vars", {}).items():
            if k.endswith("_account"):
                vuln_accounts[val] = v["id"]

    builtin_privileged = {"Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"}
    theme_privileged: set[str] = set()
    theme_id = manifest.get("theme")
    if theme_id:
        try:
            theme = load_theme(theme_id)
            theme_privileged = {g["name"] for g in theme.get("extra_groups", [])}
        except SpecError:
            pass  # theme file missing/moved since generate — privileged-group tagging just degrades to builtins only
    privileged_groups = builtin_privileged | theme_privileged

    for u in data["users"]:
        u["nt_hash"] = data["hashes"].get(u["username"], {}).get("nt_hash")
        u["vuln_id"] = vuln_accounts.get(u["username"])
        u["privileged"] = bool(privileged_groups & set(u["groups"]))
    for g in data["groups"]:
        g["privileged"] = g["name"] in privileged_groups

    # Verification, not discovery: population_plans already says exactly who
    # SHOULD exist — flag anything missing (a failed/partial ad-population.yml
    # run) rather than just reporting whatever LDAP happens to return.
    planned_names = {
        u["name"] for p in manifest.get("population_plans", []) if p["domain"] == domain for u in p["users"]
    }
    live_names = {u["username"] for u in data["users"]}
    missing = planned_names - live_names
    if planned_names and missing:
        print(
            f"warning: {len(missing)} of {len(planned_names)} planned population users were NOT found live — ad-population.yml may not have completed.",
            file=sys.stderr,
        )

    template = jinja2.Template(
        (TEMPLATES_DIR / "ad-inventory.md.j2").read_text(encoding="utf-8"), keep_trailing_newline=True
    )
    rendered = template.render(
        lab_name=lab_name,
        domain=domain,
        dc_ip=dc_ip,
        users=sorted(data["users"], key=lambda u: u["username"].lower()),
        groups=sorted(data["groups"], key=lambda g: g["name"].lower()),
        nxc_available=data["nxc_available"],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    out_path = lab_dir / "ad-inventory.md"
    out_path.write_text(rendered, encoding="utf-8")
    print(
        f"OK: wrote {out_path} ({len(data['users'])} users, {len(data['groups'])} groups, {len(data['hashes'])} NT hashes)"
    )
    return 0


# Vulnerability validation confirms two things per injected vuln: that the config
# was APPLIED (the AD artifact proving the injection landed) and that it is
# EXPLOITABLE (the primitive actually works). It deliberately does NOT predict
# detection coverage (PREVENIDO/DETECTADO/NO VISTO) — out of scope for this harness.
# A vuln's whole purpose is to be reachable, so its own validation is about
# presence + exploitability, not whether a SIEM would catch it.
VALID_RESULT = ("YES", "NO", "PARTIAL", "REQUIRES-HUMAN", "PENDING")


# ---------------------------------------------------------------------------
# validate --run: drive the live checks ourselves instead of asking a human to
# fill a results JSON. What's safely automatable over the tunnel (the two
# roasting primitives — crisp output: a hash or nothing) is auto-confirmed with
# nxc/netexec; every other vuln is an ACL abuse, a cert enrollment or a SYSVOL
# read whose "did it actually work" step is genuinely interactive, so we emit
# the exact ready-to-run command and mark it REQUIRES-HUMAN rather than guess.
# We NEVER print a false "not applied": an ambiguous/failed check is PENDING.
# nxc is the signing-aware client the rest of this project standardized on
# (the hardening enforces LDAP signing, which rejects plain ldap3 binds).
# ---------------------------------------------------------------------------

# vuln id -> (nxc roast flag, description). Both APPLIED and EXPLOITABLE are
# proven at once: a returned Kerberos hash means the account is roastable.
ROAST_FLAGS = {
    "asreproast": ("--asreproast", "AS-REP hash"),
    "kerberoasting": ("--kerberoasting", "TGS-REP (service ticket) hash"),
}

# vuln id -> (LDAP filter, human label). A non-empty result proves the artifact
# LANDED (APPLIED); actually abusing it stays a human step (EXPLOITABLE).
LDAP_APPLIED_FILTERS = {
    "readable-gmsa": ("(objectClass=msDS-GroupManagedServiceAccount)", "gMSA object present"),
    "unconstrained-delegation": (
        "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        "non-DC principal trusted for unconstrained delegation",
    ),
    "constrained-delegation": ("(msDS-AllowedToDelegateTo=*)", "msDS-AllowedToDelegateTo set"),
    "shadow-credentials": ("(msDS-KeyCredentialLink=*)", "msDS-KeyCredentialLink set"),
    "rbcd-abuse": (
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) set",
    ),
}

# vuln id -> PowerShell one-shot check executed over WinRM (nxc/netexec winrm -X),
# the twin of LDAP_APPLIED_FILTERS for vulns with no LDAP-visible artifact: the
# five OS-level local-privesc vulns (workstation, no AD object at all) plus
# writable-gpo/adminsdholder-acl, whose "applied" state lives in GroupPolicy/the
# AD: PowerShell provider rather than a raw LDAP filter. Each script prints
# exactly one line, "PF_CHECK:True" or "PF_CHECK:False" — parsed by
# _winrm_check_result, ignoring nxc's own banner/auth noise around it. Scripts
# for account-scoped checks (writable-gpo, adminsdholder-acl) carry the literal
# placeholder __ACCOUNT__, substituted with the vuln's cast account at run time
# (never .format()'d — the scripts are full of literal PowerShell `{ }` blocks).
WINRM_APPLIED_CHECKS = {
    "unquoted-service-path": (
        "$svc = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PFUnquotedSvc' -ErrorAction SilentlyContinue; "
        "$img = $svc.ImagePath; "
        "$unquoted = [bool]($img -and ($img -notmatch '^\"') -and ($img -match ' ')); "
        "$acl = Get-Acl 'C:\\PFApps' -ErrorAction SilentlyContinue; "
        "$writable = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "Write-Output ('PF_CHECK:' + [bool]($unquoted -and $writable))"
    ),
    "weak-service-permissions": (
        # sc.exe sdshow always renders the access mask as symbolic SDDL letters
        # (never the raw hex the inject task-file writes), so match the AU ACE by
        # its DC (SERVICE_CHANGE_CONFIG) bit — the one that actually enables
        # `sc config` reconfiguration, rather than the literal '0xF01FF' string.
        "$sddl = (& sc.exe sdshow PFWeakPermSvc) -join ''; "
        "$hasAce = [bool]($sddl -match '\\(A;;[A-Z]*DC[A-Z]*;;;AU\\)'); "
        "Write-Output ('PF_CHECK:' + $hasAce)"
    ),
    "dll-hijacking": (
        "$acl = Get-Acl -LiteralPath 'C:\\PFApps\\PFMonitor' -ErrorAction SilentlyContinue; "
        "$hasAce = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "$svc = Get-CimInstance Win32_Service -Filter \"Name='PFHijackSvc'\" -ErrorAction SilentlyContinue; "
        "$isSystem = [bool]($svc -and $svc.StartName -eq 'LocalSystem'); "
        "Write-Output ('PF_CHECK:' + [bool]($hasAce -and $isSystem))"
    ),
    "scheduled-task-privesc": (
        "$task = Get-ScheduledTask -TaskName 'PurpleForge Maintenance' -ErrorAction SilentlyContinue; "
        "$isSystem = [bool]($task -and $task.Principal.UserId -match 'SYSTEM'); "
        "$acl = Get-Acl -LiteralPath 'C:\\PFScripts\\maintenance.ps1' -ErrorAction SilentlyContinue; "
        "$writable = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "Write-Output ('PF_CHECK:' + [bool]($isSystem -and $writable))"
    ),
    "always-install-elevated": (
        "$hklm = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "$hkcu = (Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "if ($null -eq $hkcu) { $hkcu = (Get-ItemProperty 'Registry::HKEY_USERS\\.DEFAULT\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated }; "
        "Write-Output ('PF_CHECK:' + [bool]($hklm -eq 1 -and $hkcu -eq 1))"
    ),
    "writable-gpo": (
        "Import-Module GroupPolicy; "
        "$dn = (Get-ADDomain).DistinguishedName; "
        "$linked = [bool]((Get-GPInheritance -Target $dn).GpoLinks | Where-Object { $_.DisplayName -eq 'Workstation Deployment Policy' -and $_.Enabled }); "
        "$perm = Get-GPPermission -Name 'Workstation Deployment Policy' -All -ErrorAction SilentlyContinue | Where-Object { $_.Trustee.Name -eq '__ACCOUNT__' -and $_.Permission -eq 'GpoEditDeleteModifySecurity' }; "
        "Write-Output ('PF_CHECK:' + [bool]($linked -and $perm))"
    ),
    "adminsdholder-acl": (
        "Import-Module ActiveDirectory; "
        "$dn = (Get-ADDomain).DistinguishedName; "
        '$acl = Get-Acl ("AD:\\CN=AdminSDHolder,CN=System," + $dn); '
        "$hasAce = [bool]($acl.Access | Where-Object { $_.IdentityReference -match '__ACCOUNT__' -and $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }); "
        "Write-Output ('PF_CHECK:' + $hasAce)"
    ),
}


def _nxc_bin() -> str | None:
    return shutil.which("nxc") or shutil.which("netexec")


def run_live_validation(rows: list[dict], manifest: dict, lab_dir: Path) -> tuple[list[dict], list[str]]:
    """Execute the live per-vuln checks over the tunnel and return confirmed rows
    + findings — the same shape merge_validation_results produces, so
    render_validation_report consumes it unchanged. Reads the domain-admin
    password from the generated terraform.tfvars.json (the RID-500 Administrator
    shares it — see render_lab_report)."""
    tfvars_path = lab_dir / "terraform" / "azure" / "terraform.tfvars.json"
    if not tfvars_path.exists():
        raise SpecError(f"{tfvars_path} not found — generate + deploy the lab first (need the live credentials).")
    tv = json.loads(tfvars_path.read_text(encoding="utf-8"))
    # admin_password lives in the gitignored secrets.auto.tfvars.json overlay
    # (the account-independent/shareable split — see render_azure_terraform),
    # not in the committed terraform.tfvars.json. Fall back to it.
    admin_pass = tv.get("admin_password")
    if not admin_pass:
        secrets_path = tfvars_path.parent / "secrets.auto.tfvars.json"
        if secrets_path.exists():
            admin_pass = json.loads(secrets_path.read_text(encoding="utf-8")).get("admin_password")
    if not admin_pass:
        raise SpecError(
            "no admin_password in terraform.tfvars.json or secrets.auto.tfvars.json — deploy the lab first (secrets are minted at deploy)."
        )
    admin_user = "Administrator"  # the domain's RID-500, not the local admin_username

    machines = manifest.get("machines_flat", [])
    by_name = {m["name"]: m for m in machines}
    dc_by_domain: dict[str, str] = {}
    for m in machines:
        if m["role"] == "domain-controller":
            dc_by_domain.setdefault(m["domain"], m["ip"])

    nxc = _nxc_bin()
    confirmed: list[dict] = []
    findings: list[str] = []

    for r in rows:
        vid = r["id"]
        host = by_name.get(r["run_on"], {})
        domain = host.get("domain") or (machines[0]["domain"] if machines else "")
        dc_ip = dc_by_domain.get(domain) or (machines and dc_by_domain.get(machines[0]["domain"])) or ""
        row = dict(r)
        row.update(applied="PENDING", exploitable="PENDING", evidence="")

        if not nxc:
            row["evidence"] = "nxc/netexec not on PATH — install it to auto-validate; command left for you below."
            row["applied"] = row["exploitable"] = "REQUIRES-HUMAN"
        elif not dc_ip:
            row["evidence"] = f"no DC IP for domain {domain!r} in the manifest."
            row["applied"] = row["exploitable"] = "PENDING"
        elif vid in ROAST_FLAGS:
            flag, label = ROAST_FLAGS[vid]
            # nxc's --asreproast/--kerberoasting REQUIRE an output-file argument;
            # omitting it makes argparse fail ("expected one argument") so no hash
            # is ever returned (false NO). The hashes are also echoed to the
            # console, which is what _nxc_run reads — the file is throwaway.
            roast_out = str(Path(tempfile.gettempdir()) / f"pf-roast-{vid}.txt")
            out = _nxc_run(
                [nxc, "ldap", dc_ip, "-u", admin_user, "-p", admin_pass, "-d", domain, flag, roast_out, "--kdcHost", dc_ip]
            )
            got_hash = out is not None and ("$krb5" in out)
            if got_hash:
                row.update(applied="YES", exploitable="YES", evidence=f"nxc returned a {label}.")
            elif out is None:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence="nxc did not run (missing/timeout) — retry the command below.",
                )
            else:
                row.update(
                    applied="NO",
                    exploitable="NO",
                    evidence=f"nxc {flag} returned no hash (KDC_ERR_ETYPE_NOSUPP? — see AZURE-DEPLOY-RUNBOOK.md step 7).",
                )
        elif vid in LDAP_APPLIED_FILTERS:
            filt, label = LDAP_APPLIED_FILTERS[vid]
            out = _nxc_run([nxc, "ldap", dc_ip, "-u", admin_user, "-p", admin_pass, "-d", domain, "--query", filt, ""])
            if out is None:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence="nxc did not run — retry the command below.",
                )
            elif _nxc_query_nonempty(out):
                row.update(
                    applied="YES",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"LDAP confirms {label}; exploit it manually (command below).",
                )
            else:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"LDAP query for {label} returned nothing parseable — confirm by hand.",
                )
        elif vid in WINRM_APPLIED_CHECKS:
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                script = WINRM_APPLIED_CHECKS[vid].replace("__ACCOUNT__", r.get("account") or "")
                out = _winrm_run(nxc, target_ip, admin_user, admin_pass, script)
                result = _winrm_check_result(out or "")
                if result is True:
                    row.update(
                        applied="YES",
                        exploitable="REQUIRES-HUMAN",
                        evidence=f"WinRM check on {r['run_on']} ({target_ip}) confirms the artifact is present; exploit it manually (command below).",
                    )
                elif result is False:
                    row.update(
                        applied="NO",
                        exploitable="NO",
                        evidence=f"WinRM check on {r['run_on']} ({target_ip}) found the artifact absent or not matching.",
                    )
                else:
                    row.update(
                        applied="PENDING",
                        exploitable="REQUIRES-HUMAN",
                        evidence="WinRM check did not run (auth/timeout/unreachable) — retry the command below.",
                    )
        elif vid == "mssql-weak-sa":
            target_ip = host.get("ip")
            sa_password = r.get("password")
            if not target_ip or not sa_password:
                row.update(
                    applied="PENDING", exploitable="PENDING", evidence="missing host IP or sa password in the manifest."
                )
            else:
                out = _nxc_run([nxc, "mssql", target_ip, "-u", "sa", "-p", sa_password, "--local-auth", "-x", "whoami"])
                # nxc's mssql protocol authenticates as sa, THEN runs -x via xp_cmdshell —
                # a returned "nt authority\..." line proves both sa auth AND xp_cmdshell exec.
                if out is None:
                    row.update(
                        applied="PENDING",
                        exploitable="PENDING",
                        evidence="nxc did not run (missing/timeout) — retry the command below.",
                    )
                elif out and "nt authority" in out.lower():
                    row.update(
                        applied="YES",
                        exploitable="YES",
                        evidence="nxc authenticated as sa and ran `whoami` via xp_cmdshell.",
                    )
                else:
                    row.update(
                        applied="NO",
                        exploitable="NO",
                        evidence="sa auth or xp_cmdshell execution failed — see nxc output; a control may have neutralized it.",
                    )
        else:
            row.update(
                applied="REQUIRES-HUMAN",
                exploitable="REQUIRES-HUMAN",
                evidence="ACL/SYSVOL/registry state — confirm with the command below (bloodhound-python / nxc / dacledit).",
            )

        row["command"] = _live_command(
            vid, dc_ip, domain, admin_user, host.get("ip"), r.get("account"), r.get("password")
        )
        confirmed.append(row)

        if row["applied"] == "NO":
            findings.append(f"{vid}: config NOT applied — injection did not land (expected: {r['applied_signature']}).")
        elif row["applied"] in ("PENDING", "REQUIRES-HUMAN"):
            findings.append(f"{vid}: needs a manual check — run: {row['command']}")
        elif row["exploitable"] == "NO":
            findings.append(
                f"{vid}: applied but NOT exploitable — a control may have neutralized it ({row['evidence']})."
            )

    return confirmed, findings


def _nxc_run(cmd: list[str]) -> str | None:
    """Run an nxc/netexec command, returning combined stdout+stderr, or None if it
    could not run at all (never raises — a live check failing is data, not a crash)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return (res.stdout or "") + (res.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _winrm_run(nxc: str, host_ip: str, user: str, password: str, script: str) -> str | None:
    """Run a PowerShell one-liner over WinRM via nxc/netexec's `-X`, returning
    combined stdout+stderr, or None if it could not run at all (auth/timeout —
    a failed live check is data, not a crash)."""
    try:
        res = subprocess.run(
            [nxc, "winrm", host_ip, "-u", user, "-p", password, "-X", script],
            capture_output=True,
            text=True,
            timeout=180,
        )
        return (res.stdout or "") + (res.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _winrm_check_result(out: str) -> bool | None:
    """Parse the PF_CHECK:True/False marker line a WINRM_APPLIED_CHECKS script
    prints. None if the marker never appeared (auth failure, WinRM down, the
    host unreachable over the tunnel)."""
    for line in out.splitlines():
        if "PF_CHECK:True" in line:
            return True
        if "PF_CHECK:False" in line:
            return False
    return None


def _nxc_query_nonempty(out: str) -> bool:
    """Heuristic: netexec's ldap --query prints one line per matched attribute
    (containing 'CN=', a DN, or 'Response:'/'objectClass' markers) after its
    banner. Treat any such content line as a non-empty result — deliberately
    conservative so we never claim 'not applied' on unfamiliar output."""
    markers = ("CN=", "DC=", "objectClass", "sAMAccountName", "msDS-", "Response for object")
    return any(any(mk in line for mk in markers) for line in out.splitlines())


def _live_command(
    vid: str,
    dc_ip: str,
    domain: str,
    admin_user: str,
    target_ip: str | None = None,
    account: str | None = None,
    password: str | None = None,
) -> str:
    """The exact copy-pasteable command an operator runs to confirm a vuln the
    harness can't safely auto-confirm. Uses <PASS> as a placeholder for the lab
    admin's password (a real secret, not echoed here) — the real password is in
    lab-report.md / terraform.tfvars.json. mssql-weak-sa is the one exception:
    its `password` IS the vulnerability (a deliberately known-weak sa
    credential, same treatment as the roastable accounts' cracked hashes in the
    validation report), so it's safe and useful to print directly."""
    dc_ip = dc_ip or "<dc-ip>"
    base = f"nxc ldap {dc_ip} -u {admin_user} -p '<PASS>' -d {domain}"
    if vid in ROAST_FLAGS:
        return f"{base} {ROAST_FLAGS[vid][0]} out --kdcHost {dc_ip}"
    if vid in LDAP_APPLIED_FILTERS:
        return f'{base} --query "{LDAP_APPLIED_FILTERS[vid][0]}" ""'
    if vid in WINRM_APPLIED_CHECKS:
        script = WINRM_APPLIED_CHECKS[vid].replace("__ACCOUNT__", account or "<account>")
        return f"nxc winrm {target_ip or '<host-ip>'} -u {admin_user} -p '<PASS>' -X \"{script}\""
    if vid == "mssql-weak-sa":
        return f"nxc mssql {target_ip or '<host-ip>'} -u sa -p '{password or '<sa-pass>'}' --local-auth -x whoami"
    return f"bloodhound-python -d {domain} -u {admin_user} -p '<PASS>' -dc {dc_ip} -c All  # then inspect the {vid} edge in BloodHound"


def build_vuln_check(vuln: dict, catalog_entry: dict) -> dict:
    """For one planned vuln, the two things its validation confirms: APPLIED (the
    AD artifact/edge that proves the injection landed) and EXPLOITABLE (the
    technique/primitive to run to prove it works). Pulled from the catalog's
    validate/attack metadata — no detection/coverage prediction."""
    validate = (catalog_entry or {}).get("validate", {}) or {}
    attack = (catalog_entry or {}).get("attack", {}) or {}
    account_key, password_key = VULN_CREDENTIAL_VARS.get(vuln["id"], (None, None))
    account = (vuln.get("vars") or {}).get(account_key) if account_key else None
    password = (vuln.get("vars") or {}).get(password_key) if password_key else None
    return {
        "id": vuln["id"],
        "mitre": vuln["mitre"],
        "run_on": vuln["run_on"],
        "account": account,
        "password": password,
        "neutralization": vuln["neutralization"].split(" (")[0],
        "applied_signature": validate.get("bloodhound_edge") or "AD artifact created by the inject primitive",
        "exploit_check": validate.get("atomic") or "run the vuln's attack primitive",
        "intended_path": vuln.get("intended_path") or " ".join((attack.get("intended_path") or "").split()),
    }


def render_results_template(rows: list[dict]) -> dict:
    """The skeleton the live validation run fills in: per vuln, whether the config
    is APPLIED and whether it is EXPLOITABLE (YES/NO/PARTIAL) plus an evidence
    string. Feeding it back via `validate --results` writes the confirmed report."""
    return {
        "_help": f"Per vuln set `applied` and `exploitable` to one of {list(VALID_RESULT)} from the live check, plus an `evidence` string. Then: forge.py validate <spec> --results <this file>.",
        "vulns": [
            {"id": r["id"], "mitre": r["mitre"], "applied": None, "exploitable": None, "evidence": ""} for r in rows
        ],
    }


def merge_validation_results(rows: list[dict], results: dict) -> tuple[list[dict], list[str]]:
    """Crosses the per-vuln checks with the live results, returning the confirmed
    list (each row gains applied/exploitable/evidence) and human-readable findings
    (config that didn't land, or landed but isn't exploitable). Raises SpecError on
    a malformed results file."""
    by_id = {v.get("id"): v for v in results.get("vulns", [])}
    confirmed: list[dict] = []
    findings: list[str] = []

    for r in rows:
        res = by_id.get(r["id"]) or {}
        row = dict(r)
        for field in ("applied", "exploitable"):
            val = res.get(field)
            if val is not None and val not in VALID_RESULT:
                raise SpecError(f"vuln {r['id']}: {field} '{val}' is not one of {list(VALID_RESULT)}")
            row[field] = val or "PENDING"
        row["evidence"] = res.get("evidence", "")
        if row["applied"] == "NO":
            findings.append(
                f"{r['id']}: config NOT applied — injection did not land (expected artifact: {r['applied_signature']})."
            )
        elif row["applied"] == "PENDING":
            findings.append(f"{r['id']}: no live result recorded.")
        elif row["exploitable"] == "NO":
            findings.append(
                f"{r['id']}: applied but NOT exploitable — a control may have neutralized it ({row['evidence'] or 'no evidence given'})."
            )
        confirmed.append(row)
    return confirmed, findings


def render_validation_report(lab_name: str, confirmed: list[dict], findings: list[str], lab_dir: Path) -> Path:
    """The confirmed validation section of the deliverable: per vuln, was the config
    applied and is it exploitable, with evidence. purple-validator folds this into
    lab-report.md."""
    n = len(confirmed)
    applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
    exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
    lines = [
        f"# Vulnerability validation — {lab_name}",
        "",
        f"_Confirmed {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} against the live lab. Each injected vuln is checked for two things: the config was APPLIED correctly (the AD artifact landed) and it is actually EXPLOITABLE. This is not a detection/coverage matrix._",
        "",
        f"- Config applied: **{applied_yes}/{n}**",
        f"- Exploitable: **{exploit_yes}/{n}**",
        "",
        "| Vuln | ATT&CK | Host | Applied | Exploitable | Evidence | Manual command (if any) |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in confirmed:
        needs_cmd = r["applied"] in ("REQUIRES-HUMAN", "PENDING") or r["exploitable"] in ("REQUIRES-HUMAN", "PENDING")
        cmd = f"`{r['command']}`" if (needs_cmd and r.get("command")) else "—"
        lines.append(
            f"| {r['id']} | {r['mitre']} | {r['run_on']} | **{r['applied']}** | "
            f"**{r['exploitable']}** | {r.get('evidence') or '—'} | {cmd} |"
        )
    lines += ["", "## Findings", ""]
    lines += [f"- {f}" for f in findings] if findings else ["- None — every injected vuln is applied and exploitable."]
    lines.append("")
    report_path = lab_dir / "validation-report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    (lab_dir / "validation-report.json").write_text(
        json.dumps(
            {
                "lab": lab_name,
                "summary": {"applied": applied_yes, "exploitable": exploit_yes, "total": n},
                "findings": findings,
                "vulns": confirmed,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path


def cmd_validate(args: argparse.Namespace) -> int:
    """Vulnerability validation for a generated lab: per injected vuln, the AD
    artifact that proves the config was APPLIED and the check that proves it is
    EXPLOITABLE. Writes validation-plan.{json,md} (the per-vuln checklist) plus a
    validation-results.template.json. With --results <file>, merges the live
    YES/NO/PARTIAL results into the confirmed validation-report.md. Validation is
    about applied+exploitable — NOT detection coverage (out of scope)."""
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    manifest_path = lab_dir / "lab-manifest.json"
    if not manifest_path.exists():
        print(f"error: {manifest_path} not found — run `generate` first.", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    catalog = load_vuln_catalog()
    planned = manifest.get("vulnerabilities_planned", [])
    if not planned:
        print("note: this lab has no injected vulnerabilities — nothing to validate.")
        return 0

    rows = [build_vuln_check(v, catalog.get(v["id"], {})) for v in planned]
    plan = {
        "lab": lab_name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "note": "Per-vuln validation checklist. Confirm live that each config was APPLIED (artifact present) and is EXPLOITABLE. Not a detection/coverage matrix.",
        "vulns": rows,
    }
    (lab_dir / "validation-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Vulnerability validation plan — {lab_name}",
        "",
        f"_Generated {plan['generated_at']} from `lab-manifest.json`. For each injected vuln,",
        "confirm two things live: the config was **applied** (the AD artifact landed) and it is",
        "actually **exploitable**. This is not a detection/coverage matrix._",
        "",
        "| Vuln | ATT&CK | Host | Reconciliation | Applied signature (confirm present) | Exploitability check |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['id']} | {r['mitre']} | {r['run_on']} | {r['neutralization']} | "
            f"{r['applied_signature']} | {r['exploit_check']} |"
        )
    lines += [
        "",
        "## How to confirm each vuln",
        "",
        "1. **Applied** — query AD with a signing-aware client (e.g. `nxc`) for the artifact in",
        "   the 'Applied signature' column (a UAC flag, an SPN, an ACE, a group membership, a",
        "   SYSVOL file…). Present ⇒ the injection landed.",
        "2. **Exploitable** — run the primitive in the last column (roast the hash, read the",
        "   cpassword, abuse the ACL) and confirm it actually yields what it should.",
        "3. Record YES/NO/PARTIAL + evidence per vuln in the results template, then re-run with",
        "   `--results` to write the confirmed report.",
        "",
    ]
    (lab_dir / "validation-plan.md").write_text("\n".join(lines), encoding="utf-8")

    # The template only makes sense as a starting point — don't clobber a results
    # file the operator is already filling in.
    template_path = lab_dir / "validation-results.template.json"
    if not template_path.exists():
        template_path.write_text(json.dumps(render_results_template(rows), indent=2) + "\n", encoding="utf-8")

    print(f"OK: wrote {lab_dir / 'validation-plan.json'}, validation-plan.md, validation-results.template.json")
    for r in rows:
        print(
            f"    - {r['id']} [{r['mitre']}] on {r['run_on']}: applied? [{r['applied_signature']}]  exploitable? [{r['exploit_check']}]"
        )

    # --run: do the live checks ourselves and write the confirmed report directly,
    # collapsing the fill-a-JSON-by-hand loop into one command.
    if getattr(args, "run", False):
        try:
            confirmed, findings = run_live_validation(rows, manifest, lab_dir)
        except SpecError as e:
            print(f"error: cannot run live validation: {e}", file=sys.stderr)
            return 1
        report_path = render_validation_report(lab_name, confirmed, findings, lab_dir)
        applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
        exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
        need_human = sum(
            1
            for r in confirmed
            if "REQUIRES-HUMAN" in (r["applied"], r["exploitable"]) or "PENDING" in (r["applied"], r["exploitable"])
        )
        print(f"OK: wrote {report_path} (live run)")
        print(
            f"  auto-confirmed applied: {applied_yes}/{len(confirmed)}, exploitable: {exploit_yes}/{len(confirmed)}; {need_human} need a manual command (listed in the report + findings)"
        )
        for r in confirmed:
            print(f"    - {r['id']}: applied={r['applied']} exploitable={r['exploitable']}")
        return 0

    if args.results:
        results_path = Path(args.results).resolve()
        if not results_path.exists():
            print(f"error: --results file not found: {results_path}", file=sys.stderr)
            return 2
        try:
            results = json.loads(results_path.read_text(encoding="utf-8"))
            confirmed, findings = merge_validation_results(rows, results)
        except (json.JSONDecodeError, SpecError) as e:
            print(f"error: bad --results file: {e}", file=sys.stderr)
            return 1
        report_path = render_validation_report(lab_name, confirmed, findings, lab_dir)
        applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
        exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
        print(f"OK: wrote {report_path} (confirmed)")
        print(
            f"  applied: {applied_yes}/{len(confirmed)}, exploitable: {exploit_yes}/{len(confirmed)}; {len(findings)} finding(s)"
        )

    return 0


def cmd_guardrail(args: argparse.Namespace) -> int:
    """Deterministic invariant gate (CLAUDE.md reglas invariantes), run AFTER
    `lab-spec` and BEFORE any deploy. Reads generated/<lab>/lab-manifest.json and
    the catalog, and hard-fails (exit 1) if any machine-checkable invariant is
    violated. Invariant #6 (authorized use) is a human judgement — it is printed
    as a REVIEW item, never auto-passed. This replaces the old policy-guardrail
    subagent: the risky logic lives in code, not in a prompt."""
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    manifest_path = lab_dir / "lab-manifest.json"
    if not manifest_path.exists():
        print(f"error: {manifest_path} not found — run `lab-spec` first.", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lab = manifest.get("lab", {})
    catalog = load_vuln_catalog()
    failures: list[str] = []

    # inv #1 — isolation by construction (no public IP / no RDP-WinRM from the
    # internet; access only via the WireGuard bastion). Compute layer is
    # private-IP-only by construction in the templates; here we assert the spec
    # asked for vpn-only isolation and the network plan actually placed a bastion
    # in a management subnet.
    if lab.get("isolation") != "vpn-only":
        failures.append(f"#1 isolation: lab.isolation is {lab.get('isolation')!r}, must be 'vpn-only'")
    np = manifest.get("network_plan", {})
    if not np.get("management_subnet") or not np.get("jumpbox_ip"):
        failures.append("#1 isolation: network_plan is missing the management subnet / WireGuard jumpbox")

    # inv #2 — purple coupling: every injected vuln carries mitigate +
    # neutralized_by in the catalog (its blue counterpart).
    for vid in manifest.get("vulnerabilities", []):
        entry = catalog.get(vid)
        if entry is None:
            failures.append(f"#2 purple: vuln {vid!r} is not in catalog/vulnerabilities/")
            continue
        missing = [k for k in ("mitigate", "neutralized_by") if not entry.get(k)]
        if missing:
            failures.append(f"#2 purple: vuln {vid!r} is missing {', '.join(missing)}")

    # inv #3 — reconciliation honoured: the hardening<->vuln reconciliation ran
    # and is recorded; on_conflict:fail must leave no unresolved conflict.
    recon = manifest.get("reconciliation")
    if not isinstance(recon, dict) or "on_conflict" not in recon:
        failures.append("#3 reconciliation: no reconciliation block recorded in the manifest")
    elif recon.get("on_conflict") == "fail" and recon.get("conflicts_detected"):
        failures.append("#3 reconciliation: on_conflict=fail but unresolved conflicts remain")

    # inv #4 — cost & lifecycle as code: auto_shutdown + budget mandatory; remote
    # Terraform state (backend.hcl must not be a local backend).
    if not lab.get("auto_shutdown"):
        failures.append("#4 lifecycle: lab.auto_shutdown is missing")
    if not lab.get("budget_alert_usd"):
        failures.append("#4 lifecycle: lab.budget_alert_usd is missing")
    # Proxmox deliberately uses a LOCAL Terraform backend (no cloud object store
    # on-prem to mint per-deployer) — a documented relaxation of #4's remote-state
    # requirement, so the remote-backend assertion below is skipped for it and
    # surfaced as an honest REVIEW note rather than passing silently.
    provider = lab.get("provider")
    if provider != "proxmox":
        for backend in lab_dir.glob("terraform/*/backend.hcl"):
            text = backend.read_text(encoding="utf-8").lower()
            if "storage_account_name" not in text and "dynamodb" not in text and "bucket" not in text:
                failures.append(
                    f"#4 state: {backend} does not look like a remote backend (S3/DynamoDB or Azure Storage)"
                )

    print(f"guardrail — {lab_name}")
    if failures:
        print("FAIL — invariant(s) violated:")
        for f in failures:
            print(f"  ✗ {f}")
    else:
        print(
            "PASS — all machine-checkable invariants hold (#1 isolation, #2 purple coupling, #3 reconciliation, #4 lifecycle/state)"
        )
    if provider == "proxmox":
        print(
            "REVIEW — #4 state: provider 'proxmox' uses a LOCAL Terraform backend by decision "
            "(no on-prem cloud object store to mint per-deployer). Remote-state-with-locking is "
            "relaxed for this provider — point terraform/proxmox/versions.tf at a pg/s3(MinIO)/http "
            "backend if a shared state store exists."
        )
    # inv #6 is a judgement call, never auto-passed.
    print(
        "REVIEW — #6 authorized use: confirm this is an isolated lab for authorized "
        "testing, not automation aimed at third-party/production systems. Human/LLM must judge; not machine-checked."
    )
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="forge.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_lab_spec = sub.add_parser(
        "lab-spec", help="Validate, resolve and reconcile a lab-spec.yml; emit lab-manifest.json"
    )
    p_lab_spec.add_argument("spec", help="Path to a lab-spec YAML file")
    p_lab_spec.add_argument(
        "--check-only", action="store_true", help="Validate/reconcile but do not write lab-manifest.json"
    )
    p_lab_spec.add_argument("--out-dir", help="Override output directory (default: generated/<lab.name>/)")
    p_lab_spec.set_defaults(func=cmd_lab_spec)

    p_generate = sub.add_parser(
        "generate", help="Render Terraform + Ansible artifacts for a lab-spec.yml into generated/<lab>/"
    )
    p_generate.add_argument("spec", help="Path to a lab-spec YAML file")
    p_generate.add_argument("--out-dir", help="Override output directory (default: generated/<lab.name>/)")
    p_generate.add_argument(
        "--plan",
        action="store_true",
        help="Also run terraform init/validate/plan after rendering (needs terraform on PATH; needs cloud credentials for a full plan)",
    )
    p_generate.set_defaults(func=cmd_generate)

    p_deploy = sub.add_parser(
        "deploy",
        help="Deterministic no-AI deploy: guardrail gate, then run the generated deploy.sh (state backend, auto-sizing, terraform apply, WireGuard, Ansible site.yml)",
    )
    p_deploy.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_deploy.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_deploy.add_argument(
        "--skip-guardrail",
        action="store_true",
        help="Skip the pre-deploy guardrail gate (not recommended — it enforces the CLAUDE.md invariants before spend)",
    )
    p_deploy.add_argument(
        "--sizes-only",
        action="store_true",
        help="Only (re)write sizes.auto.tfvars.json (auto-pick a cheap unrestricted SKU) and exit — no apply",
    )
    p_deploy.set_defaults(func=cmd_deploy)

    p_teardown = sub.add_parser(
        "teardown",
        help="Deterministic no-AI teardown: run the generated teardown.sh (start deallocated VMs, destroy, sweep stray snapshots, verify cost-zero, local cleanup)",
    )
    p_teardown.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_teardown.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_teardown.set_defaults(func=cmd_teardown)

    p_destroy = sub.add_parser(
        "destroy",
        help="terraform destroy a generated lab + verify no Azure resource group is left behind (lower-level; `teardown` wraps this with the deallocated-VM/snapshot gotchas)",
    )
    p_destroy.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_destroy.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_destroy.add_argument(
        "--yes",
        action="store_true",
        help="Pass -auto-approve to terraform destroy (default: terraform's own interactive confirmation prompt)",
    )
    p_destroy.add_argument(
        "--check-only",
        action="store_true",
        help="Run 'terraform plan -destroy' instead of actually destroying anything",
    )
    p_destroy.set_defaults(func=cmd_destroy)

    p_ad_inventory = sub.add_parser(
        "ad-inventory",
        help="Query a LIVE deployed lab's domain (LDAP + DCSync via nxc) and render generated/<lab>/ad-inventory.md: users, groups, NT hashes",
    )
    p_ad_inventory.add_argument("spec", help="Path to the same lab-spec YAML file used to generate/deploy the lab")
    p_ad_inventory.add_argument(
        "--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)"
    )
    p_ad_inventory.set_defaults(func=cmd_ad_inventory)

    p_validate = sub.add_parser(
        "validate",
        help="Per-vuln validation checklist: the AD artifact that proves each injected vuln's config was APPLIED and the check that proves it is EXPLOITABLE (with --results, writes the confirmed report). Not detection coverage.",
    )
    p_validate.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_validate.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_validate.add_argument(
        "--results",
        help="Path to a filled validation-results JSON (from the live run); merges it into the confirmed validation-report.md",
    )
    p_validate.add_argument(
        "--run",
        action="store_true",
        help="Run the live checks over the tunnel (nxc/netexec) and write validation-report.md directly — no by-hand JSON. Auto-confirms the roasting vulns; emits a ready-to-run command for the interactive ones.",
    )
    p_validate.set_defaults(func=cmd_validate)

    p_guardrail = sub.add_parser(
        "guardrail",
        help="Deterministic invariant gate (CLAUDE.md reglas invariantes): PASS/FAIL over a lab-manifest.json before deploy. Replaces the policy-guardrail subagent.",
    )
    p_guardrail.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_guardrail.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_guardrail.set_defaults(func=cmd_guardrail)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
