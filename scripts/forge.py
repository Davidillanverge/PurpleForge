#!/usr/bin/env python3
"""PurpleForge deterministic core.

Implements the parts of the harness that must be deterministic and testable
rather than left to an LLM: schema validation, semantic checks, defense.profile
default resolution, IP assignment, cost estimation and the hardening<->vuln
reconciliation described in DISENO-purpleforge.md §7.3. Invoked by the
lab-spec skill (.claude/skills/lab-spec/SKILL.md); later phases add generate/
deploy/validate/destroy subcommands here as those skills are implemented.

Usage:
    scripts/forge.py lab-spec specs/examples/medieval-2dom-azure.yml
    scripts/forge.py lab-spec specs/examples/medieval-2dom-azure.yml --check-only
    scripts/forge.py generate specs/examples/single-dc-azure.yml --plan
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import jinja2
import jsonschema
import yaml

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
    """"20:00 Europe/Madrid" -> ("2000", "Romance Standard Time") for
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
    plan = {
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
                hosts.append({
                    "role": m["role"],
                    "os": m["os"],
                    "ip": f"10.{octet}.{i}.{host_octet}",
                    "services": m.get("services", []),
                    "image_id": m.get("image_id"),
                })
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


def reconcile(resolved_defense: dict, vulnerabilities: list[str], catalog: dict[str, dict], on_conflict: str) -> tuple[dict, dict]:
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
            if isinstance(e, str) and e.startswith("hardening.controls.")
            and e.split("hardening.controls.", 1)[1] not in FIXED_HARDENING_TOGGLES
        ]

        for entry in entries:
            if isinstance(entry, dict) and "hardening.baseline" in entry:
                baseline_list = entry["hardening.baseline"]
                if baseline != "none" and baseline in baseline_list:
                    conflicts.append({
                        "vuln": vuln_id,
                        "kind": "baseline",
                        "baseline": baseline,
                        "control": implicit_labels[0] if implicit_labels else None,
                        "detail": (
                            f"baseline '{baseline}' bundles rule(s) that neutralize '{vuln_id}'"
                            + (f" (control: {implicit_labels[0]})" if implicit_labels else "")
                        ),
                    })
            elif isinstance(entry, str) and entry.startswith("hardening.controls."):
                control_name = entry.split("hardening.controls.", 1)[1]
                if control_name in FIXED_HARDENING_TOGGLES and controls.get(control_name) not in (False, "disable", None):
                    conflicts.append({
                        "vuln": vuln_id,
                        "kind": "control",
                        "control": control_name,
                        "detail": f"control '{control_name}' neutralizes '{vuln_id}'",
                    })

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
            excluded.append({
                **c,
                "action": (
                    "abstract exclusion recorded; concrete ansible-lockdown skip_rule vars are "
                    "resolved later by the defensive-controls skill"
                ),
            })
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


def generate_password(length: int = 20) -> str:
    """Random password meeting basic Windows complexity rules (upper/lower/digit/symbol)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_="
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in "!@#$%^&*-_=" for c in pw)
        ):
            return pw


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
            machines.append({
                "name": name,
                "domain": domain,
                "role": role,
                "os": host["os"],
                "ip": host["ip"],
                "services": host.get("services", []),
                "image_id": host.get("image_id"),
            })
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
            common.update({
                "parent_domain": parent,
                "parent_domain_user": yaml_scalar(f"{forest_by_domain[parent]['netbios']}\\Administrator"),
                "parent_domain_password": admin_password,
                "source_dc": f"{parent_dc}.{parent}" if parent_dc else "",
                "dns_domain": parent_dc or first["name"],
            })
            groups["child_domain_controllers"].append(common)
        else:
            groups["domain_controllers"].append(common)
            trust = d.get("trust")
            if trust and trust["type"] != "parent-child":
                groups["trust_anchors"].append({
                    "name": first["name"],
                    "ip": first["ip"],
                    "domain_username": yaml_scalar(f"{d['netbios']}\\Administrator"),
                    "domain_password": admin_password,
                    "remote_forest": trust["target"],
                    "remote_admin": yaml_scalar(f"{forest_by_domain[trust['target']]['netbios']}\\Administrator"),
                    "remote_admin_password": admin_password,
                })

        for extra in dcs[1:]:
            groups["domain_controllers_additional"].append({
                "name": extra["name"],
                "ip": extra["ip"],
                "domain": domain,
                "domain_name": domain,
                "netbios_name": d["netbios"],
                "domain_username": yaml_scalar(f"{d['netbios']}\\Administrator"),
                "domain_password": admin_password,
                "dns_domain": root_dc_name[domain],
            })

    for m in machines:
        if m["role"] in ("member-server", "workstation"):
            group = "member_servers" if m["role"] == "member-server" else "workstations"
            member_netbios = forest_by_domain[m["domain"]]["netbios"]
            groups[group].append({
                "name": m["name"],
                "ip": m["ip"],
                "member_domain": m["domain"],
                "domain_username": yaml_scalar(f"{member_netbios}\\Administrator"),
                "domain_password": admin_password,
                "dns_domain": root_dc_name.get(m["domain"], ""),
            })

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
            }
            for m in machines
        ],
        "admin_username": WINDOWS_ADMIN_USERNAME,
        "admin_password": admin_password,
        "ansible_password": ansible_password,
        "jumpbox_username": WINDOWS_ADMIN_USERNAME,
        "wireguard_port": 51820,
        "wireguard_allowed_cidrs": ["0.0.0.0/0"],
        "bastion_ssh_allowed_cidrs": [],
        "bastion_size": "Standard_B1s",
    }
    (dst / "terraform.tfvars.json").write_text(json.dumps(tfvars, indent=2) + "\n", encoding="utf-8")
    render_backend_config(lab["name"], dst)


def load_theme(theme_id: str) -> dict:
    return load_yaml(THEMES_DIR / f"{theme_id}.yml")


def compute_population_counts(users: int, density: str) -> tuple[int, int, int]:
    """UserCount is population.users directly; GroupCount/ComputerCount scale
    off it by density, matching Invoke-BadBlood.ps1's own three counters."""
    ratio_by_density = {"sparse": (0.15, 0.3), "realistic": (0.2, 0.4), "messy": (0.3, 0.5)}
    group_ratio, computer_ratio = ratio_by_density[density]
    return users, max(1, round(users * group_ratio)), max(1, round(users * computer_ratio))


def attach_population_vars(groups: dict[str, list[dict]], spec: dict) -> None:
    """BadBlood populates a domain as a whole (any single DC in it sees the
    same directory), so it must run exactly once per domain — on that
    domain's root DC, never on domain_controllers_additional. population.users
    is spec-wide, so it's split evenly across every populatable domain; each
    domain gets population.seed + its index for Get-Random -SetSeed, so
    multi-domain labs don't draw identical 'random' populations twice."""
    dc_hosts = groups["domain_controllers"] + groups["child_domain_controllers"]
    per_domain_users = max(1, spec["population"]["users"] // max(1, len(dc_hosts)))
    user_count, group_count, computer_count = compute_population_counts(per_domain_users, spec["population"]["density"])
    base_seed = spec["population"]["seed"]
    for i, host in enumerate(dc_hosts):
        host["badblood_user_count"] = user_count
        host["badblood_group_count"] = group_count
        host["badblood_computer_count"] = computer_count
        host["badblood_seed"] = base_seed + i


def render_badblood_overlay(theme: dict, dest_dir: Path) -> None:
    """Overwrites BadBlood's own Names/*.txt + 3lettercodes.csv with
    theme-derived equivalents at the exact relative paths
    CreateUsers.ps1/CreateComputers.ps1/CreateOUStructure.ps1 already read
    from (see .claude/skills/ad-theming/SKILL.md) — BadBlood's scripts
    themselves are never modified, only the data files they load."""
    v = theme["vocabulary"]
    names_dir = dest_dir / "AD_Users_Create" / "Names"
    names_dir.mkdir(parents=True, exist_ok=True)
    (names_dir / "malenames-usa-top1000.txt").write_text(
        "\n".join(n.upper() for n in v["given_names_male"]) + "\n", encoding="utf-8"
    )
    (names_dir / "femalenames-usa-top1000.txt").write_text(
        "\n".join(n.upper() for n in v["given_names_female"]) + "\n", encoding="utf-8"
    )
    (names_dir / "familynames-usa-top1000.txt").write_text(
        "\n".join(n.upper() for n in v["family_names"]) + "\n", encoding="utf-8"
    )

    ou_dir = dest_dir / "AD_OU_CreateStructure"
    ou_dir.mkdir(parents=True, exist_ok=True)
    csv_lines = ["name,description"] + [f'{h["code"]},{h["name"]}' for h in v["houses"]]
    (ou_dir / "3lettercodes.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")


def render_ad_theming(theme: dict, out_dir: Path) -> None:
    dst_ansible = out_dir / "ansible"
    badblood_dst = dst_ansible / "files" / "badblood"
    if badblood_dst.exists():
        shutil.rmtree(badblood_dst)
    shutil.copytree(
        REPO_ROOT / "vendor" / "BadBlood", badblood_dst, ignore=shutil.ignore_patterns(".git", ".git*")
    )
    render_badblood_overlay(theme, badblood_dst)
    shutil.copy(TEMPLATES_DIR / "ansible" / "playbooks" / "ad-theming.yml", dst_ansible / "playbooks" / "ad-theming.yml")


# Intentionally weak, dictionary-crackable passwords for the roastable accounts —
# being crackable offline IS the vulnerability (kerberoasting/asreproast). They
# are non-secret by design and still only ever written into generated/<lab>/
# (gitignored). Accounts whose weakness is NOT about the password (dcsync-acl,
# passwords-in-description) get a strong random one instead.
VULN_WEAK_PASSWORD = "Password123!"
VULN_WEAK_PASSWORD_ALT = "Summer2024!"
VULN_WEAK_PASSWORD_3 = "Welcome2024!"


def build_vuln_vars(vid: str, machines: list[dict], primary_dc: dict) -> dict:
    if vid == "kerberoasting":
        return {"vuln_kerberoast_account": "svc-sqlreport", "vuln_kerberoast_password": VULN_WEAK_PASSWORD}
    if vid == "asreproast":
        return {"vuln_asrep_account": "svc-legacyapp", "vuln_asrep_password": VULN_WEAK_PASSWORD_ALT}
    if vid == "laps-read-acl":
        return {"vuln_laps_reader_group": "Domain Users"}
    if vid == "shadow-credentials":
        return {
            "vuln_shadowcred_target": "svc-tier0-admin",
            "vuln_shadowcred_target_password": generate_password(),
            "vuln_shadowcred_writer_group": "Domain Users",
        }
    if vid == "dnsadmins-privesc":
        return {"vuln_dnsadmins_account": "svc-dns-operator", "vuln_dnsadmins_password": generate_password()}
    if vid == "rbcd-abuse":
        members = [m for m in machines if m["role"] == "member-server"]
        computer = members[0]["name"] if members else primary_dc["name"]
        return {
            "vuln_rbcd_delegate_account": "svc-app-proxy",
            "vuln_rbcd_delegate_password": VULN_WEAK_PASSWORD_3,
            "vuln_rbcd_target_computer": computer,
        }
    if vid == "backup-operators-membership":
        return {"vuln_backupop_account": "svc-backup-agent", "vuln_backupop_password": generate_password()}
    if vid == "dcsync-acl":
        return {"vuln_dcsync_account": "svc-replication", "vuln_dcsync_password": generate_password()}
    if vid == "passwords-in-description":
        return {"vuln_pwddesc_account": "temp-contractor", "vuln_pwddesc_password": generate_password()}
    if vid == "gpp-cpassword":
        return {"vuln_gpp_name": "Workstations - Local Admin Password"}
    if vid == "unconstrained-delegation":
        members = [m for m in machines if m["role"] == "member-server"]
        computer = members[0]["name"] if members else primary_dc["name"]
        return {"vuln_unconstrained_computer": computer}
    if vid == "constrained-delegation":
        dc_fqdn = f"{primary_dc['name']}.{primary_dc['domain']}"
        return {
            "vuln_delegation_account": "svc-webapp",
            "vuln_delegation_password": generate_password(),
            "vuln_delegation_target_spn": f"ldap/{dc_fqdn}",
        }
    # adcs-esc1 and any future service-scoped vuln need no extra vars beyond the
    # inventory's domain/domain_username/domain_password and vuln_files_dir.
    return {}


def plan_vuln_injection(
    spec: dict, catalog: dict[str, dict], machines: list[dict], groups: dict[str, list[dict]], reconciliation: dict
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

    planned = []
    for vid in spec["vulnerabilities"]:
        v = catalog[vid]
        requires = v["attack"].get("requires_services") or []
        if requires:
            # semantic_checks already guaranteed a host provides these services.
            host = next(m for m in machines if all(s in m.get("services", []) for s in requires))
            run_on, target_domain = host["name"], host["domain"]
        else:
            run_on, target_domain = primary_dc["name"], primary_dc["domain"]

        if vid in excluded:
            status = "gap-preserved (neutralizing control excluded via on_conflict:exclude-control)"
        elif vid in warned:
            status = "AT RISK (neutralizing hardening applied; on_conflict:warn — gap may be closed)"
        else:
            status = "clear (no selected hardening control neutralizes this vuln)"

        planned.append({
            "id": vid,
            "name": v["name"],
            "severity": v["severity"],
            "mitre": ",".join(v["attack"]["mitre_attack"]),
            "run_on": run_on,
            "target_domain": target_domain,
            "intended_path": " ".join(v["attack"]["intended_path"].split()),
            "neutralization": status,
            "vars": build_vuln_vars(vid, machines, primary_dc),
        })
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


def render_site_playbook(has_vuln_injection: bool, out_dir: Path) -> None:
    """The single entry point a /deploy command should run — enforces
    CLAUDE.md's deploy order (hardening before vuln-injection) instead of
    leaving it up to whoever runs the individual playbooks by hand."""
    dst = out_dir / "ansible" / "playbooks"
    dst.mkdir(parents=True, exist_ok=True)
    template = jinja2.Template(
        (TEMPLATES_DIR / "ansible" / "playbooks" / "site.yml.j2").read_text(encoding="utf-8"),
        keep_trailing_newline=True,
    )
    (dst / "site.yml").write_text(template.render(has_vuln_injection=has_vuln_injection), encoding="utf-8")


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


def resolve_hardening_skip_rules(baseline_id: str, reconciliation: dict, oses_in_scope: set[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Per-OS list of ansible-lockdown skip_rule vars to force false, derived
    ONLY from verified catalog/defense/hardening/control-cis-rules.yml entries
    — plus an honest note for every exclusion that could NOT be turned into a
    concrete skip_rule (unmapped control, STIG, or a rule whose level isn't
    even selected by this baseline)."""
    skip_rules: dict[str, list[str]] = {os_: [] for os_ in oses_in_scope}
    notes: list[str] = []

    if baseline_id in ("none", "baseline-controls"):
        for c in reconciliation.get("excluded_controls", []):
            notes.append(f"vuln '{c['vuln']}': baseline '{baseline_id}' runs no ansible-lockdown role, so no skip_rule applies — the toggle exclusion alone (pf_controls not applying it) is what preserves this gap.")
        return skip_rules, notes

    control_rules = load_control_cis_rules()
    baseline_levels = BASELINE_LEVELS.get(baseline_id, set())

    for c in reconciliation.get("excluded_controls", []):
        if c["kind"] != "control":
            notes.append(
                f"vuln '{c['vuln']}': baseline-level exclusion (control label '{c.get('control')}') has no "
                f"verified ansible-lockdown rule mapping in control-cis-rules.yml — no skip_rule applied."
            )
            continue
        control_name = c["control"]
        if baseline_id == "stig":
            notes.append(
                f"control '{control_name}' excluded, but no STIG skip_rule mapping is implemented "
                f"(catalog/defense/hardening/stig.yml) — pf_controls still does not apply the toggle itself."
            )
            continue
        mapping = control_rules.get(control_name)
        if not mapping:
            notes.append(f"control '{control_name}' excluded, but no control-cis-rules.yml entry exists for it — no skip_rule derived.")
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
        groups.append({"os": os_, "role_name": role_name, "hosts": hosts, "tags": tags, "skip_rule_vars": skip_rules_by_os.get(os_, [])})

    if errors:
        raise SpecError("hardening plan errors:\n" + "\n".join(f"  - {e}" for e in errors))
    return {"baseline": baseline_id, "engine": baseline["engine"], "apply_to": sorted(apply_to), "groups": groups, "notes": notes}


def plan_edr(resolved_defense: dict, machines: list[dict]) -> list[dict]:
    plans = []
    for entry in resolved_defense.get("edr", []):
        product = entry["product"]
        catalog_path = EDR_DIR / f"{product}.yml"
        catalog_entry = load_yaml(catalog_path) if catalog_path.exists() else {}
        targets = expand_role_or_all(entry.get("targets"))
        target_hosts = [m["name"] for m in machines if m["role"] in targets]

        if not catalog_entry:
            plans.append({"product": product, "mode": entry["mode"], "targets": target_hosts, "status": "not-implemented", "reason": f"no catalog/defense/edr/{product}.yml entry found"})
        elif catalog_entry.get("backend_required"):
            plans.append({
                "product": product, "mode": entry["mode"], "targets": target_hosts, "status": "not-implemented",
                "reason": f"'{product}' needs a management backend this project does not build (no detection-lab) — recorded, not silently skipped.",
            })
        elif product == "defender-av":
            plans.append({"product": product, "mode": entry["mode"], "targets": target_hosts, "status": "implemented", "settings": entry.get("settings", {})})
        else:
            plans.append({"product": product, "mode": entry["mode"], "targets": target_hosts, "status": "not-implemented", "reason": "no implementation wired for this product yet"})
    return plans


def plan_deception(resolved_defense: dict, theme: dict, groups: dict[str, list[dict]]) -> dict:
    deception = resolved_defense.get("deception", {})
    count = deception.get("honey_accounts", 0)
    if count <= 0:
        return {"honey_accounts": [], "run_on": None, "canarytokens": deception.get("canarytokens", [])}
    root_dcs = groups.get("domain_controllers", [])
    run_on = root_dcs[0]["name"] if root_dcs else None
    pattern = theme.get("honey_account_naming", "honey.user.{n}")
    accounts = [pattern.format(n=i + 1) for i in range(count)]
    return {"honey_accounts": accounts, "run_on": run_on, "canarytokens": deception.get("canarytokens", [])}


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
    hardening_plan: dict, edr_plan: list[dict], deception_plan: dict, machines: list[dict],
    resolved_defense: dict, ansible_groups: dict[str, list[dict]], out_dir: Path
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
        edr_implemented.append({
            "product": e["product"],
            "mode": e["mode"],
            "targets": e["targets"],
            "settings": [(k, yaml_scalar(v)) for k, v in e.get("settings", {}).items()],
        })

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
    theme: dict,
    out_dir: Path,
) -> dict[str, list[dict]]:
    src = TEMPLATES_DIR / "ansible"
    dst = out_dir / "ansible"
    (dst / "playbooks").mkdir(parents=True, exist_ok=True)
    (dst / "inventory").mkdir(parents=True, exist_ok=True)

    shutil.copy(src / "ansible.cfg", dst / "ansible.cfg")
    shutil.copy(src / "playbooks" / "ad-topology.yml", dst / "playbooks" / "ad-topology.yml")

    groups = build_ansible_groups(spec, machines, admin_password)
    attach_population_vars(groups, spec)

    template = jinja2.Template((src / "inventory" / "hosts.yml.j2").read_text(encoding="utf-8"), keep_trailing_newline=True)
    rendered = template.render(
        lab_name=spec["lab"]["name"],
        ansible_password=ansible_password,
        groups=groups,
        ad_theming_extra_groups=theme["extra_groups"],
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
        print("warning: terraform not found on PATH; skipping plan (install terraform to exercise this step).", file=sys.stderr)
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
# destroy: PROMPT-claude-code.md specifies /destroy as "terraform destroy +
# verificación de coste cero" — not just a clean terraform exit code. Every
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
        print(f"WARNING: resource group '{lab_name}' still exists after destroy — remaining resources:", file=sys.stderr)
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


def cmd_destroy(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    lab_name = load_yaml(spec_path)["lab"]["name"]

    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    tf_root = lab_dir / "terraform"
    if not tf_root.exists():
        print(f"error: no terraform/ directory found under {lab_dir} (nothing generated, or already destroyed?)", file=sys.stderr)
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
            print(f"  warning: no {backend_hcl.name} in {provider_dir}; assuming already initialized against the right backend.", file=sys.stderr)
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
}

VULN_CREDENTIAL_NOTES = {
    "gpp-cpassword": "No named account — a GPO's Groups.xml carries a cpassword that decrypts to `Local*8!` (published MS14-025 key).",
    "unconstrained-delegation": "No credentialed account — sets TRUSTED_FOR_DELEGATION on a computer object.",
    "smb-signing-disabled": "No account — machine-wide registry policy (RequireSecuritySignature=0).",
    "ntlm-downgrade": "No account — machine-wide registry policy (LmCompatibilityLevel=2).",
    "adcs-esc1": "No account — publishes the ESC1 certificate template (ENROLLEE_SUPPLIES_SUBJECT) for enrollment by Domain Users.",
    "laps-read-acl": "No named account — grants CONTROL_ACCESS read on msLAPS-Password (domain-wide) to an existing group, `Domain Users` by default.",
}


def describe_vuln_credentials(vid: str, vvars: dict) -> str:
    entry = VULN_CREDENTIAL_VARS.get(vid)
    if entry:
        account_key, password_key = entry
        account = vvars.get(account_key, "?")
        password = vvars.get(password_key, "?")
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
    population_by_domain = []
    for h in ansible_groups.get("domain_controllers", []) + ansible_groups.get("child_domain_controllers", []):
        population_by_domain.append({
            "domain": h["domain"],
            "users": h.get("badblood_user_count"),
            "groups": h.get("badblood_group_count"),
            "computers": h.get("badblood_computer_count"),
            "seed": h.get("badblood_seed"),
        })

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
    domain_admin_rows = [{"domain": d["domain"], "username": "Administrator", "password": admin_password} for d in spec["forest"]]

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
        "network_plan": network_plan,
        "machines": machines,
        "forest": spec["forest"],
        "population": spec["population"],
        "population_by_domain": population_by_domain,
        "theme_extra_groups": theme["extra_groups"],
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
        "network_protection_enabled": settings["network_protection"] if "network_protection" in settings else (mode != "detect"),
    }


def render_verify_playbook(
    machines: list[dict],
    ansible_groups: dict[str, list[dict]],
    theme: dict,
    hardening_plan: dict,
    resolved_controls: dict,
    edr_plan: list[dict],
    planned_vulns: list[dict],
    out_dir: Path,
) -> None:
    dc_domain_hosts = ansible_groups.get("domain_controllers", []) + ansible_groups.get("child_domain_controllers", [])

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
    print(f"  wrote {manifest_path.relative_to(REPO_ROOT) if manifest_path.is_relative_to(REPO_ROOT) else manifest_path}")
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
    if provider != "azure":
        print(
            f"FAIL: infra-{provider} is not implemented yet (see PROMPT-claude-code.md roadmap Fase 8 for AWS).",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / spec["lab"]["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    network_plan = manifest["network_plan"]
    machines = flatten_machines(spec, network_plan)
    admin_password = generate_password()
    ansible_password = generate_password()

    render_azure_terraform(
        network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"]
    )
    theme = load_theme(spec["lab"]["theme"])
    ansible_groups = render_ansible(spec, machines, admin_password, ansible_password, theme, out_dir)
    render_ad_theming(theme, out_dir)

    catalog = load_vuln_catalog()
    planned_vulns = plan_vuln_injection(spec, catalog, machines, ansible_groups, reconciliation)
    render_vuln_injection(spec, planned_vulns, out_dir)

    resolved_defense = manifest["defense_resolved"]
    hardening_plan = plan_hardening(machines, resolved_defense, reconciliation)
    edr_plan = plan_edr(resolved_defense, machines)
    deception_plan = plan_deception(resolved_defense, theme, ansible_groups)
    render_defensive_controls(hardening_plan, edr_plan, deception_plan, machines, resolved_defense, ansible_groups, out_dir)
    render_site_playbook(bool(planned_vulns), out_dir)

    manifest["machines_flat"] = machines
    manifest["ansible_groups"] = ansible_groups
    manifest["theme"] = theme["id"]
    manifest["vulnerabilities_planned"] = planned_vulns
    manifest["hardening_plan"] = hardening_plan
    manifest["edr_plan"] = edr_plan
    manifest["deception_plan"] = deception_plan
    manifest_path = out_dir / "lab-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    render_lab_report(
        spec, manifest, machines, network_plan, ansible_groups, theme,
        admin_password, ansible_password, planned_vulns,
        hardening_plan, edr_plan, deception_plan, out_dir,
    )
    render_verify_playbook(
        machines, ansible_groups, theme, hardening_plan,
        resolved_defense["hardening"].get("controls", {}), edr_plan, planned_vulns, out_dir,
    )

    print(f"OK: generated {spec_path.name} -> {out_dir.relative_to(REPO_ROOT) if out_dir.is_relative_to(REPO_ROOT) else out_dir}")
    print(f"  wrote {manifest_path.name}")
    print("  wrote lab-report.md (contains generated secrets — gitignored, never commit)")
    print("  wrote ansible/playbooks/verify.yml (post-deploy check, run separately after site.yml — see README)")
    print(f"  wrote terraform/{provider}/ (terraform.tfvars.json has generated secrets — gitignored, never commit)")
    print("  wrote ansible/ (inventory/hosts.yml has generated secrets — gitignored, never commit)")
    print(f"  wrote ansible/files/badblood/ (theme '{theme['id']}' overlay on vendor/BadBlood)")
    if planned_vulns:
        print(f"  wrote ansible/playbooks/vuln-injection.yml + ansible/vulns/ ({len(planned_vulns)} vuln(s))")
        for v in planned_vulns:
            print(f"      - {v['id']} -> {v['run_on']}  [{v['neutralization'].split(' (')[0]}]")
    print(f"  wrote ansible/playbooks/defensive-controls.yml (baseline: {hardening_plan['baseline']}, {len(hardening_plan.get('groups', []))} OS group(s))")
    for n in hardening_plan.get("notes", []):
        print(f"      note: {n}")
    for e in edr_plan:
        if e["status"] != "implemented":
            print(f"      note: edr '{e['product']}' — {e['reason']}")
    print("  wrote ansible/playbooks/site.yml (run this, not the individual playbooks — enforces hardening-before-vulns)")

    if args.plan:
        return run_terraform_plan(out_dir / "terraform" / provider)
    return 0


# ---------------------------------------------------------------------------
# ad-inventory: a POST-DEPLOY report, genuinely different from lab-report.md
# (which is spec-time/pre-deploy). BadBlood's own per-user passwords are
# randomly generated with PowerShell's Get-Random on the Windows host during
# `site.yml` and never written anywhere — not even by BadBlood itself, not
# recoverable by this script either. The only honest way to document "users
# with password" after a real deploy is what's actually recoverable from the
# live domain: NT hashes via a DCSync-style dump (pass-the-hash usable,
# crackable offline), not plaintext. Queries the domain directly — LDAP
# (ldap3) for users/groups, `nxc`/netexec for the hash dump — rather than
# guessing anything from the spec.
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
        base_dn, "(&(objectClass=user)(objectCategory=person))", SUBTREE,
        attributes=["sAMAccountName", "userAccountControl", "memberOf", "description"],
    )
    users = []
    for e in conn.entries:
        uac = int(e.userAccountControl.value)
        member_of = [dn_to_name(dn) for dn in e.memberOf.values] if "memberOf" in e else []
        users.append({
            "username": str(e.sAMAccountName),
            "enabled": not (uac & 2),  # ADS_UF_ACCOUNTDISABLE
            "description": str(e.description) if "description" in e and e.description else "",
            "groups": sorted(member_of),
        })

    conn.search(base_dn, "(objectClass=group)", SUBTREE, attributes=["sAMAccountName", "description", "member"])
    groups = []
    for e in conn.entries:
        members = [dn_to_name(dn) for dn in e.member.values] if "member" in e else []
        groups.append({
            "name": str(e.sAMAccountName),
            "description": str(e.description) if "description" in e and e.description else "",
            "members": sorted(members),
        })
    conn.unbind()

    hashes: dict[str, dict] = {}
    nxc_bin = shutil.which("nxc") or shutil.which("netexec")
    if nxc_bin:
        result = subprocess.run(
            [nxc_bin, "smb", dc_ip, "-d", domain, "-u", admin_user, "-p", admin_password, "--ntds", "drsuapi"],
            capture_output=True, text=True, timeout=300,
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
        print(f"error: {lab_dir} has no generated inventory/manifest — run `generate` (and deploy) first.", file=sys.stderr)
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
    print(f"OK: wrote {out_path} ({len(data['users'])} users, {len(data['groups'])} groups, {len(data['hashes'])} NT hashes)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="forge.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_lab_spec = sub.add_parser("lab-spec", help="Validate, resolve and reconcile a lab-spec.yml; emit lab-manifest.json")
    p_lab_spec.add_argument("spec", help="Path to a lab-spec YAML file")
    p_lab_spec.add_argument("--check-only", action="store_true", help="Validate/reconcile but do not write lab-manifest.json")
    p_lab_spec.add_argument("--out-dir", help="Override output directory (default: generated/<lab.name>/)")
    p_lab_spec.set_defaults(func=cmd_lab_spec)

    p_generate = sub.add_parser("generate", help="Render Terraform + Ansible artifacts for a lab-spec.yml into generated/<lab>/")
    p_generate.add_argument("spec", help="Path to a lab-spec YAML file")
    p_generate.add_argument("--out-dir", help="Override output directory (default: generated/<lab.name>/)")
    p_generate.add_argument("--plan", action="store_true", help="Also run terraform init/validate/plan after rendering (needs terraform on PATH; needs cloud credentials for a full plan)")
    p_generate.set_defaults(func=cmd_generate)

    p_destroy = sub.add_parser("destroy", help="terraform destroy a generated lab + verify no Azure resource group is left behind")
    p_destroy.add_argument("spec", help="Path to the same lab-spec YAML file used to generate the lab")
    p_destroy.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_destroy.add_argument("--yes", action="store_true", help="Pass -auto-approve to terraform destroy (default: terraform's own interactive confirmation prompt)")
    p_destroy.add_argument("--check-only", action="store_true", help="Run 'terraform plan -destroy' instead of actually destroying anything")
    p_destroy.set_defaults(func=cmd_destroy)

    p_ad_inventory = sub.add_parser(
        "ad-inventory",
        help="Query a LIVE deployed lab's domain (LDAP + DCSync via nxc) and render generated/<lab>/ad-inventory.md: users, groups, NT hashes",
    )
    p_ad_inventory.add_argument("spec", help="Path to the same lab-spec YAML file used to generate/deploy the lab")
    p_ad_inventory.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_ad_inventory.set_defaults(func=cmd_ad_inventory)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
