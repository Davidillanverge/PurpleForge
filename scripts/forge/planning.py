"""Deterministic planning core: schema + semantic validation, IP assignment,
cost estimation, the hardening<->vulnerability reconciliation, the machine/
inventory/attack-chain/vuln-injection plans, and the hardening/EDR/deception
plans. Everything here is pure (no I/O beyond reading the catalog) and testable;
the render module turns these plans into Terraform/Ansible artifacts.
"""

from __future__ import annotations

import copy
import json
import random
import sys
from pathlib import Path

import jsonschema

from .catalog import (
    load_control_cis_rules,
    load_hardening_baseline,
    load_vuln_catalog,
    resolve_defense,
)
from .core import (
    EDR_DIR,
    REPO_ROOT,
    ROLE_ABBREV,
    THEMES_DIR,
    VULN_CREDENTIAL_VARS,
    SpecError,
    generate_password,
    load_schema,
    load_yaml,
    stable_octet,
    yaml_scalar,
)

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

# Intentionally weak, dictionary-crackable passwords for the roastable accounts —
# being crackable offline IS the vulnerability (kerberoasting/asreproast). They
# are non-secret by design and still only ever written into generated/<lab>/
# (gitignored). Accounts whose weakness is NOT about the password (dcsync-acl,
# passwords-in-description) get a strong random one instead.
VULN_WEAK_PASSWORD = "Password123!"
VULN_WEAK_PASSWORD_ALT = "Summer2024!"
VULN_WEAK_PASSWORD_3 = "Welcome2024!"

BASELINE_LEVELS = {"cis-l1": {"l1"}, "cis-l2": {"l1", "l2"}}

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


def validate_schema(spec: dict, schema: dict) -> list[str]:
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(spec), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]


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
            "scripts/forge/planning.py (azurerm_dev_test_global_vm_shutdown_schedule "
            "requires a Windows timezone ID, not an IANA name)."
        ) from None
    return time_part.replace(":", ""), windows_tz


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


def compute_population_counts(users: int, density: str) -> tuple[int, int, int]:
    """UserCount is population.users directly; GroupCount/ComputerCount scale
    off it by density, matching Invoke-BadBlood.ps1's own three counters."""
    ratio_by_density = {"sparse": (0.15, 0.3), "realistic": (0.2, 0.4), "messy": (0.3, 0.5)}
    group_ratio, computer_ratio = ratio_by_density[density]
    return users, max(1, round(users * group_ratio)), max(1, round(users * computer_ratio))


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


def expand_role_or_all(value) -> set[str]:
    if value == "all" or value is None:
        return {"domain-controller", "member-server", "workstation"}
    return set(value)


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
