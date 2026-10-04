"""PurpleForge deterministic core.

Implements the parts of the harness that must be deterministic and testable
rather than left to an LLM: schema validation, semantic checks, defense.profile
default resolution, IP assignment, cost estimation and the hardening<->vuln
reconciliation, plus the deterministic, no-AI lifecycle: generate (renders
Terraform + Ansible + deploy.sh/teardown.sh + lab-report.md), guardrail, deploy,
validate --run, teardown, destroy, ad-inventory.

This package was split out of a single scripts/forge.py module; the layering is:
    core        — paths, constants, SpecError, small pure helpers
    catalog     — vuln/theme/hardening/defense loaders
    planning    — validation, resolution, reconciliation, all the *plans*
    render      — plans -> Terraform/Ansible/report artifacts
    lifecycle   — deploy / teardown / destroy
    validate    — live vuln validation + ad-inventory
    __init__    — cmd_lab_spec/generate/guardrail + main() (the CLI)

Everything public is re-exported here, so `import forge; forge.<name>` keeps
working exactly as it did against the old flat module.

Usage:
    forge lab-spec specs/<lab>.yml
    forge generate specs/<lab>.yml --plan
    forge deploy   specs/<lab>.yml
    forge validate specs/<lab>.yml --run
    forge teardown specs/<lab>.yml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import (
    build_technique_index,
    load_control_cis_rules,
    load_defense_profile,
    load_hardening_baseline,
    load_theme,
    load_theme_schema,
    load_vuln_catalog,
    load_vulnerability_schema,
    resolve_defense,
)
from .core import (
    CONTROL_CIS_RULES_PATH,
    DEFENSE_PROFILES_DIR,
    EDR_DIR,
    GENERATED_DIR,
    HARDENING_DIR,
    REPO_ROOT,
    ROLE_ABBREV,
    SCHEMA_PATH,
    TEMPLATES_DIR,
    THEMES_DIR,
    VULN_CATALOG_DIR,
    VULN_CREDENTIAL_VARS,
    WINDOWS_ADMIN_USERNAME,
    WINRM_AUTOMATION_USERNAME,
    SpecError,
    deep_merge,
    generate_password,
    load_schema,
    load_yaml,
    stable_octet,
    yaml_scalar,
)
from .from_exercise import (
    build_spec,
    cmd_from_exercise,
    load_navigator_layer,
    match_techniques,
)
from .lifecycle import (
    clean_snapshot_name,
    cmd_deploy,
    cmd_destroy,
    cmd_reset,
    cmd_teardown,
    run_terraform_plan,
    verify_azure_teardown,
)
from .planning import (
    BASELINE_LEVELS,
    BROKEN_UPSTREAM_CIS_RULES,
    ENUM_HARDENING_TOGGLES,
    FIXED_HARDENING_TOGGLES,
    HOURLY_RATE_USD,
    IANA_TO_WINDOWS_TIMEZONE,
    VULN_WEAK_PASSWORD,
    VULN_WEAK_PASSWORD_3,
    VULN_WEAK_PASSWORD_ALT,
    WINDOWS_EVAL_EXPIRY_DAYS,
    assign_ips,
    build_ansible_groups,
    build_manifest,
    build_vuln_vars,
    compute_population_counts,
    derive_infra_secrets,
    estimate_cost,
    eval_expiry_notes,
    expand_role_or_all,
    flatten_machines,
    load_and_resolve,
    parse_auto_shutdown,
    plan_application_provisioning,
    plan_bas,
    plan_deception,
    plan_edr,
    plan_hardening,
    plan_service_provisioning,
    plan_telemetry,
    plan_vuln_injection,
    reconcile,
    resolve_attack_chain,
    resolve_hardening_skip_rules,
    semantic_checks,
    validate_schema,
)
from .render import (
    DEFENDER_ASR_RULE_IDS,
    VULN_CREDENTIAL_NOTES,
    describe_vuln_credentials,
    render_ad_population,
    render_ansible,
    render_application_provisioning,
    render_aws_terraform,
    render_azure_terraform,
    render_backend_config,
    render_bas,
    render_defensive_controls,
    render_deploy_scripts,
    render_lab_report,
    render_proxmox_terraform,
    render_service_provisioning,
    render_site_playbook,
    render_telemetry,
    render_verify_playbook,
    render_vuln_injection,
    resolve_defender_av_expected,
    write_lab_secrets,
)
from .validate import (
    LDAP_APPLIED_FILTERS,
    ROAST_FLAGS,
    VALID_RESULT,
    WINRM_APPLIED_CHECKS,
    build_vuln_check,
    cmd_ad_inventory,
    cmd_validate,
    merge_validation_results,
    query_ad_inventory,
    render_results_template,
    render_validation_report,
    run_live_validation,
)


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
    if provider not in ("azure", "proxmox", "aws"):
        print(
            f"FAIL: infra-{provider} is not implemented yet (Azure, Proxmox and AWS today).",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / spec["lab"]["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    network_plan = manifest["network_plan"]
    machines = flatten_machines(spec, network_plan)
    # Infra secrets (domain admin + ansible WinRM) are derived from population.seed,
    # so the spec alone reproduces the whole lab — lab-report.md included — and a
    # regenerate is a Terraform no-op (same password every time). See
    # planning.derive_infra_secrets.
    admin_password, ansible_password = derive_infra_secrets(spec["population"]["seed"])

    if provider == "proxmox":
        render_proxmox_terraform(network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"])
    elif provider == "aws":
        render_aws_terraform(network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"])
    else:
        render_azure_terraform(network_plan, machines, out_dir, admin_password, ansible_password, spec["lab"])
    theme = load_theme(spec["lab"]["theme"])
    ansible_groups = render_ansible(spec, machines, admin_password, ansible_password, out_dir)
    population_plans = render_ad_population(theme, spec, ansible_groups, out_dir)
    write_lab_secrets(out_dir, admin_password, ansible_password, population_plans)

    service_hosts = plan_service_provisioning(machines)
    render_service_provisioning(service_hosts, spec["lab"]["name"], out_dir)
    app_hosts = plan_application_provisioning(machines)
    render_application_provisioning(app_hosts, spec["lab"]["name"], out_dir)

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
    tel_hosts = plan_telemetry(spec, machines)
    render_telemetry(tel_hosts, spec["lab"]["name"], out_dir)
    bas_hosts = plan_bas(spec, machines)
    render_bas(bas_hosts, spec["lab"]["name"], out_dir)
    render_site_playbook(
        bool(planned_vulns), bool(service_hosts), out_dir, bool(app_hosts), bool(tel_hosts), bool(bas_hosts)
    )
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
        telemetry_plan=tel_hosts,
        bas_plan=bas_hosts,
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
        "  wrote ansible/ (hosts.yml + ad-population.yml secret-free; all secrets — population + infra keys — are seed-deterministic in the gitignored group_vars/all/, reproduced identically by generate)"
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
        "  wrote deploy.sh + teardown.sh (deterministic no-AI deploy/teardown — run directly or via `forge deploy`/`teardown`)"
    )
    if provider == "proxmox":
        print(
            "  NOTE: provider 'proxmox' — before deploy, fill terraform/proxmox/host.auto.tfvars.json (see host.auto.tfvars.example.json) and export PROXMOX_VE_ENDPOINT / PROXMOX_VE_API_TOKEN. Windows templates now only need cloudbase-init (with UserDataPlugin enabled) baked in — WinRM + the `ansible` admin are bootstrapped at first boot via cloudbase-init user-data (terraform/proxmox/cloudinit/windows-bootstrap.ps1.tpl)."
        )

    if args.plan:
        return run_terraform_plan(out_dir / "terraform" / provider)
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
    parser = argparse.ArgumentParser(prog="forge", description=__doc__)
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

    p_reset = sub.add_parser(
        "reset",
        help="Roll a deployed lab back to its clean-state snapshot (taken at the end of deploy, after hardening+vulns, before any attack) — run the generated reset.sh. Lets an exercise restart from a pristine lab.",
    )
    p_reset.add_argument("spec", help="Path to the same lab-spec YAML file used to generate/deploy the lab")
    p_reset.add_argument("--out-dir", help="Override the generated lab directory (default: generated/<lab.name>/)")
    p_reset.set_defaults(func=cmd_reset)

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

    p_from_exercise = sub.add_parser(
        "from-exercise",
        help="Author specs/<lab>.yml from a BAS exercise's ATT&CK Navigator layer: select the catalog vulns that reproduce its techniques and emit a spec whose intentional gaps are provably those techniques (then run lab-spec/generate as usual).",
    )
    p_from_exercise.add_argument("layer", help="Path to an ATT&CK Navigator layer JSON (from bas-purple-team-exercise)")
    p_from_exercise.add_argument("--out", help="Output spec path (default: specs/<lab.name>.yml)")
    p_from_exercise.add_argument("--name", help="Lab name (default: derived from the layer's 'name', else 'exercise-lab')")
    p_from_exercise.add_argument("--theme", default="corporate", help="catalog/themes/<theme> (default: corporate)")
    p_from_exercise.add_argument("--provider", default="azure", choices=["aws", "azure", "proxmox"], help="default: azure")
    p_from_exercise.add_argument("--region", default="eastus", help="default: eastus")
    p_from_exercise.add_argument("--domain", default="corp.local", help="single forest domain FQDN (default: corp.local)")
    p_from_exercise.add_argument("--users", type=int, default=25, help="population size (default: 25)")
    p_from_exercise.add_argument("--seed", type=int, default=1337, help="population seed (default: 1337)")
    p_from_exercise.add_argument(
        "--density", default="realistic", choices=["sparse", "realistic", "messy"], help="default: realistic"
    )
    p_from_exercise.add_argument("--budget", type=float, default=30, help="budget_alert_usd (default: 30)")
    p_from_exercise.add_argument(
        "--auto-shutdown", default="20:00 Europe/Madrid", help="auto_shutdown (default: '20:00 Europe/Madrid')"
    )
    p_from_exercise.add_argument(
        "--chain", default="independent", choices=["independent", "ctf"], help="attack_chain.mode (default: independent)"
    )
    p_from_exercise.add_argument(
        "--exact-only",
        action="store_true",
        help="Match techniques verbatim only; suppress parent<->sub-technique roll-up",
    )
    p_from_exercise.add_argument("--force", action="store_true", help="Overwrite the output spec if it already exists")
    p_from_exercise.set_defaults(func=cmd_from_exercise)

    args = parser.parse_args()
    return args.func(args)


__all__ = [
    # core
    "CONTROL_CIS_RULES_PATH", "DEFENSE_PROFILES_DIR", "EDR_DIR", "GENERATED_DIR", "HARDENING_DIR", "REPO_ROOT",
    "ROLE_ABBREV", "SCHEMA_PATH", "TEMPLATES_DIR", "THEMES_DIR", "VULN_CATALOG_DIR", "VULN_CREDENTIAL_VARS",
    "WINDOWS_ADMIN_USERNAME", "WINRM_AUTOMATION_USERNAME", "SpecError", "deep_merge", "generate_password",
    "load_schema", "load_yaml", "stable_octet", "yaml_scalar",
    # catalog
    "build_technique_index", "load_control_cis_rules", "load_defense_profile", "load_hardening_baseline",
    "load_theme", "load_theme_schema", "load_vuln_catalog", "load_vulnerability_schema", "resolve_defense",
    # from_exercise
    "build_spec", "cmd_from_exercise", "load_navigator_layer", "match_techniques",
    # planning
    "BASELINE_LEVELS", "BROKEN_UPSTREAM_CIS_RULES", "ENUM_HARDENING_TOGGLES", "FIXED_HARDENING_TOGGLES",
    "HOURLY_RATE_USD", "IANA_TO_WINDOWS_TIMEZONE", "VULN_WEAK_PASSWORD", "VULN_WEAK_PASSWORD_3",
    "VULN_WEAK_PASSWORD_ALT", "WINDOWS_EVAL_EXPIRY_DAYS", "assign_ips", "build_ansible_groups", "build_manifest",
    "build_vuln_vars", "compute_population_counts", "derive_infra_secrets", "estimate_cost", "eval_expiry_notes",
    "expand_role_or_all", "flatten_machines", "load_and_resolve", "parse_auto_shutdown", "plan_deception",
    "plan_application_provisioning", "plan_bas", "plan_edr", "plan_telemetry", "plan_hardening", "plan_service_provisioning", "plan_vuln_injection", "reconcile",
    "resolve_attack_chain", "resolve_hardening_skip_rules", "semantic_checks", "validate_schema",
    # render
    "DEFENDER_ASR_RULE_IDS", "VULN_CREDENTIAL_NOTES", "describe_vuln_credentials", "render_ad_population",
    "render_ansible", "render_azure_terraform", "render_backend_config", "render_defensive_controls",
    "render_application_provisioning", "render_bas", "render_deploy_scripts", "render_telemetry", "render_lab_report", "render_proxmox_terraform", "render_service_provisioning",
    "render_site_playbook", "render_verify_playbook", "render_vuln_injection", "resolve_defender_av_expected",
    "write_lab_secrets",
    # lifecycle
    "clean_snapshot_name", "cmd_deploy", "cmd_destroy", "cmd_reset", "cmd_teardown", "run_terraform_plan",
    "verify_azure_teardown",
    # validate
    "LDAP_APPLIED_FILTERS", "ROAST_FLAGS", "VALID_RESULT", "WINRM_APPLIED_CHECKS", "build_vuln_check",
    "cmd_ad_inventory", "cmd_validate", "merge_validation_results", "query_ad_inventory", "render_results_template",
    "render_validation_report", "run_live_validation",
    # this module
    "cmd_generate", "cmd_guardrail", "cmd_lab_spec", "main",
]
