"""Rendering: turns the deterministic plans (from planning) into the concrete
Terraform + Ansible + report artifacts under generated/<lab>/. Every function
here is a pure "plan in, files out" step; the orchestration order lives in
cmd_generate (forge/__init__.py), and the deploy order it enforces is
CLAUDE.md's mandate (hardening before vuln injection).
"""

from __future__ import annotations

import ipaddress
import json
import shutil
from pathlib import Path

import jinja2
from population import generate_population_plan

from .core import (
    REPO_ROOT,
    TEMPLATES_DIR,
    VULN_CREDENTIAL_VARS,
    WINDOWS_ADMIN_USERNAME,
    WINRM_AUTOMATION_USERNAME,
    generate_password,
    yaml_scalar,
)
from .planning import (
    build_ansible_groups,
    compute_population_counts,
    expand_role_or_all,
    parse_auto_shutdown,
)

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
    # The two infra secrets in a SEPARATE gitignored auto-tfvars overlay (terraform
    # auto-loads *.auto.tfvars.json), so the committed terraform.tfvars.json stays
    # secret-free and shareable. Both are seed-derived (derive_infra_secrets), so
    # `generate` reproduces this file identically from the spec.
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


def render_aws_backend_config(lab_name: str, dst: Path) -> None:
    """Writes backend.hcl for `terraform init -backend-config=backend.hcl`
    (versions.tf declares a partial `backend "s3" {}` — CLAUDE.md invariant #4,
    state must never default to local). One shared S3 bucket + DynamoDB lock
    table holds every lab's state as a separate key (the AWS analogue of the
    shared Azure storage account); the bucket name must be globally unique, so
    the placeholder below WILL collide across PurpleForge installs — treat it
    as a value to override after the one-time bootstrap, not a working default.
    See .claude/skills/infra-aws/SKILL.md.
    """
    content = (
        'bucket         = "purpleforge-tfstate"  # placeholder — S3 bucket names are global, override after bootstrap\n'
        f'key            = "{lab_name}.tfstate"\n'
        'region         = "us-east-1"  # the state bucket\'s region (not necessarily the lab\'s region)\n'
        'dynamodb_table = "purpleforge-tfstate-lock"\n'
        'encrypt        = true\n'
    )
    (dst / "backend.hcl").write_text(content, encoding="utf-8")


def parse_auto_shutdown_cron(value: str) -> tuple[str, str]:
    """ "20:00 Europe/Madrid" -> ("cron(0 20 * * ? *)", "Europe/Madrid") for
    aws_scheduler_schedule. Unlike Azure (parse_auto_shutdown), EventBridge
    Scheduler accepts the IANA zone name directly, so no Windows-timezone
    translation is needed — the schema already enforces the "HH:MM Area/City"
    pattern on lab.auto_shutdown."""
    time_part, tz_part = value.split(" ", 1)
    hh, mm = time_part.split(":")
    return f"cron({int(mm)} {int(hh)} * * ? *)", tz_part


def render_aws_terraform(
    network_plan: dict, machines: list[dict], out_dir: Path, admin_password: str, ansible_password: str, lab: dict
) -> None:
    """Sibling of render_azure_terraform for the AWS provider. Same committed-
    tfvars / gitignored-secrets-overlay split as Azure, and a remote S3 state
    backend (backend.hcl, invariant #4). AWS has no resource-group or per-VM
    shutdown schedule, so the Terraform layer tags everything lab/project (the
    provider default_tags) and builds auto_shutdown from EventBridge Scheduler +
    a Lambda (auto_shutdown.tf). AMIs resolve from SSM public parameters at
    plan/apply time, so no account-specific ami-id is baked into the spec."""
    src = TEMPLATES_DIR / "terraform" / "aws"
    dst = out_dir / "terraform" / "aws"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    shutdown_cron, shutdown_tz = parse_auto_shutdown_cron(lab["auto_shutdown"])
    tfvars = {
        "lab_name": lab["name"],
        "region": lab["region"],
        "auto_shutdown_cron": shutdown_cron,
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
                # image_id on AWS holds an AMI id; most labs leave it null and
                # resolve the stock Windows AMI via SSM (see windows.tf).
                "image_id": m.get("image_id"),
            }
            for m in machines
        ],
        "admin_username": WINDOWS_ADMIN_USERNAME,
        "jumpbox_username": WINDOWS_ADMIN_USERNAME,
        "wireguard_port": 51820,
        "wireguard_allowed_cidrs": ["0.0.0.0/0"],
        "bastion_ssh_allowed_cidrs": [],
    }
    (dst / "terraform.tfvars.json").write_text(json.dumps(tfvars, indent=2) + "\n", encoding="utf-8")
    (dst / "secrets.auto.tfvars.json").write_text(
        json.dumps({"admin_password": admin_password, "ansible_password": ansible_password}, indent=2) + "\n",
        encoding="utf-8",
    )
    render_aws_backend_config(lab["name"], dst)


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
    """Writes the lab's secrets as ansible group_vars under group_vars/all/ so
    ansible auto-loads them for every host (win_ping + site.yml). EVERY secret
    here — population USER passwords AND the two infra keys (domain admin +
    ansible WinRM) — is deterministic from population.seed, so `generate`
    reproduces them identically from the spec alone (CLAUDE.md invariant #5).
    They all live under gitignored generated/<lab>/, so none reaches git and
    none is ever minted at deploy time — sharing the spec is sufficient to
    reproduce them.

      - population-secrets.yml: the population USER passwords (pf_pop_secrets).
      - secrets.yml: the two infra keys (pf_admin_password/pf_ansible_password),
        mirrored for Terraform in secrets.auto.tfvars.json (render_azure_terraform).

    JSON is a valid YAML subset, so the .yml bodies are written as JSON to dodge
    password-quoting pitfalls. Returns the population-user count."""
    pop_secrets = {u["sam_account_name"]: u["password"] for plan in population_plans for u in plan["users"]}
    gv = out_dir / "ansible" / "inventory" / "group_vars" / "all"
    gv.mkdir(parents=True, exist_ok=True)
    (gv / "population-secrets.yml").write_text(
        "# Population user passwords — deterministic from population.seed, so\n"
        "# `forge generate` reproduces them identically from the spec.\n"
        + json.dumps({"pf_pop_secrets": pop_secrets}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    (gv / "secrets.yml").write_text(
        "# Infra keys (domain admin + ansible WinRM) — deterministic from\n"
        "# population.seed like every other secret. Gitignored; never commit.\n"
        + json.dumps({"pf_admin_password": admin_password, "pf_ansible_password": ansible_password}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return len(pop_secrets)


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
    commands (the lab-report just points at them); `forge deploy`/`teardown`
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
    template_suffix = {"proxmox": "-proxmox", "aws": "-aws"}.get(provider, "")
    env = jinja2.Environment(keep_trailing_newline=True)
    # reset.sh restores the clean-state snapshot deploy.sh takes as its last step
    # (CLAUDE.md deploy order) — run between exercises via `forge reset`.
    for name in ("deploy.sh", "teardown.sh", "reset.sh"):
        stem = name[: -len(".sh")]
        template = env.from_string((TEMPLATES_DIR / f"{stem}{template_suffix}.sh.j2").read_text(encoding="utf-8"))
        path = out_dir / name
        path.write_text(template.render(**context), encoding="utf-8")
        path.chmod(0o755)


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
    # DNS forwarder for the DC (GOAD's domain_controller role, xDnsServerForwarder).
    # Azure's magic resolver 168.63.129.16 is WRONG on AWS — there the VPC resolver
    # is the VPC CIDR base + 2 (e.g. 10.54.0.0/16 -> 10.54.0.2). Without this, a
    # promoted DC forwards public DNS to an unreachable IP and every Install-Module
    # from PSGallery fails "No match was found" (ActiveDirectoryDSC etc.). Proxmox
    # keeps the old value — its lab bridge has no uplink, so the forwarder is moot
    # (GOAD modules are pre-baked in the template there).
    provider = spec["lab"]["provider"]
    if provider == "aws":
        octet = machines[0]["ip"].split(".")[1]  # lab addressing is always 10.<octet>.0.0/16
        dns_server_forwarder = f"10.{octet}.0.2"
    else:
        dns_server_forwarder = "168.63.129.16"
    # Primary NIC name GOAD's roles configure (xDnsServerAddress / rename). Azure &
    # Proxmox images present it as "Ethernet"; EC2 Windows AMIs (ENA driver)
    # enumerate the primary adapter as "Ethernet 3" — without this, GOAD's member
    # -server DNS task fails "No MSFT_NetAdapter objects found with property 'Name'
    # equal to 'Ethernet'".
    domain_adapter = "Ethernet 3" if provider == "aws" else "Ethernet"
    rendered = template.render(
        lab_name=spec["lab"]["name"],
        ansible_password=ansible_password,
        groups=groups,
        local_admin_username=WINDOWS_ADMIN_USERNAME,
        provider=provider,
        dns_server_forwarder=dns_server_forwarder,
        domain_adapter=domain_adapter,
    )
    (dst / "inventory" / "hosts.yml").write_text(rendered, encoding="utf-8")
    return groups


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
