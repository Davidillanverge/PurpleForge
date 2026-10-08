"""Structural assertions on the RENDERED artifacts (not just the plan).

The plan-level tests cover assign_ips/build_ansible_groups in isolation; this
drives a full `generate` and asserts the invariants hold in the files an operator
actually deploys: invariant #1 (every machine private-IP-only, WireGuard bastion
present) and the mandated deploy order (site.yml runs hardening before vuln
injection).
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from types import SimpleNamespace

import forge
import pytest
from _helpers import make_spec, write_spec


def _generate(tmp_path, **spec_kwargs):
    # All secrets are seed-derived, so generate is hermetic — no pre-seeding needed.
    spec_file = write_spec(tmp_path, make_spec(**spec_kwargs))
    out = tmp_path / "out"
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    return out


def test_no_machine_gets_a_public_ip(tmp_path):
    """Invariant #1: no vulnerable host is internet-reachable — every rendered
    machine IP is in RFC1918 space (the /16 supernet the plan carves)."""
    out = _generate(tmp_path, members=1, workstations=1, vulns=["kerberoasting"])
    tfvars = json.loads((out / "terraform" / "azure" / "terraform.tfvars.json").read_text(encoding="utf-8"))
    assert tfvars["machines"], "expected at least one machine rendered"
    for m in tfvars["machines"]:
        assert ipaddress.ip_address(m["ip"]).is_private, f"{m['name']} got a non-private IP {m['ip']}"
    # The only routable entry point is the WireGuard bastion in the mgmt subnet.
    assert ipaddress.ip_address(tfvars["jumpbox_private_ip"]).is_private
    assert tfvars["wireguard_port"] == 51820


def test_site_yml_orders_hardening_before_vuln_injection(tmp_path):
    """CLAUDE.md deploy order: hardening (defensive-controls) must be imported
    before vuln-injection in the single site.yml entry point."""
    out = _generate(tmp_path, members=1, vulns=["kerberoasting"], baseline="cis-l1")
    site = (out / "ansible" / "playbooks" / "site.yml").read_text(encoding="utf-8")
    assert "defensive-controls.yml" in site and "vuln-injection.yml" in site
    assert site.index("defensive-controls.yml") < site.index("vuln-injection.yml"), (
        "site.yml must run hardening before vuln injection"
    )


# Power controls (stop/restart): the provider-specific action each generated
# script must invoke — deallocate/stop to drop to minimal cost, reboot/reset to
# unstick a hung VM. Keyed by provider; checked in the rendered script text.
_POWER_MARKERS = {
    "azure": {"stop.sh": "/deallocate?", "start.sh": "/start?api-version", "restart.sh": "/restart?api-version"},
    "aws": {"stop.sh": "stop-instances", "start.sh": "start-instances", "restart.sh": "reboot-instances"},
    # graceful guest shutdown first (hard stop only as a timeout fallback)
    "proxmox": {"stop.sh": "status/shutdown", "start.sh": "status/start", "restart.sh": "status/reset"},
}


@pytest.mark.parametrize("provider", ["azure", "aws", "proxmox"])
def test_power_control_scripts_are_generated_per_provider(tmp_path, provider):
    """stop.sh (pause to minimal cost, no destroy) and restart.sh (reboot a hung
    VM, not a snapshot rollback) are rendered for every provider, carry that
    provider's power action, and are syntactically valid bash."""
    out = _generate(tmp_path, provider=provider, members=1, vulns=["kerberoasting"])
    bash = shutil.which("bash")
    for script, marker in _POWER_MARKERS[provider].items():
        path = out / script
        if script == "start.sh":
            # start.sh sources deploy.sh and reuses its start_vms() (one source of truth)
            assert "start_vms" in path.read_text(encoding="utf-8")
            path = out / "deploy.sh"
        assert path.exists(), f"{script} not generated for {provider}"
        text = path.read_text(encoding="utf-8")
        assert marker in text, f"{script} ({provider}) missing power action {marker!r}"
        # Safety: a power control never destroys infra (that's `forge teardown`).
        assert "terraform destroy" not in text
        if bash:
            assert subprocess.run([bash, "-n", str(path)]).returncode == 0, f"{script} ({provider}) is not valid bash"


@pytest.mark.parametrize("provider,tf_sub", [("azure", "azure"), ("aws", "aws"), ("proxmox", "proxmox")])
def test_regenerate_preserves_deploy_resolved_state(tmp_path, provider, tf_sub):
    """Regenerating a DEPLOYED lab must NOT wipe its deploy-resolved files (the
    remote-state pointer, sizing/region overlays, SSH keys, terraform-init
    cache). Wiping them orphans the remote state so teardown silently skips
    destroy — the teardown-backend-overwrite class of bug. A second
    `forge generate` into the same dir must carry them across untouched."""
    spec_file = write_spec(tmp_path, make_spec(provider=provider, members=1, vulns=["kerberoasting"]))
    out = tmp_path / "out"

    def gen():
        return forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False))

    assert gen() == 0
    tf = out / "terraform" / tf_sub

    # Simulate what a deploy leaves behind: a RESOLVED backend pointer + the
    # deploy-time overlays, keys and init cache that are not reproducible from
    # the spec. Each gets a sentinel we can detect after the regenerate.
    sentinels = {
        "sizes.auto.tfvars.json": '{"__sentinel__": "deploy-sizing"}',
        "region.auto.tfvars.json": '{"__sentinel__": "deploy-region"}',
        "ssh_keys/bastion.pem": "----DEPLOY SSH KEY SENTINEL----",
        ".terraform.lock.hcl": "# deploy lock sentinel",
        ".terraform/terraform.tfstate": '{"backend": "sentinel"}',
    }
    if provider != "proxmox":  # proxmox uses local state, no backend.hcl
        sentinels["backend.hcl"] = 'bucket = "deploy-resolved-sentinel-bucket"\n'
    for rel, body in sentinels.items():
        p = tf / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    assert gen() == 0, "second generate failed"

    for rel, body in sentinels.items():
        p = tf / rel
        assert p.exists(), f"regenerate wiped deploy-resolved {rel} ({provider})"
        assert p.read_text(encoding="utf-8") == body, f"regenerate overwrote deploy-resolved {rel} ({provider})"
    # the new power scripts are still emitted on the regenerate
    assert (out / "stop.sh").exists() and (out / "restart.sh").exists()


def test_fresh_generate_writes_placeholder_backend(tmp_path):
    """Preserving a resolved backend.hcl must not stop a FIRST generate from
    writing the placeholder — otherwise a fresh clone has no backend config."""
    for provider, tf_sub in (("azure", "azure"), ("aws", "aws")):
        sub = tmp_path / provider
        sub.mkdir()
        spec_file = write_spec(sub, make_spec(provider=provider, vulns=["kerberoasting"]))
        out = sub / "out"
        assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
        backend = (out / "terraform" / tf_sub / "backend.hcl").read_text(encoding="utf-8")
        assert "purpleforge-tfstate" in backend, f"{provider}: fresh generate must write the placeholder backend"


def test_committed_terraform_tfvars_carries_no_infra_secret(tmp_path):
    """The shareable terraform.tfvars.json must stay secret-free — admin/ansible
    passwords live only in the gitignored secrets.auto.tfvars.json overlay."""
    out = _generate(tmp_path, vulns=["kerberoasting"])
    tfvars_text = (out / "terraform" / "azure" / "terraform.tfvars.json").read_text(encoding="utf-8")
    assert "admin_password" not in tfvars_text
    assert "ansible_password" not in tfvars_text
    # the actual seed-derived admin secret must not leak into the shareable tfvars.
    admin_pw, _ = forge.derive_infra_secrets(1)  # make_spec default seed
    assert admin_pw not in tfvars_text


_LIFECYCLE = ("deploy.sh", "start.sh", "stop.sh", "reset.sh", "rollback.sh", "restart.sh", "teardown.sh")


@pytest.mark.parametrize("provider", ["azure", "aws", "proxmox"])
def test_lifecycle_scripts_contracts(tmp_path, provider):
    """The five operator scripts (+ rollback/restart) are rendered for every
    provider, valid bash, take the lab dir as an argument, and keep their
    contracts: start never applies, stop/reset never touch terraform state,
    teardown confirms (or --force) and purges local residue."""
    out = _generate(tmp_path, provider=provider, members=1, vulns=["kerberoasting"])
    bash = shutil.which("bash")
    text = {}
    for name in _LIFECYCLE:
        path = out / name
        assert path.exists(), f"{name} not generated for {provider}"
        text[name] = path.read_text(encoding="utf-8")
        assert "{%" not in text[name] and "{{" not in text[name], f"{name}: unrendered jinja"
        if bash:
            assert subprocess.run([bash, "-n", str(path)]).returncode == 0, f"{name} ({provider}) is not valid bash"
    for name in ("deploy.sh", "stop.sh", "teardown.sh"):
        assert 'pf_resolve_lab_dir "$@"' in text[name]
    # deploy: outputs -> JSON + connectivity check; sourceable by start/reset
    assert "pf_export_outputs" in text["deploy.sh"] and "pf_check_connectivity" in text["deploy.sh"]
    assert 'if [ "${BASH_SOURCE[0]}" = "$0" ]; then' in text["deploy.sh"]
    # start: sources deploy.sh but never runs apply/tf_apply
    assert "/deploy.sh" in text["start.sh"] and "tf_apply" not in text["start.sh"]
    start_body = text["start.sh"].split("start_main() {", 1)[1]
    assert "terraform -chdir" not in start_body and "apply -auto-approve" not in start_body
    assert "pf_check_connectivity" in text["start.sh"]
    # stop / reset: no terraform at all, no power-off in reset
    # (strip the shared helper library: it DEFINES pf_export_outputs, stop never calls it)
    stop_own = text["stop.sh"].split("# ---- end shared lifecycle helpers", 1)[1]
    assert "terraform -chdir" not in stop_own and "pf_export_outputs" not in stop_own
    reset_body = text["reset.sh"].split("reset_main() {", 1)[1]
    assert "run_site" in reset_body and "tf_apply" not in reset_body
    for verb in ("stop_vms", "stop-instances", "/deallocate", "status/stop", "terraform destroy", "forge destroy"):
        assert verb not in reset_body
    assert "--snapshot" in text["reset.sh"] and "rollback.sh" in text["reset.sh"]
    # teardown: confirmation + purge of local residue
    assert "confirm_teardown" in text["teardown.sh"] and "--force" in text["teardown.sh"]
    assert "purge_local" in text["teardown.sh"] and ".terraform" in text["teardown.sh"]


def test_teardown_refuses_without_confirmation(tmp_path):
    """Non-interactive stdin and no --force -> teardown dies BEFORE destroying."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    repo = tmp_path / "repo"
    (repo / "vendor").mkdir(parents=True)
    out = repo / "generated" / "lab"
    spec_file = write_spec(tmp_path, make_spec(provider="proxmox", region="node-1", members=1, vulns=["kerberoasting"]))
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    env = {"PATH": "/usr/bin:/bin", "PROXMOX_VE_ENDPOINT": "https://pve.invalid:8006/", "PROXMOX_VE_API_TOKEN": "x"}
    r = subprocess.run([bash, str(out / "teardown.sh"), str(out)], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, env=env)
    assert r.returncode != 0
    assert "without confirmation" in r.stderr and "--force" in r.stderr
