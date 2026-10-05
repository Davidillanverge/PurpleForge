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
    "azure": {"stop.sh": "/deallocate?api-version", "restart.sh": "/restart?api-version"},
    "aws": {"stop.sh": "stop-instances", "restart.sh": "reboot-instances"},
    "proxmox": {"stop.sh": "status/stop", "restart.sh": "status/reset"},
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
        assert path.exists(), f"{script} not generated for {provider}"
        text = path.read_text(encoding="utf-8")
        assert marker in text, f"{script} ({provider}) missing power action {marker!r}"
        # Safety: a power control never destroys infra (that's `forge teardown`).
        assert "terraform destroy" not in text
        if bash:
            assert subprocess.run([bash, "-n", str(path)]).returncode == 0, f"{script} ({provider}) is not valid bash"


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
