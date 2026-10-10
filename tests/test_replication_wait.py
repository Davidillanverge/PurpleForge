"""Multi-DC / multi-domain labs gate vuln-injection on AD replication convergence.

A lone DC in a single domain has no replication partners, so the gate is omitted;
with >1 DC in a domain or >1 domain (cross-domain GC/trust) it is rendered and
imported between hardening and vuln-injection.
"""

from __future__ import annotations

import forge
from _helpers import make_spec


def test_needs_replication_wait_single_dc_single_domain_false():
    assert forge.needs_replication_wait(make_spec(domains=1)) is False


def test_needs_replication_wait_two_domains_true():
    assert forge.needs_replication_wait(make_spec(domains=2)) is True


def test_needs_replication_wait_multi_dc_single_domain_true():
    spec = make_spec(domains=1)
    spec["forest"][0]["domain_controllers"] = 2
    spec["machines"].append(
        {"role": "domain-controller", "os": "windows-server-2019", "domain": "corp.local", "count": 1}
    )
    assert forge.needs_replication_wait(spec) is True


def test_gate_rendered_and_imported_for_multi_domain(tmp_path):
    forge.render_replication_convergence(tmp_path)
    pb = tmp_path / "ansible" / "playbooks" / "replication-convergence.yml"
    assert pb.exists()
    body = pb.read_text()
    # targets every DC group and polls until converged
    assert "domain_controllers:child_domain_controllers:domain_controllers_additional" in body
    assert "REPL-CONVERGED" in body and "until:" in body


def test_site_playbook_imports_gate_before_vuln_injection(tmp_path):
    forge.render_site_playbook(
        has_vuln_injection=True,
        has_service_provisioning=False,
        out_dir=tmp_path,
        has_replication_wait=True,
    )
    site = (tmp_path / "ansible" / "playbooks" / "site.yml").read_text()
    assert "replication-convergence.yml" in site
    assert site.index("replication-convergence.yml") < site.index("vuln-injection.yml")


def test_site_playbook_omits_gate_when_not_needed(tmp_path):
    forge.render_site_playbook(
        has_vuln_injection=True,
        has_service_provisioning=False,
        out_dir=tmp_path,
        has_replication_wait=False,
    )
    site = (tmp_path / "ansible" / "playbooks" / "site.yml").read_text()
    assert "replication-convergence.yml" not in site
