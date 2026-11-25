"""role: standalone — no-AD (workgroup) labs.

A lab may omit forest[] entirely when every machine is role: standalone. Such a
host is never promoted or domain-joined: it lands on its own STANDALONE_SEGMENT
subnet, gets no AD population, and only the non-AD phases (hardening controls,
EDR, telemetry, BAS) run on it. AD-only defenses and vulns are rejected up front
rather than silently dropped.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import forge
import pytest
import yaml
from _helpers import make_spec, write_spec


def _standalone_spec(provider: str = "aws", **overrides) -> dict:
    spec = make_spec(provider=provider, region="eu-west-1" if provider == "aws" else "westeurope")
    del spec["forest"]
    spec["machines"] = [{"role": "standalone", "os": "windows-server-2022", "count": 1}]
    spec["defense"] = {
        "profile": "none",
        "hardening": {"baseline": "baseline-controls", "apply_to": "all", "controls": {"laps": False}},
        "edr": [{"product": "defender-av", "mode": "enabled", "targets": "all"}],
    }
    spec["telemetry"] = {"edr": {"provider": "elastic", "enabled": True}, "siem": {"provider": "elastic", "enabled": True}}
    spec["bas"] = {"caldera": {"enabled": True, "targets": "all"}}
    spec.update(overrides)
    return spec


def _generate(tmp_path, spec: dict):
    out = tmp_path / "out"
    spec_file = write_spec(tmp_path, spec)
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    return out


def test_standalone_lab_resolves_without_forest(tmp_path):
    res = forge.load_and_resolve(write_spec(tmp_path, _standalone_spec()))
    assert res is not None
    spec, manifest = res
    assert spec["forest"] == []
    np = manifest["network_plan"]
    assert list(np["domains"]) == [forge.STANDALONE_SEGMENT]
    assert np["domains"][forge.STANDALONE_SEGMENT]["hosts"][0]["role"] == "standalone"


def test_schema_rejects_domain_on_standalone_and_requires_it_elsewhere():
    schema = forge.load_schema()
    bad = _standalone_spec()
    bad["machines"][0]["domain"] = "corp.local"
    assert forge.validate_schema(bad, schema), "standalone with a domain must fail the schema"

    no_dom = make_spec()
    del no_dom["machines"][0]["domain"]
    assert forge.validate_schema(no_dom, schema), "a DC without a domain must fail the schema"


def test_standalone_rejects_vulns(tmp_path):
    assert forge.load_and_resolve(write_spec(tmp_path, _standalone_spec(vulnerabilities=["kerberoasting"]))) is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["hardening"]["controls"].update(laps=True),
        lambda d: d["hardening"]["controls"].update(protected_users_group=["bob"]),
        lambda d: d.update(deception={"honey_accounts": 1}),
    ],
)
def test_standalone_rejects_ad_only_defenses(tmp_path, mutate):
    spec = _standalone_spec()
    mutate(spec["defense"])
    assert forge.load_and_resolve(write_spec(tmp_path, spec)) is None


@pytest.mark.parametrize("provider", ["aws", "azure"])
def test_standalone_generate(tmp_path, provider):
    out = _generate(tmp_path, _standalone_spec(provider=provider))

    inv = yaml.safe_load((out / "ansible" / "inventory" / "hosts.yml").read_text(encoding="utf-8"))
    children = inv["all"]["children"]
    assert set(children) == {"standalone_servers"}, "a no-AD lab must have no AD inventory group"
    assert list(children["standalone_servers"]["hosts"]) == ["srv01"]

    site = (out / "ansible" / "playbooks" / "site.yml").read_text(encoding="utf-8")
    assert "ad-population.yml" not in site, "no forest -> no AD population phase"
    assert "vuln-injection.yml" not in site
    for phase in ("ad-topology.yml", "defensive-controls.yml", "telemetry-provisioning.yml", "bas-provisioning.yml"):
        assert phase in site

    tfvars = json.loads((out / "terraform" / provider / "terraform.tfvars.json").read_text(encoding="utf-8"))
    assert list(tfvars["domains"]) == [forge.STANDALONE_SEGMENT]
    (machine,) = tfvars["machines"]
    assert machine["role"] == "standalone" and machine["domain"] == forge.STANDALONE_SEGMENT
    # Every role a template keys by must exist in its role maps.
    windows_tf = (out / "terraform" / provider / "windows.tf").read_text(encoding="utf-8")
    assert '"standalone"' in windows_tf
    assert "standalone" in tfvars["endpoint_probes"]

    for f in ("telemetry-provisioning.yml", "bas-provisioning.yml"):
        assert "srv01" in (out / "ansible" / "playbooks" / f).read_text(encoding="utf-8")


def test_standalone_hosts_coexist_with_a_domain(tmp_path):
    """A standalone host can sit beside an AD forest on its own segment."""
    spec = make_spec(provider="aws", region="eu-west-1")
    spec["machines"].append({"role": "standalone", "os": "windows-server-2022", "count": 1})
    res = forge.load_and_resolve(write_spec(tmp_path, spec))
    assert res is not None
    _, manifest = res
    assert list(manifest["network_plan"]["domains"]) == ["corp.local", forge.STANDALONE_SEGMENT]
    machines = forge.flatten_machines(res[0], manifest["network_plan"])
    names = {m["name"]: m for m in machines}
    assert names["workgroup-srv01"]["domain"] == forge.STANDALONE_SEGMENT
    groups = forge.build_ansible_groups(res[0], machines, "pw")
    assert [h["name"] for h in groups["standalone_servers"]] == ["workgroup-srv01"]
    assert [h["name"] for h in groups["domain_controllers"]] == ["corp-dc01"]
