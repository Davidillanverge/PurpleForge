"""from-exercise translator tests.

The converter authors a lab-spec from a BAS exercise's ATT&CK Navigator layer.
These assert the invariants that must hold for ANY layer, in the test-owns-its-
inputs style: build a layer in code, run the real matcher/builder, and check the
emitted spec (a) validates against the lab-spec schema, (b) fully resolves
through load_and_resolve (semantics + reconciliation), and (c) keeps every
selected vuln's gap open — the "provably vulnerable to the exercise" guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path

import forge
import jsonschema
import pytest
import yaml

CATALOG = forge.load_vuln_catalog()
INDEX = forge.build_technique_index(CATALOG)
SCHEMA = forge.load_schema()


def write_layer(tmp_path: Path, technique_ids, name="exercise 001") -> Path:
    layer = {"name": name, "domain": "enterprise-attack", "techniques": [{"techniqueID": t} for t in technique_ids]}
    path = tmp_path / "layer.json"
    path.write_text(json.dumps(layer), encoding="utf-8")
    return path


def test_technique_index_is_derived_from_catalog():
    # Every id in the index maps back to a vuln that really carries it.
    for tech, vids in INDEX.items():
        assert vids == sorted(vids)
        for vid in vids:
            assert tech in CATALOG[vid]["attack"]["mitre_attack"], f"{vid} does not carry {tech}"
    # Every catalog technique appears in the index (nothing dropped).
    for vid, entry in CATALOG.items():
        for tech in entry["attack"]["mitre_attack"]:
            assert vid in INDEX[tech]


def test_load_navigator_layer_shapes(tmp_path):
    # dict with technique objects
    p = write_layer(tmp_path, ["T1558.003", "T1649"])
    assert forge.load_navigator_layer(p) == ["T1558.003", "T1649"]
    # top-level list of bare ids, deduped, order preserved, lowercase coerced
    p2 = tmp_path / "bare.json"
    p2.write_text(json.dumps(["t1649", "T1649", "T1003.006"]), encoding="utf-8")
    assert forge.load_navigator_layer(p2) == ["T1649", "T1003.006"]


def test_load_navigator_layer_rejects_junk(tmp_path):
    p = tmp_path / "junk.json"
    p.write_text(json.dumps({"techniques": [{"techniqueID": "not-a-technique"}]}), encoding="utf-8")
    with pytest.raises(forge.SpecError):
        forge.load_navigator_layer(p)


def test_exact_match_selects_the_carrying_vulns():
    # T1003.006 is DCSync's exact id; exact-only must select dcsync-acl and not
    # drag in anything by roll-up.
    selected, uncovered = forge.match_techniques(["T1003.006"], INDEX, exact_only=True)
    assert "dcsync-acl" in selected
    assert selected["dcsync-acl"]["match"] == "exact"
    assert uncovered == []


def test_rollup_is_broader_than_exact_and_flagged_approx():
    exact, _ = forge.match_techniques(["T1558.003"], INDEX, exact_only=True)
    rolled, _ = forge.match_techniques(["T1558.003"], INDEX, exact_only=False)
    # roll-up (sub -> parent T1558) can only add vulns, never remove them.
    assert set(exact).issubset(set(rolled))
    for vid in set(rolled) - set(exact):
        assert rolled[vid]["match"] == "approx"


def test_unknown_technique_is_reported_uncovered_not_selected():
    selected, uncovered = forge.match_techniques(["T1566.001"], INDEX)
    assert selected == {}
    assert uncovered == ["T1566.001"]


@pytest.mark.parametrize(
    "techniques",
    [
        ["T1558.003"],  # roasting -> AD only, DC-only topology
        ["T1649"],  # ADCS -> forces a member-server with services:[adcs]
        ["T1574.009"],  # unquoted-service-path -> forces a workstation
        ["T1558.003", "T1649", "T1003.006"],  # a small chain
    ],
)
def test_authored_spec_validates_and_resolves(tmp_path, techniques):
    layer = forge.load_navigator_layer(write_layer(tmp_path, techniques))
    selected, _ = forge.match_techniques(layer, INDEX)
    assert selected, "fixture techniques should map to at least one vuln"
    spec = forge.build_spec(
        selected,
        CATALOG,
        name="fixture-lab",
        theme="corporate",
        provider="azure",
        region="eastus",
        domain="corp.local",
        users=15,
        seed=7,
        density="sparse",
        budget=30,
        auto_shutdown="20:00 Europe/Madrid",
        chain_mode="independent",
    )
    # (a) schema-valid
    jsonschema.Draft202012Validator(SCHEMA).validate(spec)
    # (b) fully resolves through the real pipeline
    path = tmp_path / "authored.yml"
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    res = forge.load_and_resolve(path)
    assert res is not None, "authored spec failed to resolve (semantics/reconciliation)"
    _spec, manifest = res
    # (c) every selected vuln is actually planned into the lab
    assert set(manifest["vulnerabilities"]) == set(selected)


def test_services_and_workstation_routing():
    # ADCS vuln -> a member-server carrying services:[adcs]; no workstation.
    selected, _ = forge.match_techniques(["T1649"], INDEX, exact_only=True)
    spec = _minimal_build(selected)
    members = [m for m in spec["machines"] if m["role"] == "member-server"]
    assert members and "adcs" in members[0]["services"]
    assert not any(m["role"] == "workstation" for m in spec["machines"])

    # a workstation-local-privesc vuln -> a workstation, no member-server.
    selected_ws, _ = forge.match_techniques(["T1574.009"], INDEX, exact_only=True)
    spec_ws = _minimal_build(selected_ws)
    assert any(m["role"] == "workstation" for m in spec_ws["machines"])
    assert not any(m["role"] == "member-server" for m in spec_ws["machines"])


def test_gap_is_forced_open_so_lab_is_provably_vulnerable(tmp_path):
    # The whole point: the reconciler must keep each selected vuln's gap open.
    layer = forge.load_navigator_layer(write_layer(tmp_path, ["T1558.003", "T1003.006", "T1649"]))
    selected, _ = forge.match_techniques(layer, INDEX)
    spec = _minimal_build(selected)
    path = tmp_path / "authored.yml"
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    _spec, manifest = forge.load_and_resolve(path)
    recon = manifest["reconciliation"]
    # exclude-control resolution must never leave an unresolved conflict that
    # would silently neutralize a selected vuln.
    assert recon["on_conflict"] == "exclude-control"
    assert not recon.get("conflicts_detected") or recon.get("excluded_controls")


def test_lab_name_sanitization_always_schema_valid():
    from forge.from_exercise import _sanitize_lab_name

    for raw in ["APT-X emulation / 001!!", "", "   ", "1337", "—"]:
        name = _sanitize_lab_name(raw)
        jsonschema.Draft202012Validator(SCHEMA["$defs"]["lab"]["properties"]["name"]).validate(name)


def _minimal_build(selected: dict) -> dict:
    return forge.build_spec(
        selected,
        CATALOG,
        name="fixture-lab",
        theme="corporate",
        provider="azure",
        region="eastus",
        domain="corp.local",
        users=15,
        seed=7,
        density="sparse",
        budget=30,
        auto_shutdown="20:00 Europe/Madrid",
        chain_mode="independent",
    )
