"""Schema-shape regressions + resolution of programmatically-built specs.

No committed example specs: the tests build their inputs with make_spec() and
assert that valid ones resolve and invalid ones are rejected.
"""

from __future__ import annotations

import copy
import json

import forge
import pytest
from _helpers import make_spec, write_spec

SCHEMA = json.loads(forge.SCHEMA_PATH.read_text(encoding="utf-8"))
DEFENSE = SCHEMA["$defs"]["defense"]["properties"]


def test_no_siem_or_detection_rules_in_schema():
    assert "siem" not in DEFENSE, "defense.siem should be gone (detection out of scope)"
    assert "detection_rules" not in SCHEMA["properties"], "top-level detection_rules should be gone"


def test_profile_enum_has_no_telemetry_only():
    assert DEFENSE["profile"]["enum"] == ["none", "realistic", "hardened"]


def test_edr_product_enum_is_defender_only():
    assert DEFENSE["edr"]["items"]["properties"]["product"]["enum"] == ["defender-av"]


def test_deception_has_no_canarytokens():
    assert "canarytokens" not in DEFENSE["deception"]["properties"]


# A spread of valid shapes must pass schema + semantic validation + reconciliation.
VALID = [
    {"provider": "azure"},
    {"provider": "aws", "members": 1, "services": ["iis", "mssql"], "workstations": 3, "baseline": "cis-l2", "profile": "hardened"},
    {"provider": "proxmox", "workstations": 1, "baseline": "baseline-controls"},
    {"domains": 2, "members": 1, "services": ["adcs"], "vulns": ["kerberoasting", "adcs-esc1"], "baseline": "cis-l1",
         "profile": "realistic", "edr": True, "deception": 2, "on_conflict": "exclude-control"},
]


@pytest.mark.parametrize("kw", VALID, ids=lambda k: f"{k.get('provider','azure')}-{k.get('domains',1)}dom")
def test_valid_specs_resolve(tmp_path, kw):
    assert forge.load_and_resolve(write_spec(tmp_path, make_spec(**kw))) is not None


def test_schema_rejects_unknown_defense_profile(tmp_path):
    spec = make_spec()
    spec["defense"]["profile"] = "telemetry-only"  # not in the enum
    assert forge.load_and_resolve(write_spec(tmp_path, spec)) is None


def test_semantic_check_rejects_missing_service_host(tmp_path):
    """adcs-esc1 requires a machine offering the adcs service — a spec without one
    must fail semantic validation, not resolve."""
    spec = make_spec(vulns=["adcs-esc1"])  # no member server with services: [adcs]
    assert forge.load_and_resolve(write_spec(tmp_path, spec)) is None


def test_semantic_check_rejects_dangling_trust(tmp_path):
    spec = make_spec(domains=2)
    spec["forest"][1]["trust"]["target"] = "nonexistent.local"
    assert forge.load_and_resolve(write_spec(tmp_path, spec)) is None


def test_make_spec_is_a_pure_builder():
    """Two builds with the same args are equal and independent objects."""
    a, b = make_spec(domains=2, members=1), make_spec(domains=2, members=1)
    assert a == b and a is not b
    a["machines"].clear()
    assert b["machines"], "make_spec leaked shared state between calls"
    assert copy.deepcopy(a) == a
