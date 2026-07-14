"""Schema-shape regressions + every hand-maintained spec must resolve."""

from __future__ import annotations

import json

import forge
import pytest
from _helpers import ALL_SPECS

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


@pytest.mark.parametrize("spec_path", ALL_SPECS, ids=lambda p: p.stem)
def test_every_spec_resolves(spec_path):
    """Schema + semantic validation + reconciliation succeeds for every checked-in
    spec — this is what catches a spec left with a now-invalid field."""
    assert forge.load_and_resolve(spec_path) is not None, f"{spec_path.name} failed to resolve"
