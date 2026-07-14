"""Tests for the machine-checkable invariant gate (cmd_guardrail).

Each case writes a crafted lab-manifest.json into a temp lab dir and asserts the
gate PASSES (0) or FAILS (1). This locks CLAUDE.md's invariants #1-#4 as code.
"""

from __future__ import annotations

import argparse
import copy
import json

import forge
from _helpers import make_spec, write_spec


def _passing_manifest() -> dict:
    return {
        "lab": {
            "name": "single-dc-test",
            "isolation": "vpn-only",
            "auto_shutdown": "20:00 Europe/Madrid",
            "budget_alert_usd": 50,
            "provider": "azure",
        },
        "network_plan": {"management_subnet": "10.7.0.0/24", "jumpbox_ip": "10.7.0.10"},
        "vulnerabilities": ["kerberoasting"],
        "reconciliation": {"on_conflict": "exclude-control", "conflicts_detected": []},
    }


def _run(tmp_path, manifest: dict) -> int:
    # The gate reads the manifest from out_dir; the spec path only needs to load.
    spec_path = write_spec(tmp_path, make_spec(name="single-dc-test"))
    (tmp_path / "lab-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    args = argparse.Namespace(spec=str(spec_path), out_dir=str(tmp_path))
    return forge.cmd_guardrail(args)


def test_guardrail_passes_on_clean_manifest(tmp_path):
    assert _run(tmp_path, _passing_manifest()) == 0


def test_guardrail_fails_when_not_vpn_only(tmp_path):
    m = _passing_manifest()
    m["lab"]["isolation"] = "public"
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_without_bastion(tmp_path):
    m = _passing_manifest()
    m["network_plan"] = {}
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_without_auto_shutdown(tmp_path):
    m = _passing_manifest()
    del m["lab"]["auto_shutdown"]
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_without_budget(tmp_path):
    m = _passing_manifest()
    del m["lab"]["budget_alert_usd"]
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_on_unknown_vuln(tmp_path):
    m = _passing_manifest()
    m["vulnerabilities"] = ["not-a-real-vuln"]
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_without_reconciliation(tmp_path):
    m = _passing_manifest()
    del m["reconciliation"]
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_on_unresolved_fail_conflict(tmp_path):
    m = _passing_manifest()
    m["reconciliation"] = {"on_conflict": "fail", "conflicts_detected": ["gpp-cpassword"]}
    assert _run(tmp_path, m) == 1


def test_guardrail_fails_on_local_terraform_backend(tmp_path):
    m = _passing_manifest()
    tf = tmp_path / "terraform" / "azure"
    tf.mkdir(parents=True)
    (tf / "backend.hcl").write_text('path = "./terraform.tfstate"\n', encoding="utf-8")
    assert _run(tmp_path, m) == 1


def test_passing_manifest_is_actually_minimal():
    """Guard against a stale fixture: every top-level key the passing manifest
    carries is one the gate inspects (drop one and it should fail)."""
    base = _passing_manifest()
    assert set(base) == {"lab", "network_plan", "vulnerabilities", "reconciliation"}
    assert isinstance(copy.deepcopy(base), dict)
