"""Catalog contract tests.

Enforce CLAUDE.md invariant #2 (every vuln ships mitigate + neutralized_by + a
valid ATT&CK id) at test time, not just at guardrail time — and lock in the
detection removal (no `detect`/SIEM block survives in any catalog entry).
"""

from __future__ import annotations

import re

import forge
import pytest

CATALOG = forge.load_vuln_catalog()
VULN_IDS = sorted(CATALOG)
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SEVERITIES = {"low", "medium", "high", "critical"}


def test_catalog_is_non_empty():
    assert VULN_IDS, "no vulnerabilities loaded from catalog/vulnerabilities/"


@pytest.mark.parametrize("vid", VULN_IDS)
def test_vuln_has_required_purple_fields(vid):
    entry = CATALOG[vid]
    assert entry.get("mitigate"), f"{vid}: missing mitigate (invariant #2)"
    assert entry.get("neutralized_by"), f"{vid}: missing neutralized_by (invariant #2)"


@pytest.mark.parametrize("vid", VULN_IDS)
def test_vuln_mitre_ids_are_well_formed(vid):
    ids = CATALOG[vid].get("attack", {}).get("mitre_attack", [])
    assert ids, f"{vid}: attack.mitre_attack is empty"
    for tid in ids:
        assert MITRE_RE.match(tid), f"{vid}: '{tid}' is not a valid ATT&CK technique id"


@pytest.mark.parametrize("vid", VULN_IDS)
def test_vuln_severity_is_known(vid):
    assert CATALOG[vid].get("severity") in SEVERITIES, f"{vid}: bad severity"


@pytest.mark.parametrize("vid", VULN_IDS)
def test_vuln_inject_playbook_exists(vid):
    playbook = CATALOG[vid].get("inject", {}).get("playbook")
    assert playbook, f"{vid}: inject.playbook is not set"
    assert (forge.REPO_ROOT / playbook).is_file(), f"{vid}: inject.playbook {playbook} does not exist"


@pytest.mark.parametrize("vid", VULN_IDS)
def test_no_detection_block_survives(vid):
    """Detection is out of scope — no catalog entry may carry a `detect` block
    or a `siem_rule` reference (regression guard for the detection removal)."""
    entry = CATALOG[vid]
    assert "detect" not in entry, f"{vid}: still carries a `detect:` block"
    assert "siem_rule" not in repr(entry), f"{vid}: still references a siem_rule"
