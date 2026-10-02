"""mssql_hardening pf_controls toggle — reconciliation contract.

mssql_hardening is a real FIXED_HARDENING_TOGGLES control (not a free label): when
a lab selects it AND carries mssql-weak-sa, on_conflict:exclude-control must force
it off so the gap stays open; without the vuln it stays on (a hardened SQL box).
"""

from __future__ import annotations

from _helpers import resolve_spec


def _resolve(tmp_path, **kw):
    return resolve_spec(tmp_path, **kw)


def _excluded_controls(manifest):
    return {c.get("control") for c in manifest["reconciliation"].get("excluded_controls", [])}


def test_mssql_hardening_forced_off_when_vuln_present(tmp_path):
    m = _resolve(
        tmp_path,
        name="mssql-on-with-vuln",
        members=1,
        services=["mssql"],
        vulns=["mssql-weak-sa"],
        baseline="baseline-controls",  # sets intentional_gaps_auto=True
        controls={"mssql_hardening": True},
        on_conflict="exclude-control",
    )
    assert "mssql_hardening" in _excluded_controls(m)
    assert m["defense_resolved"]["hardening"]["controls"]["mssql_hardening"] is False


def test_mssql_hardening_stays_on_without_vuln(tmp_path):
    m = _resolve(
        tmp_path,
        name="mssql-on-no-vuln",
        members=1,
        services=["mssql"],
        vulns=[],  # no mssql-weak-sa -> nothing to neutralize -> keep the control
        baseline="baseline-controls",
        controls={"mssql_hardening": True},
        on_conflict="exclude-control",
    )
    assert "mssql_hardening" not in _excluded_controls(m)
    assert m["defense_resolved"]["hardening"]["controls"]["mssql_hardening"] is True
