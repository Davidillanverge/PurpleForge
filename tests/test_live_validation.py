"""Unit tests for the live-validation output parsers and result merging.

These pure functions (in forge.validate) turn raw nxc/netexec/WinRM console
output into APPLIED/EXPLOITABLE verdicts and findings — exactly where a subtle
parsing bug silently mislabels a vuln. They take strings/dicts, so they test
without any live host.
"""

from __future__ import annotations

import forge
import pytest


# ---------------------------------------------------------------- _winrm_check_result
@pytest.mark.parametrize(
    "out, expected",
    [
        ("WINRM   10.0.0.5   5985   DC01   PF_CHECK:True", True),
        ("banner noise\nPF_CHECK:False\nmore noise", False),
        ("auth failed, nothing ran", None),
        ("", None),
        # True wins if (pathologically) both appear — first match in line order.
        ("PF_CHECK:True\nPF_CHECK:False", True),
    ],
)
def test_winrm_check_result(out, expected):
    assert forge.validate._winrm_check_result(out) is expected


# --------------------------------------------------------------- _nxc_query_nonempty
def test_nxc_query_nonempty_true_on_dn_markers():
    out = "LDAP   10.0.0.5   389   DC01\nLDAP   10.0.0.5   389   DC01   CN=svc-gmsa,CN=Managed Service Accounts,DC=corp,DC=local"
    assert forge.validate._nxc_query_nonempty(out) is True


def test_nxc_query_nonempty_false_on_banner_only():
    out = "LDAP   10.0.0.5   389   DC01   [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local)"
    assert forge.validate._nxc_query_nonempty(out) is False


# ------------------------------------------------------------------ _live_command
def test_live_command_never_echoes_admin_password():
    """The copy-pasteable command uses a <PASS> placeholder for the real admin
    secret — the one exception (mssql sa, a deliberately-weak known cred) is
    handled by its own branch, tested separately."""
    cmd = forge.validate._live_command("kerberoasting", "10.0.0.10", "corp.local", "Administrator")
    assert "<PASS>" in cmd and "--kerberoasting" in cmd


def test_live_command_mssql_prints_the_weak_sa_password():
    cmd = forge.validate._live_command(
        "mssql-weak-sa", "10.0.0.10", "corp.local", "Administrator", target_ip="10.0.1.50", password="Password123!"
    )
    assert "Password123!" in cmd and "mssql" in cmd


# ------------------------------------------------------------ merge_validation_results
def _row(vid="kerberoasting"):
    return {"id": vid, "mitre": "T1558.003", "run_on": "dc01", "applied_signature": "SPN present"}


def test_merge_flags_not_applied_as_finding():
    rows = [_row()]
    results = {"vulns": [{"id": "kerberoasting", "applied": "NO", "exploitable": "NO", "evidence": "no SPN"}]}
    confirmed, findings = forge.merge_validation_results(rows, results)
    assert confirmed[0]["applied"] == "NO"
    assert any("NOT applied" in f for f in findings)


def test_merge_flags_applied_but_not_exploitable():
    rows = [_row()]
    results = {"vulns": [{"id": "kerberoasting", "applied": "YES", "exploitable": "NO", "evidence": "AES only"}]}
    _, findings = forge.merge_validation_results(rows, results)
    assert any("NOT exploitable" in f for f in findings)


def test_merge_missing_result_is_pending_finding():
    rows = [_row()]
    confirmed, findings = forge.merge_validation_results(rows, {"vulns": []})
    assert confirmed[0]["applied"] == "PENDING"
    assert any("no live result" in f for f in findings)


def test_merge_rejects_invalid_result_value():
    rows = [_row()]
    bad = {"vulns": [{"id": "kerberoasting", "applied": "MAYBE", "exploitable": "YES"}]}
    with pytest.raises(forge.SpecError):
        forge.merge_validation_results(rows, bad)


def test_merge_clean_run_has_no_findings():
    rows = [_row()]
    good = {"vulns": [{"id": "kerberoasting", "applied": "YES", "exploitable": "YES", "evidence": "hash cracked"}]}
    _, findings = forge.merge_validation_results(rows, good)
    assert findings == []


# ------------------------------------------------------------------ build_vuln_check
def test_build_vuln_check_pulls_account_and_password_from_vars():
    planned = {
        "id": "kerberoasting",
        "mitre": "T1558.003",
        "run_on": "dc01",
        "neutralization": "clear (no selected hardening control neutralizes this vuln)",
        "vars": {"vuln_kerberoast_account": "svc-report", "vuln_kerberoast_password": "Password123!"},
    }
    catalog_entry = {"validate": {"bloodhound_edge": "HasSPN", "atomic": "T1558.003"}}
    check = forge.build_vuln_check(planned, catalog_entry)
    assert check["account"] == "svc-report"
    assert check["password"] == "Password123!"
    assert check["applied_signature"] == "HasSPN"
    # neutralization label is trimmed to the leading clause (before the parenthetical).
    assert check["neutralization"] == "clear"
