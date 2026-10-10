"""ctf attack chains must make sense (chain.role).

- acquire vulns (asreproast/kerberoasting) land on DISTINCT accounts — the
  AS-REP-roastable user is never also the kerberoastable one;
- acquire/pivot accounts get a password that is actually in the attacker's
  wordlist (rockyou), or the crack stage is unsolvable;
- grant vulns are cast onto a principal compromised by an earlier stage, so the
  prior loot is the real prerequisite.
"""

from __future__ import annotations

import forge
from forge import planning
from _helpers import make_spec

CATALOG = forge.load_vuln_catalog()

POP_PLANS = [
    {
        "domain": "corp.local",
        "users": [{"name": f"u{i}"} for i in range(12)],
        "groups": [{"name": f"g{i}", "curated": False} for i in range(4)],
    }
]


def _spec(vulns, mode="ctf"):
    s = make_spec(domains=1, vulns=vulns)
    s["attack_chain"] = {"mode": mode}
    return s


def _steps(vulns, mode="ctf"):
    chain = forge.resolve_attack_chain(_spec(vulns, mode), CATALOG, POP_PLANS, mode)
    return {s["id"]: s for s in chain["steps"]}


def test_acquire_vulns_get_distinct_accounts():
    st = _steps(["asreproast", "kerberoasting"])
    assert st["asreproast"]["cast_name"] != st["kerberoasting"]["cast_name"], (
        "AS-REP and Kerberoast must not land on the same user"
    )


def test_acquire_passwords_are_in_rockyou_pool():
    st = _steps(["asreproast", "kerberoasting"])
    for vid in ("asreproast", "kerberoasting"):
        assert st[vid]["cast_password"] in planning.ROCKYOU_CRACKABLE


def test_grant_reuses_a_compromised_principal():
    # asreproast compromises an account; dcsync-acl (grant) should be cast onto it.
    st = _steps(["asreproast", "dcsync-acl"])
    assert st["dcsync-acl"]["cast_name"] == st["asreproast"]["cast_name"]
    assert st["dcsync-acl"]["role"] == "grant"


def test_grant_grantee_is_the_latest_compromised():
    st = _steps(["asreproast", "kerberoasting", "shadow-credentials"])
    # shadow-credentials is cast onto the most recently obtained principal (kerb)
    assert st["shadow-credentials"]["cast_name"] == st["kerberoasting"]["cast_name"]


def test_rockyou_pool_entries_are_real_rockyou_lines():
    # Guard against someone adding a password that is not actually crackable.
    import pathlib

    rockyou = pathlib.Path("/usr/share/wordlists/rockyou.txt")
    if not rockyou.exists():
        import pytest

        pytest.skip("rockyou.txt not present on this host")
    present = set()
    with rockyou.open("r", encoding="latin-1") as fh:
        wanted = set(planning.ROCKYOU_CRACKABLE)
        for line in fh:
            w = line.rstrip("\n")
            if w in wanted:
                present.add(w)
                if present == wanted:
                    break
    missing = set(planning.ROCKYOU_CRACKABLE) - present
    assert not missing, f"not in rockyou.txt: {sorted(missing)}"


def test_independent_mode_keeps_acquire_distinct_too():
    st = _steps(["asreproast", "kerberoasting"], mode="independent")
    assert st["asreproast"]["cast_name"] != st["kerberoasting"]["cast_name"]
