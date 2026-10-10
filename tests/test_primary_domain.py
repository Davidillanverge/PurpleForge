"""attack_chain.primary_domain — the AD attack surface can be a child domain.

Covers the child->parent CTF feature: when primary_domain names a child domain,
the domain-object vulns cast onto that domain's population and target its DC,
instead of always defaulting to the first forest[] entry (the root). The default
(unset) behavior must stay byte-identical to the historical root placement.
"""

from __future__ import annotations

import forge
import pytest
from _helpers import make_spec

CATALOG = forge.load_vuln_catalog()

# Two population plans: root first (as the generator orders them), child second.
# Minimal shape resolve_attack_chain reads: domain, users[{name}], groups[{name,curated}].
POP_PLANS = [
    {
        "domain": "corp.local",
        "users": [{"name": f"root_u{i}"} for i in range(5)],
        "groups": [{"name": f"root_g{i}", "curated": False} for i in range(3)],
    },
    {
        "domain": "sub.corp.local",
        "users": [{"name": f"child_u{i}"} for i in range(5)],
        "groups": [{"name": f"child_g{i}", "curated": False} for i in range(3)],
    },
]

# DC machines the way plan_vuln_injection reads them (name + role + domain).
MACHINES = [
    {"name": "corp-dc01", "role": "domain-controller", "domain": "corp.local", "count": 1},
    {"name": "sub-dc01", "role": "domain-controller", "domain": "sub.corp.local", "count": 1},
]
# groups["domain_controllers"] holds only root/non-child DCs (the default path).
GROUPS = {"domain_controllers": [MACHINES[0]], "child_domain_controllers": [MACHINES[1]]}
NO_CONFLICT = {"excluded_controls": [], "warnings": []}


def _spec(primary_domain=None):
    s = make_spec(domains=2, vulns=["asreproast", "dcsync-acl"])
    s["attack_chain"] = {"mode": "ctf"}
    if primary_domain is not None:
        s["attack_chain"]["primary_domain"] = primary_domain
    return s


# ---------------------------------------------------------------- validation
def test_primary_domain_unknown_is_rejected():
    errs = forge.semantic_checks(_spec("nope.local"), CATALOG)
    assert any("primary_domain" in e and "not a domain" in e for e in errs)


def test_primary_domain_without_dc_is_rejected():
    spec = make_spec(domains=1, vulns=["asreproast"])
    # a member-only domain the forest doesn't give a DC
    spec["forest"].append(
        {"domain": "dmz.corp.local", "netbios": "DMZ", "functional_level": "2016", "domain_controllers": 0}
    )
    spec["attack_chain"] = {"mode": "ctf", "primary_domain": "dmz.corp.local"}
    errs = forge.semantic_checks(spec, CATALOG)
    assert any("primary_domain" in e and "no domain-controller" in e for e in errs)


def test_primary_domain_valid_child_passes():
    assert forge.semantic_checks(_spec("sub.corp.local"), CATALOG) == []


# ---------------------------------------------------- casting (resolve_attack_chain)
def test_cast_targets_child_population_when_primary_domain_set():
    chain = forge.resolve_attack_chain(_spec("sub.corp.local"), CATALOG, POP_PLANS, "ctf")
    cast = {s["id"]: s["cast_name"] for s in chain["steps"]}
    assert cast["asreproast"] is not None
    assert cast["asreproast"].startswith("child_"), "AD vuln must cast onto the CHILD population"
    # ctf mode reuses the same object across the chain
    assert cast["dcsync-acl"] == cast["asreproast"]


def test_cast_defaults_to_first_forest_domain():
    chain = forge.resolve_attack_chain(_spec(), CATALOG, POP_PLANS, "ctf")
    cast = {s["id"]: s["cast_name"] for s in chain["steps"]}
    assert cast["asreproast"].startswith("root_"), "default must stay on the first forest domain (root)"


# --------------------------------------------- host targeting (plan_vuln_injection)
def test_vuln_injection_targets_child_dc_when_primary_domain_set():
    planned = forge.plan_vuln_injection(
        _spec("sub.corp.local"), CATALOG, MACHINES, GROUPS, NO_CONFLICT
    )
    hosts = {p["id"]: p["run_on"] for p in planned}
    assert hosts["asreproast"] == "sub-dc01"
    assert hosts["dcsync-acl"] == "sub-dc01"


def test_vuln_injection_defaults_to_root_dc():
    planned = forge.plan_vuln_injection(_spec(), CATALOG, MACHINES, GROUPS, NO_CONFLICT)
    hosts = {p["id"]: p["run_on"] for p in planned}
    assert hosts["asreproast"] == "corp-dc01"
