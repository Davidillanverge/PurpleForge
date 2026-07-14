"""Invariant tests for the resolved manifest — they hold for ANY spec, so the
tests build their own inputs with make_spec() instead of comparing a frozen golden
of specific example specs. Covers the IP plan, reconciliation, cost, defense
resolution, population, and determinism (CLAUDE.md invariant #5).
"""

from __future__ import annotations

import ipaddress

import forge
import pytest
from _helpers import make_spec, resolve_spec, write_spec

# A spread of shapes across the manifest code paths: providers, single/multi-domain
# (+ trust), member servers with services, workstations.
SHAPES = [
    {"provider": "azure", "domains": 1},
    {"provider": "azure", "domains": 2, "members": 1, "services": ["adcs", "mssql"], "workstations": 2},
    {"provider": "aws", "domains": 1, "members": 1, "services": ["iis", "mssql"], "workstations": 3},
    {"provider": "proxmox", "domains": 1, "workstations": 1},
]


# --------------------------------------------------------------------- IP plan
@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: f"{s['provider']}-{s.get('domains',1)}dom")
def test_ip_plan_is_internally_consistent(tmp_path, shape):
    plan = resolve_spec(tmp_path, **shape)["network_plan"]
    supernet = ipaddress.ip_network(plan["supernet"])
    ips = []
    for dom in plan["domains"].values():
        subnet = ipaddress.ip_network(dom["subnet"])
        assert subnet.subnet_of(supernet), "domain subnet escapes the supernet"
        for host in dom["hosts"]:
            assert ipaddress.ip_address(host["ip"]) in subnet, "host outside its domain subnet"
            ips.append(host["ip"])
    assert len(ips) == len(set(ips)), "duplicate host IPs across the plan"
    mgmt = ipaddress.ip_network(plan["management_subnet"])
    assert mgmt.subnet_of(supernet)
    assert ipaddress.ip_address(plan["jumpbox_ip"]) in mgmt, "jumpbox not in the management subnet"


def test_two_domains_get_distinct_subnets(tmp_path):
    plan = resolve_spec(tmp_path, domains=2)["network_plan"]
    subnets = {d["subnet"] for d in plan["domains"].values()}
    assert len(subnets) == 2


# ------------------------------------------------------------------ determinism
def test_same_spec_resolves_identically(tmp_path):
    """Invariant #5: the resolved manifest is a pure function of the spec."""
    kw = {"domains": 2, "members": 1, "services": ["adcs"], "vulns": ["kerberoasting"], "baseline": "cis-l1"}
    first = resolve_spec(tmp_path, **kw)
    second = resolve_spec(tmp_path, **kw)
    assert first == second


# --------------------------------------------------------------- reconciliation
def test_conflict_is_excluded_under_exclude_control(tmp_path):
    m = resolve_spec(tmp_path, vulns=["gpp-cpassword"], baseline="cis-l1", on_conflict="exclude-control")
    assert m["reconciliation"]["excluded_controls"], "cis-l1 ⟷ gpp-cpassword should exclude a control"


def test_conflict_only_warns_under_warn(tmp_path):
    m = resolve_spec(tmp_path, vulns=["gpp-cpassword"], baseline="cis-l1", on_conflict="warn")
    assert m["reconciliation"]["warnings"], "warn should record the conflict"
    assert not m["reconciliation"]["excluded_controls"], "warn must change nothing"


def test_fixed_toggle_conflict_flips_the_control(tmp_path):
    m = resolve_spec(
        tmp_path,
        members=1,
        vulns=["unconstrained-delegation"],
        baseline="cis-l2",
        controls={"lsa_protection": True},
        on_conflict="exclude-control",
    )
    assert m["reconciliation"]["excluded_controls"], "lsa_protection ⟷ unconstrained-delegation not reconciled"
    assert m["defense_resolved"]["hardening"]["controls"]["lsa_protection"] is False, "toggle not flipped off"


def test_no_conflict_leaves_reconciliation_empty(tmp_path):
    m = resolve_spec(tmp_path, vulns=["kerberoasting"], baseline="none", on_conflict="exclude-control")
    assert not m["reconciliation"]["excluded_controls"]
    assert not m["reconciliation"]["warnings"]


def test_on_conflict_fail_aborts_resolution(tmp_path):
    """on_conflict: fail with a real conflict returns None (no manifest)."""
    spec = make_spec(vulns=["gpp-cpassword"], baseline="cis-l1", on_conflict="fail")
    assert forge.load_and_resolve(write_spec(tmp_path, spec)) is None


# ----------------------------------------------------------------------- cost
def test_cloud_costs_money_and_proxmox_is_free(tmp_path):
    assert resolve_spec(tmp_path, provider="azure")["cost_estimate"]["estimated_monthly_usd"] > 0
    assert resolve_spec(tmp_path, provider="aws")["cost_estimate"]["estimated_monthly_usd"] > 0
    assert resolve_spec(tmp_path, provider="proxmox")["cost_estimate"]["estimated_monthly_usd"] == 0


def test_cost_flags_over_budget(tmp_path):
    m = resolve_spec(tmp_path, members=2, workstations=3, budget=1)
    assert m["cost_estimate"]["warning"] and "budget" in m["cost_estimate"]["warning"].lower()


# ------------------------------------------------------------ defense resolution
def test_profile_defaults_resolve(tmp_path):
    """The realistic profile fills in an EDR + hardening baseline even when the
    spec's defense block only names the profile."""
    spec = make_spec()
    spec["defense"] = {"profile": "realistic"}
    m = forge.load_and_resolve(write_spec(tmp_path, spec))[1]
    resolved = m["defense_resolved"]
    assert resolved["edr"], "realistic profile should resolve an EDR entry"
    assert resolved["hardening"]["baseline"] != "none", "realistic profile should set a hardening baseline"


# ------------------------------------------------------------------- population
@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: f"{s['provider']}-{s.get('domains',1)}dom")
def test_population_config_is_carried(tmp_path, shape):
    """The manifest carries the population config (the per-domain plans are
    computed later, in generate)."""
    pop = resolve_spec(tmp_path, users=20, density="realistic", **shape)["population"]
    assert pop["users"] == 20
    assert pop["density"] == "realistic"
