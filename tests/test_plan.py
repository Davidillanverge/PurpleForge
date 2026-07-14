"""Unit tests for the pure deterministic-core functions in forge.py."""

from __future__ import annotations

import ipaddress

import forge
import pytest
from _helpers import FIXTURES_DIR


# ---------------------------------------------------------------- stable_octet
def test_stable_octet_deterministic_and_in_range():
    for name in ("kingdom", "raven-corp", "shire", "a", "z" * 30):
        octet = forge.stable_octet(name)
        assert octet == forge.stable_octet(name)  # deterministic
        assert 10 <= octet <= 209  # documented band


def test_stable_octet_varies_across_names():
    sample = {forge.stable_octet(n) for n in ("alpha", "bravo", "charlie", "delta", "echo")}
    assert len(sample) > 1  # not a constant


# ------------------------------------------------------------------ assign_ips
def _load(spec_name: str) -> dict:
    return forge.load_yaml(FIXTURES_DIR / spec_name)


def test_assign_ips_no_duplicate_host_ips():
    plan = forge.assign_ips(_load("two-domain-azure.yml"))
    ips = [h["ip"] for dom in plan["domains"].values() for h in dom["hosts"]]
    assert len(ips) == len(set(ips)), "duplicate host IPs in the plan"


def test_assign_ips_hosts_sit_in_their_domain_subnet():
    plan = forge.assign_ips(_load("two-domain-azure.yml"))
    for dom in plan["domains"].values():
        subnet = ipaddress.ip_network(dom["subnet"])
        for host in dom["hosts"]:
            assert ipaddress.ip_address(host["ip"]) in subnet


def test_assign_ips_jumpbox_in_management_subnet():
    plan = forge.assign_ips(_load("single-dc-azure.yml"))
    assert ipaddress.ip_address(plan["jumpbox_ip"]) in ipaddress.ip_network(plan["management_subnet"])


def test_assign_ips_overflow_raises():
    spec = {
        "lab": {"name": "overflow-lab"},
        "forest": [{"domain": "big.local"}],
        "machines": [{"domain": "big.local", "role": "workstation", "os": "windows-11-23h2", "count": 200}],
    }
    with pytest.raises(forge.SpecError):
        forge.assign_ips(spec)


# ----------------------------------------------------------------- cost model
def test_estimate_cost_scales_with_machine_count():
    spec = _load("single-dc-azure.yml")
    base = forge.estimate_cost(spec)["hourly_usd"]
    for m in spec["machines"]:
        m["count"] *= 2
    doubled = forge.estimate_cost(spec)["hourly_usd"]
    assert doubled == pytest.approx(base * 2)


def test_estimate_cost_warns_when_over_budget():
    spec = _load("single-dc-azure.yml")
    spec["lab"]["budget_alert_usd"] = 0.01  # force the daily estimate over budget
    cost = forge.estimate_cost(spec)
    assert cost["warning"] is not None
    assert "budget" in cost["warning"].lower()


# ------------------------------------------------------- parse_auto_shutdown
def test_parse_auto_shutdown_valid():
    hhmm, win_tz = forge.parse_auto_shutdown("20:00 Europe/Madrid")
    assert hhmm == "2000"
    assert win_tz  # a non-empty Windows timezone id


def test_parse_auto_shutdown_unknown_zone_raises():
    with pytest.raises(forge.SpecError):
        forge.parse_auto_shutdown("20:00 Mars/Olympus_Mons")


# ------------------------------------------------------ population counts
@pytest.mark.parametrize("density", ["sparse", "realistic", "messy"])
def test_population_counts_are_positive_ints(density):
    users, groups, computers = forge.compute_population_counts(300, density)
    assert users == 300
    assert isinstance(groups, int) and groups >= 1
    assert isinstance(computers, int) and computers >= 1


def test_population_density_orders_group_counts():
    _, sparse_g, _ = forge.compute_population_counts(300, "sparse")
    _, realistic_g, _ = forge.compute_population_counts(300, "realistic")
    _, messy_g, _ = forge.compute_population_counts(300, "messy")
    assert sparse_g < realistic_g < messy_g


# --------------------------------------------------------------- deep_merge
def test_deep_merge_override_wins_and_recurses():
    base = {"a": 1, "nested": {"x": 1, "y": 2}}
    override = {"a": 2, "nested": {"y": 3, "z": 4}}
    merged = forge.deep_merge(base, override)
    assert merged["a"] == 2
    assert merged["nested"] == {"x": 1, "y": 3, "z": 4}
    # inputs are not mutated
    assert base["a"] == 1 and base["nested"]["y"] == 2
