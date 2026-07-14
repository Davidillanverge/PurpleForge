"""Shared test helpers.

The tests own their inputs: `make_spec()` builds a valid, semantically-consistent
lab-spec dict in code, so NO example/fixture spec files need to exist and the tests
assert invariants that hold for ANY spec, not a frozen golden of specific ones.
`resolve_spec()` writes one to a temp file and runs it through the real
`load_and_resolve` (schema + semantic checks + defense resolution + IP plan + cost
+ reconciliation), returning the manifest.
"""

from __future__ import annotations

from pathlib import Path

import forge
import yaml

REPO_ROOT = Path(forge.REPO_ROOT)


def make_spec(
    *,
    name: str = "fixture",
    provider: str = "azure",
    region: str = "westeurope",
    theme: str = "corporate",
    domains: int = 1,
    trust: bool = True,
    members: int = 0,
    workstations: int = 0,
    services: list[str] | None = None,
    vulns: list[str] | None = None,
    baseline: str = "none",
    controls: dict | None = None,
    profile: str = "none",
    edr: bool = False,
    deception: int = 0,
    users: int = 10,
    density: str = "sparse",
    seed: int = 1,
    budget: int = 50,
    on_conflict: str = "warn",
    auto_shutdown: str = "20:00 Europe/Madrid",
) -> dict:
    """Build a valid lab-spec dict. Override any knob to exercise a code path;
    the forest/machines stay internally consistent (DC counts match, trusts
    reference a real domain, services land on the member server)."""
    dom0 = "corp.local"
    forest = [{"domain": dom0, "netbios": "CORP", "functional_level": "2016", "domain_controllers": 1}]
    machines = [{"role": "domain-controller", "os": "windows-server-2019", "domain": dom0, "count": 1}]
    if domains >= 2:
        dom1 = "sub.corp.local"
        entry = {"domain": dom1, "netbios": "SUB", "functional_level": "2016", "domain_controllers": 1}
        if trust:
            entry["trust"] = {"target": dom0, "type": "parent-child"}
        forest.append(entry)
        machines.append({"role": "domain-controller", "os": "windows-server-2019", "domain": dom1, "count": 1})
    if members:
        member = {"role": "member-server", "os": "windows-server-2022", "domain": dom0, "count": members}
        if services:
            member["services"] = list(services)
        machines.append(member)
    if workstations:
        machines.append({"role": "workstation", "os": "windows-11-23h2", "domain": dom0, "count": workstations})

    defense: dict = {"profile": profile}
    hardening: dict = {}
    if baseline != "none":
        hardening.update(baseline=baseline, apply_to="all", intentional_gaps_auto=True)
    if controls:
        hardening["controls"] = dict(controls)
    if hardening:
        defense["hardening"] = hardening
    if edr:
        defense["edr"] = [{"product": "defender-av", "mode": "enabled", "targets": "all"}]
    if deception:
        defense["deception"] = {"honey_accounts": deception}

    return {
        "lab": {
            "name": name,
            "theme": theme,
            "provider": provider,
            "region": region,
            "isolation": "vpn-only",
            "auto_shutdown": auto_shutdown,
            "budget_alert_usd": budget,
        },
        "forest": forest,
        "machines": machines,
        "population": {"users": users, "density": density, "seed": seed},
        "vulnerabilities": list(vulns or []),
        "defense": defense,
        "on_conflict": on_conflict,
        "validation": {"bloodhound": False, "pingcastle": False, "atomic_red_team": []},
    }


def write_spec(tmp_path: Path, spec: dict, name: str = "spec.yml") -> Path:
    """Serialize a spec dict to a temp .yml so it goes through the real YAML path."""
    path = tmp_path / name
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    return path


def resolve_spec(tmp_path: Path, **kwargs) -> dict:
    """make_spec(**kwargs) -> temp file -> load_and_resolve -> manifest. Asserts it
    resolves (schema + semantics + reconciliation all pass)."""
    res = forge.load_and_resolve(write_spec(tmp_path, make_spec(**kwargs)))
    assert res is not None, "spec failed to resolve"
    return res[1]
