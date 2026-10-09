"""MDE (Microsoft Defender for Endpoint) telemetry.edr provider.

Covers the plan + render wiring: MDE is its OWN agent (not folded into the
shared elastic-agent), Windows-only, onboarded from the operator's package via
a deploy-time path (MDE_WIN_ONBOARDING_PATH) — never hardcoded in the playbook.
"""

from __future__ import annotations

from types import SimpleNamespace

import forge
import pytest
from _helpers import make_spec, write_spec


def _machines():
    return [
        {"name": "dc01", "role": "domain-controller"},
        {"name": "mbr01", "role": "member-server"},
    ]


def test_mde_is_its_own_agent_not_elastic():
    spec = {"telemetry": {"edr": {"provider": "microsoft-defender", "targets": "all"}}}
    plan = forge.planning.plan_telemetry(spec, _machines())
    assert plan == {"mde": ["dc01", "mbr01"]}
    assert "elastic-agent" not in plan


def test_mde_respects_targets_and_enabled_flag():
    spec = {"telemetry": {"edr": {"provider": "microsoft-defender", "targets": ["domain-controller"]}}}
    assert forge.planning.plan_telemetry(spec, _machines()) == {"mde": ["dc01"]}
    off = {"telemetry": {"edr": {"provider": "microsoft-defender", "enabled": False}}}
    assert forge.planning.plan_telemetry(off, _machines()) == {}


def test_elastic_edr_still_one_shared_agent():
    spec = {"telemetry": {"edr": {"provider": "elastic"}, "siem": {"provider": "elastic"}}}
    plan = forge.planning.plan_telemetry(spec, _machines())
    assert set(plan) == {"elastic-agent"} and "mde" not in plan


def _gen_mde_lab(tmp_path, provider="aws", region="us-east-1"):
    spec = make_spec(provider=provider, region=region, members=1, vulns=["kerberoasting"])
    spec["telemetry"] = {"edr": {"provider": "microsoft-defender", "targets": "all"}}
    spec_file = write_spec(tmp_path, spec)
    out = tmp_path / "out"
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    return out


@pytest.mark.parametrize("provider", ["azure", "aws", "proxmox"])
def test_mde_renders_playbook_role_and_deploy_wiring(tmp_path, provider):
    region = {"azure": "eastus", "aws": "us-east-1", "proxmox": "node-1"}[provider]
    out = _gen_mde_lab(tmp_path, provider, region)

    tel = (out / "ansible" / "playbooks" / "telemetry-provisioning.yml").read_text(encoding="utf-8")
    assert "pf_mde" in tel and tel.count("mde | onboard") == 2  # one play per host

    site = (out / "ansible" / "playbooks" / "site.yml").read_text(encoding="utf-8")
    assert "telemetry-provisioning.yml" in site

    deploy = (out / "deploy.sh").read_text(encoding="utf-8")
    assert "MDE_WIN_ONBOARDING_PATH" in deploy
    assert "pf_mde_onboarding_src=/repo/" in deploy
    # the onboarding blob itself is never written into the generated playbook
    assert "WindowsDefenderATPOnboardingScript.cmd" in deploy  # referenced by path only
    role = out / "ansible"  # role resolves from the repo's templates via roles_path; not copied
    assert not (role / "roles" / "pf_mde").exists()


def test_mde_role_is_windows_only_and_requires_the_package():
    """The shipped role asserts the deploy-time package var and guards OS/service."""
    role = forge.core.TEMPLATES_DIR / "ansible" / "roles" / "pf_mde" / "tasks" / "main.yml"
    body = role.read_text(encoding="utf-8")
    assert "pf_mde_onboarding_src" in body and "ansible.builtin.assert" in body
    # health check VERIFIES read-only (Get-Service) — it must NOT try to modify the
    # Sense service with win_service/start_mode, which MDE tamper-protection denies
    # once onboarded (regression: Access Denied Win32 5, live 2026-10-09).
    assert "Get-Service Sense" in body
    # no win_service MODULE call and no start_mode PARAM (comments may mention them)
    assert "ansible.windows.win_service:" not in body
    assert "\n    start_mode:" not in body
    assert "OnboardingState" in body and "ansible.windows" in body
    # the LOCAL onboarding .cmd is interactive (set /p + pause); the run task must
    # feed "Y" on stdin and bound the run so a head-less hang fails instead of
    # blocking the deploy forever (regression: live hang 2026-10-09).
    assert '"Y" | cmd.exe /c' in body
    assert "async:" in body and "poll:" in body


def test_no_telemetry_means_no_mde(tmp_path):
    spec_file = write_spec(tmp_path, make_spec(provider="aws", region="us-east-1", members=1, vulns=["kerberoasting"]))
    out = tmp_path / "out"
    assert forge.cmd_generate(SimpleNamespace(spec=str(spec_file), out_dir=str(out), plan=False)) == 0
    assert not (out / "ansible" / "playbooks" / "telemetry-provisioning.yml").exists()
    assert "MDE_WIN_ONBOARDING_PATH" not in (out / "deploy.sh").read_text(encoding="utf-8")
