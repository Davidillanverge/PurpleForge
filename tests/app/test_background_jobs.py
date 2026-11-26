"""Long forge calls of agent runs as detached background jobs (agents.background) and
the run console's steps panel (api.run_steps).

The deploy that motivated this: a `forge deploy` run as one blocking MCP tool call was
abandoned by the brain's MCP client (Copilot ~3 min, Claude 30 min) and killed
mid-Ansible. Now the call returns at once, the job streams its output into the run,
and the run's outcome waits for the job's real exit code."""

from __future__ import annotations

import asyncio
import stat
import uuid

import httpx
import pytest
from _appkit import ALICE, seed_lab
from _fakes import ScriptedLLM, call, reply
from test_ui import login

from agents import background
from agents.engine import AgentEngine
from agents.tools import ForgeTool
from api.registry import AgentSpec, PreparedRun, _deploy_outcome
from api.run_steps import forge_steps
from db.states import LabState

LAB = "winrm-validate-lab"

DEPLOY_OUTPUT = """\
\x1b[1;35m== 0. Preflight\x1b[0m
  account: 123
== 3. terraform init + apply
  apply complete
== 6. Provision AD -> population -> hardening -> vuln injection (site.yml)
PLAY [Promote DCs] *************************************************************
TASK [domain_controller : install AD DS] ***************************************
changed: [dc01]
TASK [pf_vulns : kerberoasting] ************************************************
fatal: [dc01]: FAILED! => {"msg": "boom"}
PLAY RECAP *********************************************************************
dc01                       : ok=41   changed=26   unreachable=0    failed=1    skipped=12   rescued=0    ignored=0
WARN: could not snapshot dc01 (continuing)
"""


@pytest.fixture
def fake_forge(tmp_path):
    """`<it> -m forge deploy …`: prints phases slowly, exits $PF_FAKE_EXIT (default 0)."""
    script = tmp_path / "fake-python"
    script.write_text(
        "#!/bin/sh\n"
        'echo "== 0. Preflight"\n'
        "sleep 0.3\n"
        'echo "== 6. Provision AD -> population -> hardening -> vuln injection (site.yml)"\n'
        'echo "PLAY [Promote DCs] ****"\n'
        'echo "TASK [install AD DS] ****"\n'
        "sleep 0.3\n"
        'echo "== DEPLOY COMPLETE — lab"\n'
        'exit "${PF_FAKE_EXIT:-0}"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.fixture
def make_bg_app(make_app, tmp_path, repo_root, fake_forge):
    """An app whose `bg-deployer` agent calls `forge deploy` once and ends its turn at once —
    the brain "giving up" while the deploy still runs."""

    def prepare(ctx):
        forge = ForgeTool(
            repo_root,
            allowed_subcommands={"deploy"},
            spec_lock=f"specs/{LAB}.yml",
            python=str(fake_forge),
        )
        engine = AgentEngine(
            ctx.llm,
            [forge, background.make_forge_wait_tool()],
            system_prompt="s",
            agent_name="bg-deployer",
            on_event=ctx.on_event,
            approver=ctx.approver,
        )
        return PreparedRun(task="bg deploy", execute=lambda run_id: engine.run("deploy", run_id=run_id))

    spec = AgentSpec(
        name="bg-deployer",
        description="test",
        prepare=prepare,
        allowed_states=frozenset({LabState.APPROVED}),
        running_state=LabState.DEPLOYING,
        failure_state=LabState.FAILED,
        outcome=_deploy_outcome,
    )
    return lambda: make_app(registry={spec.name: spec})


async def _start(app, llms, *, wait_call: bool):
    script = [reply("", call("forge", "d1", subcommand="deploy", args=[f"specs/{LAB}.yml"]))]
    if wait_call:
        script.append(reply("", call("forge_wait", "w1", job="d1", wait_seconds=30)))
    script.append(reply("done"))
    llms.items.append(ScriptedLLM(*script))
    lab = await seed_lab(app, LAB, LabState.APPROVED)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
        r = await c.post("/api/runs", json={"agent": "bg-deployer", "lab_id": str(lab.id)})
        assert r.status_code in (200, 201, 202), r.text
        run_id = r.json()["id"]
        for _ in range(500):  # the human approves the deploy, as in the real deploy-operator
            pending = (await c.get("/api/approvals")).json()
            if pending:
                await c.post(f"/api/approvals/{pending[0]['id']}/decision", json={"approved": True})
                break
            await asyncio.sleep(0.01)
        await app.state.runner.wait(uuid.UUID(run_id))
        run = (await c.get(f"/api/runs/{run_id}")).json()
        lab_out = (await c.get(f"/api/labs/{lab.id}")).json()
        events = (await c.get(f"/api/runs/{run_id}/events")).json()
    return run, lab_out, events


async def test_brain_giving_up_doesnt_fail_a_running_deploy(make_bg_app, llms):
    app = make_bg_app()
    async with app.router.lifespan_context(app):
        run, lab, events = await _start(app, llms, wait_call=False)
    results = [e["data"] for e in events if e["type"] == "tool_result" and e["data"]["id"] == "d1"]
    assert results[0]["data"]["background"] and results[0]["data"]["exit_code"] is None  # returned at once
    assert results[-1]["data"]["final"] and results[-1]["data"]["exit_code"] == 0  # the job's real result
    out = "".join(e["data"]["content"] for e in events if e["type"] == "tool_output")
    assert "== 6. Provision AD" in out and "DEPLOY COMPLETE" in out  # streamed into the run
    # the agent ended before the deploy did, yet the lab follows forge's exit code
    assert lab["state"] == "deployed" and run["status"] == "completed"


async def test_failed_background_deploy_fails_the_lab(make_bg_app, llms, monkeypatch):
    monkeypatch.setenv("PF_FAKE_EXIT", "2")
    app = make_bg_app()
    async with app.router.lifespan_context(app):
        _, lab, _ = await _start(app, llms, wait_call=False)
    assert lab["state"] == "failed"  # approved infra action ran and exited non-zero


async def test_forge_wait_reports_the_finished_job(make_bg_app, llms):
    app = make_bg_app()
    async with app.router.lifespan_context(app):
        _, lab, events = await _start(app, llms, wait_call=True)
    waited = [e["data"] for e in events if e["type"] == "tool_result" and e["data"]["id"] == "w1"][0]
    assert not waited["is_error"] and "finished" in waited["content"] and "exit code: 0" in waited["content"]
    assert lab["state"] == "deployed"


async def test_without_a_configured_db_forge_stays_blocking(repo_root, fake_forge):
    background.configure(None)
    forge = ForgeTool(repo_root, allowed_subcommands={"deploy"}, python=str(fake_forge))
    token = background.CURRENT_CALL.set((str(uuid.uuid4()), "c1"))
    try:
        res = await forge.run(forge.Input(subcommand="deploy", args=[f"specs/{LAB}.yml"]))
    finally:
        background.CURRENT_CALL.reset(token)
    assert res.data["exit_code"] == 0 and "DEPLOY COMPLETE" in res.content


def test_is_long():
    assert background.is_long("deploy", [])
    assert background.is_long("validate", ["s.yml", "--run"]) and not background.is_long("validate", ["s.yml"])
    assert not background.is_long("generate", ["s.yml", "--plan"])


# --------------------------------------------------------------------------- steps panel


class _E:
    def __init__(self, type_, **data):
        self.type, self.data = type_, data


def test_forge_steps_parses_phases_plays_failures_and_recap():
    events = [
        _E("tool_call", id="d", name="forge", arguments={"subcommand": "deploy", "args": ["specs/x.yml"]}),
        _E("tool_result", id="d", name="forge", data={"background": True, "exit_code": None}),
        _E("tool_output", id="d", content=DEPLOY_OUTPUT),
    ]
    (st,) = forge_steps(events)
    assert st.command == "forge deploy specs/x.yml" and not st.finished
    assert [p.title for p in st.phases] == [
        "0. Preflight",
        "3. terraform init + apply",
        "6. Provision AD -> population -> hardening -> vuln injection (site.yml)",
    ]
    assert [p.status for p in st.phases] == ["done", "done", "running"]
    assert st.current_play == "Promote DCs" and st.current_task == "pf_vulns : kerberoasting"
    assert st.phases[-1].tasks == 2 and st.failures and "kerberoasting @ dc01" in st.failures[0]
    assert st.recap[0].host == "dc01" and st.recap[0].failed == 1
    assert st.warnings == ["WARN: could not snapshot dc01 (continuing)"]

    events.append(_E("tool_result", id="d", name="forge", data={"background": True, "final": True, "exit_code": 1}))
    (st,) = forge_steps(events)
    assert st.finished and not st.ok and st.phases[-1].status == "failed"


async def test_run_console_shows_the_steps_panel(make_bg_app, llms):
    app = make_bg_app()
    async with app.router.lifespan_context(app):
        run, _, _ = await _start(app, llms, wait_call=False)
        ui = await login(app)
        page = (await ui.get(f"/runs/{run['id']}")).text
        part = await ui.get(f"/ui/partials/runs/{run['id']}/steps")
        await ui.aclose()
    assert "pasos — " in page and "forge deploy specs/winrm-validate-lab.yml" in page
    assert "0. Preflight" in part.text and "✔ exit 0" in part.text
