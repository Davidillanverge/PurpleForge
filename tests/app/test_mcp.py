"""MCP mode: Claude Code is the LLM; the server exposes lab operations over the SAME
DB/FSM/services/ForgeTool/outcomes. Driven with fastmcp's in-memory client.

Safety in these tests: `lab_deploy` really runs `forge generate` (which renders a
real deploy.sh). Nothing runs before a human approval, so each test replaces the
rendered lifecycle script with a local stub BEFORE approving — no cloud is touched
even on a machine with cloud credentials."""

from __future__ import annotations

import asyncio
import os
import socket

import httpx
import pytest
from _appkit import ALICE
from fastmcp import Client

from agents import deploy_operator
from api.broker import EventBroker
from api.settings import AppSettings
from api.sse import StreamEnd, StreamEvent, iter_run_events
from db import repository as repo
from db.session import transaction
from db.settings import DatabaseSettings
from db.states import LabState, RunState
from mcp_server import context as mcp_context
from mcp_server.context import McpSettings, build_context, recover_mcp_orphans, worker_is_alive
from mcp_server.server import mcp

LAB = "winrm-validate-lab"
SPEC = f"specs/{LAB}.yml"
HOST = socket.gethostname()


@pytest.fixture
async def ctx(tmp_path, repo_root):
    app = AppSettings(_env_file=None, repo_root=repo_root, auto_migrate=True, approval_timeout_seconds=30)
    db = DatabaseSettings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path / 'mcp.db'}")
    c = await build_context(app, db, McpSettings(_env_file=None, actor="claude-code(test)", approval_poll_seconds=0.05))
    mcp_context.set_context(c)
    yield c
    await mcp_context.close_context()


@pytest.fixture
async def mcp_client(ctx):
    async with Client(mcp) as c:
        yield c


@pytest.fixture
def toolchain(monkeypatch):
    monkeypatch.setattr(deploy_operator.shutil, "which", lambda b: f"/usr/bin/{b}")


async def call(client, tool, **args) -> str:
    return (await client.call_tool(tool, args)).data


async def _lab(ctx, name=LAB):
    async with ctx.sessionmaker() as s:
        return await repo.get_lab_by_name(s, ctx.tenant, name)


async def _to_state(ctx, name, *states):
    async with transaction(ctx.sessionmaker) as s:
        lab = await repo.get_lab_by_name(s, ctx.tenant, name)
        for st in states:
            await repo.transition_lab(
                s, ctx.tenant, lab, st, actor="user:alice" if st is LabState.APPROVED else "system"
            )


async def _decide(ctx, *, approved: bool):
    async with ctx.sessionmaker() as s:
        pending = await repo.list_pending_approvals(s, ctx.tenant)
    assert len(pending) == 1
    async with transaction(ctx.sessionmaker) as s:  # what the dashboard does for a human
        await repo.decide_approval(s, ctx.tenant, pending[0].id, approved=approved, by="user:alice")
    return pending[0]


async def _wait_tasks(ctx):
    await asyncio.wait_for(asyncio.gather(*list(ctx.tasks.values()), return_exceptions=True), 120)


async def _transitions(ctx, name=LAB):
    lab = await _lab(ctx, name)
    async with ctx.sessionmaker() as s:
        return list(await repo.list_transitions(s, ctx.tenant, lab.id))


# --------------------------------------------------------------------------- surface


async def test_surface_tools_prompts_resources(mcp_client):
    tools = {t.name for t in await mcp_client.list_tools()}
    assert tools == {
        "lab_list",
        "lab_status",
        "approvals_pending",
        "lab_create",
        "lab_check",
        "lab_compile",
        "lab_generate",
        "lab_design_start",
        "lab_design_finish",
        "lab_deploy",
        "lab_teardown",
        "lab_validate",
    }
    assert not tools & {"bash", "write_file", "lab_approve"}  # Claude Code has its own; only a human approves
    prompts = {p.name for p in await mcp_client.list_prompts()}
    assert prompts == {"lab_designer", "deploy_operator", "purple_validator", "catalog_author"}
    prompt = (await mcp_client.get_prompt("deploy_operator", {"lab": LAB})).messages[0].content.text
    assert "NEVER run `forge deploy" in prompt and "Deploy order" in prompt  # preamble + the .md body
    assert "No labs yet" in (await mcp_client.read_resource("lab://list"))[0].text


# --------------------------------------------------------------------------- deterministic flow


async def test_create_check_compile_to_ready(mcp_client, ctx):
    assert "designed" in await call(mcp_client, "lab_create", name=LAB)
    assert (await call(mcp_client, "lab_check", lab=LAB)).startswith("OK")
    out = await call(mcp_client, "lab_compile", lab=LAB)
    assert "is now ready" in out and "PASS" in out
    status = await call(mcp_client, "lab_status", lab=LAB)
    assert "**ready**" in status and "HUMAN reviews" in status
    assert "**ready**" in (await mcp_client.read_resource(f"lab://{LAB}"))[0].text
    actors = [t.actor for t in await _transitions(ctx)]
    assert "mcp:claude-code(test)" in actors and not any(a.startswith("user:claude") for a in actors)


async def test_the_mcp_side_can_never_approve(ctx):
    assert ctx.principal.actor.startswith("mcp:")
    async with transaction(ctx.sessionmaker) as s:
        lab = await repo.create_lab(s, ctx.tenant, name="x-lab", spec_path=SPEC)
        for st in (LabState.DESIGNED, LabState.COMPILED, LabState.READY):
            await repo.transition_lab(s, ctx.tenant, lab, st, actor="system")
        with pytest.raises(repo.ActorNotAllowed):
            await repo.transition_lab(s, ctx.tenant, lab, LabState.APPROVED, actor=ctx.principal.actor)


async def test_generate_tool(mcp_client, ctx, repo_root):
    await call(mcp_client, "lab_create", name=LAB)
    out = await call(mcp_client, "lab_generate", lab=LAB)
    assert out.startswith("Generated") and "deploy.sh" in out
    assert (repo_root / "generated" / LAB / "deploy.sh").is_file()
    assert (await _lab(ctx)).state is LabState.DESIGNED


# --------------------------------------------------------------------------- design


async def test_design_start_finish(mcp_client, ctx, repo_root):
    await call(mcp_client, "lab_create", name="new-lab", description="small AD lab")
    start = await call(mcp_client, "lab_design_start", lab="new-lab", request="theme corporate")
    assert "specs/schema/lab-spec.schema.json" in start and "specs/new-lab.yml" in start and "small AD lab" in start
    assert (await _lab(ctx, "new-lab")).state is LabState.DESIGNING
    # Claude Code writes the spec with its own file tool
    (repo_root / "specs" / "new-lab.yml").write_text(
        (repo_root / SPEC).read_text().replace(f"name: {LAB}", "name: new-lab")
    )
    done = await call(mcp_client, "lab_design_finish", lab="new-lab")
    assert "new-lab → designed" in done and "check-only PASS" in done
    lab = await _lab(ctx, "new-lab")
    assert lab.state is LabState.DESIGNED and lab.spec_path == "specs/new-lab.yml"
    async with ctx.sessionmaker() as s:
        run = (await repo.list_runs(s, ctx.tenant, lab_id=lab.id))[0]
    assert (run.source, run.agent, run.status) == ("mcp", "lab-designer", RunState.COMPLETED)


async def test_design_finish_without_spec_goes_back_to_draft(mcp_client):
    await call(mcp_client, "lab_create", name="empty-lab")
    assert "ERROR" in await call(mcp_client, "lab_design_finish", lab="empty-lab")  # never started
    await call(mcp_client, "lab_design_start", lab="empty-lab")
    assert "→ draft" in await call(mcp_client, "lab_design_finish", lab="empty-lab")


# --------------------------------------------------------------------------- gated deploy / teardown


def _stub(repo_root, script: str, code: int):
    (repo_root / "generated" / LAB / script).write_text(f"#!/bin/bash\necho 'stub {script}'\nexit {code}\n")


async def _approved_lab(mcp_client, ctx):
    await call(mcp_client, "lab_create", name=LAB)
    await _to_state(ctx, LAB, LabState.COMPILED, LabState.READY, LabState.APPROVED)


async def test_deploy_waits_for_a_human_then_runs(mcp_client, ctx, repo_root, toolchain):
    await _approved_lab(mcp_client, ctx)
    reply = await call(mcp_client, "lab_deploy", lab=LAB)
    assert "Waiting for a human" in reply and "/approvals" in reply
    assert (await _lab(ctx)).state is LabState.DEPLOYING and ctx.tasks
    _stub(repo_root, "deploy.sh", 0)  # replace the real rendered script before anything can run
    approval = await _decide(ctx, approved=True)
    await _wait_tasks(ctx)
    assert (await _lab(ctx)).state is LabState.DEPLOYED
    async with ctx.sessionmaker() as s:
        events = await repo.list_events(s, ctx.tenant, approval.run_id)
        run = await repo.get_run(s, ctx.tenant, approval.run_id)
    types = [e.type for e in events]
    assert types[:3] == ["run_started", "tool_call", "tool_result"]  # forge generate before asking
    assert types.index("approval_requested") < types.index("approval_resolved") and types[-1] == "run_completed"
    assert run.source == "mcp" and run.status is RunState.COMPLETED
    assert "stub deploy.sh" in next(e for e in reversed(events) if e.type == "tool_result").data["content"]


async def test_denied_deploy_touches_nothing(mcp_client, ctx, repo_root, toolchain):
    await _approved_lab(mcp_client, ctx)
    await call(mcp_client, "lab_deploy", lab=LAB)
    _stub(repo_root, "deploy.sh", 0)
    await _decide(ctx, approved=False)
    await _wait_tasks(ctx)
    assert (await _lab(ctx)).state is LabState.READY  # never touched infra → re-approval required


async def test_failed_deploy_then_teardown(mcp_client, ctx, repo_root, toolchain):
    await _approved_lab(mcp_client, ctx)
    await call(mcp_client, "lab_deploy", lab=LAB)
    _stub(repo_root, "deploy.sh", 1)
    await _decide(ctx, approved=True)
    await _wait_tasks(ctx)
    assert (await _lab(ctx)).state is LabState.FAILED
    assert "ERROR" in await call(mcp_client, "lab_deploy", lab=LAB)  # failed → only teardown
    assert "Waiting for a human" in await call(mcp_client, "lab_teardown", lab=LAB)
    _stub(repo_root, "teardown.sh", 0)
    await _decide(ctx, approved=True)
    await _wait_tasks(ctx)
    assert (await _lab(ctx)).state is LabState.DESTROYED


async def test_deploy_refused_without_toolchain(mcp_client, ctx, monkeypatch):
    monkeypatch.setattr(deploy_operator.shutil, "which", lambda b: None)
    await _approved_lab(mcp_client, ctx)
    out = await call(mcp_client, "lab_deploy", lab=LAB)
    assert out.startswith("ERROR") and "missing on PATH" in out
    assert (await _lab(ctx)).state is LabState.APPROVED


# --------------------------------------------------------------------------- dashboard bridge + recovery


async def test_dashboard_streams_mcp_runs_live_from_the_db(mcp_client, ctx, repo_root, toolchain):
    await _approved_lab(mcp_client, ctx)
    await call(mcp_client, "lab_deploy", lab=LAB)
    async with ctx.sessionmaker() as s:
        run = (await repo.active_runs(s, ctx.tenant, source="mcp"))[0]
    items: list = []

    async def consume():  # the API's SSE iterator with its own empty broker: only the DB carries MCP events
        async for item in iter_run_events(
            sessionmaker=ctx.sessionmaker,
            broker=EventBroker(),
            tenant_id=ctx.tenant,
            run_id=run.id,
            heartbeat=0.5,
            poll_seconds=0.05,
        ):
            if item is not None:
                items.append(item)

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.2)
    _stub(repo_root, "deploy.sh", 0)
    await _decide(ctx, approved=True)
    await _wait_tasks(ctx)
    await asyncio.wait_for(consumer, 10)
    seqs = [i.seq for i in items if isinstance(i, StreamEvent)]
    assert seqs == list(range(1, len(seqs) + 1)) and isinstance(items[-1], StreamEnd)
    assert items[-1].status == "completed"


async def test_mcp_orphans_recovered_by_pid_and_untouched_by_the_api(ctx):
    dead = f"mcp-{HOST}-999999-abcdef"  # no such pid
    alive = f"mcp-{HOST}-{os.getpid()}-zzzzzz"
    async with transaction(ctx.sessionmaker) as s:
        lab = await repo.create_lab(s, ctx.tenant, name=LAB, spec_path=SPEC)
        for st in (LabState.DESIGNED, LabState.COMPILED, LabState.READY):
            await repo.transition_lab(s, ctx.tenant, lab, st, actor="system")
        await repo.transition_lab(s, ctx.tenant, lab, LabState.APPROVED, actor="user:alice")
        await repo.transition_lab(s, ctx.tenant, lab, LabState.DEPLOYING, actor="system")
        r_dead = await repo.create_run(
            s, ctx.tenant, agent="deploy-operator", task="x", lab_id=lab.id, worker_id=dead, source="mcp"
        )
        r_alive = await repo.create_run(s, ctx.tenant, agent="catalog-author", task="y", worker_id=alive, source="mcp")
        for r in (r_dead, r_alive):
            r.status = RunState.RUNNING
            r.created_at = r.created_at.replace(year=2020)
    async with transaction(ctx.sessionmaker) as s:  # the API's recovery (engine runs only) leaves MCP runs alone
        assert (await repo.recover_orphans(s, {}, alive_workers=None))["runs"] == 0
    counts = await recover_mcp_orphans(ctx)
    assert counts["runs"] == 1 and counts["labs"] == 1
    async with ctx.sessionmaker() as s:
        assert (await repo.get_run(s, ctx.tenant, r_dead.id)).status is RunState.FAILED
        assert (await repo.get_run(s, ctx.tenant, r_alive.id)).status is RunState.RUNNING
        assert (await repo.get_lab(s, ctx.tenant, lab.id)).state is LabState.FAILED  # mid-deploy → teardown required


def test_worker_liveness_parsing():
    assert worker_is_alive(f"mcp-{HOST}-{os.getpid()}-abc123", host=HOST)
    assert not worker_is_alive(f"mcp-{HOST}-999999-abc123", host=HOST)
    assert worker_is_alive("mcp-other-host-1-abc123", host=HOST)  # can't see it → never kill it
    assert not worker_is_alive("engine-worker-1", host=HOST) and not worker_is_alive(None, host=HOST)


async def test_api_refuses_to_cancel_mcp_runs(make_app):
    app = make_app()
    async with app.router.lifespan_context(app):
        async with transaction(app.state.sessionmaker) as s:
            run = await repo.create_run(
                s, "default", agent="deploy-operator", task="x", source="mcp", worker_id="mcp-h-1-a"
            )
            run.status = RunState.WAITING_APPROVAL
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            r = await c.post(f"/api/runs/{run.id}/cancel")
            assert r.status_code == 409 and "deny the pending approval" in r.json()["detail"]
            assert (await c.get(f"/api/runs/{run.id}")).json()["source"] == "mcp"
