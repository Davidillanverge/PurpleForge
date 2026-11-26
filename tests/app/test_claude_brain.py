"""Claude-subscription brain: headless `claude` drives the agent's OWN tools via the
per-run agent-tools MCP server. A fake `claude` (tests/app/fake_claude.py) really
launches that server over stdio, so the whole wiring is exercised without spending
subscription usage."""

from __future__ import annotations

import os
import stat
import sys
import uuid
from pathlib import Path

import httpx
import pytest
from _appkit import ALICE, seed_lab
from fastmcp import Client

from api.registry import default_registry
from api.settings import AppSettings
from db import repository as repo
from db.session import transaction
from db.settings import DatabaseSettings
from db.states import ApprovalStatus, LabState, RunState
from mcp_server.agent_tools import build_server

FAKE = Path(__file__).with_name("fake_claude.py")


@pytest.fixture
def fake_claude(tmp_path):
    exe = tmp_path / "bin" / "claude"
    exe.parent.mkdir()
    exe.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


@pytest.fixture
async def app_client(make_app, fake_claude, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-must-never-reach-claude")
    single_user = {"tok-alice-0123456789abcdefghij": "alice"}  # a personal subscription = one user
    app = make_app(registry=default_registry(), settings={"claude_bin": str(fake_claude), "api_tokens": single_user})
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            c.app = app
            yield c


async def _events(app, run_id):
    async with app.state.sessionmaker() as s:
        return list(await repo.list_events(s, "default", run_id))


# --------------------------------------------------------------------------- end to end through the API


async def test_catalog_author_runs_on_the_subscription_brain(app_client):
    r = await app_client.post(
        "/api/runs",
        json={"agent": "catalog-author", "instructions": "check asreproast", "brain": "claude-subscription"},
    )
    assert r.status_code == 202, r.text
    run_id = uuid.UUID(r.json()["id"])
    await app_client.app.state.runner.wait(run_id)

    run = (await app_client.get(f"/api/runs/{run_id}")).json()
    assert run["status"] == "completed" and run["output"] == "done via subscription"
    assert run["provider"] == "claude (subscription)" and run["model"] == "claude-test-model"
    # tokens: fresh + cache writes + cache reads, per assistant message, summed
    assert (run["input_tokens"], run["output_tokens"], run["turns"]) == (10 + 1000 + 500 + 5 + 1500, 50, 2)

    events = await _events(app_client.app, run_id)
    assert [e.seq for e in events] == list(range(1, len(events) + 1))  # two writers, no gaps or clashes
    types = [e.type for e in events]
    assert types[0] == "run_started" and types[-1] == "run_completed"
    # the tool call was executed by the agent-tools MCP server (another process) via the engine's _execute
    assert "tool_call" in types and "tool_result" in types
    result = next(e for e in events if e.type == "tool_result")
    assert result.data["name"] == "read_file" and not result.data["is_error"] and "asreproast" in result.data["content"]
    texts = " ".join(e.data.get("content", "") for e in events if e.type == "assistant_message")
    assert "api key visible=False" in texts  # ANTHROPIC_API_KEY stripped → subscription, never API billing
    assert "tools=['catalog_check', 'edit_file', 'glob', 'grep', 'read_file', 'web_fetch', 'write_file']" in texts


async def test_lane_holds_on_the_subscription_brain(app_client, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_TOOL", "write_file")
    monkeypatch.setenv("FAKE_CLAUDE_ARGS", '{"path": "specs/evil.yml", "content": "x"}')
    r = await app_client.post(
        "/api/runs", json={"agent": "catalog-author", "instructions": "x", "brain": "claude-subscription"}
    )
    run_id = uuid.UUID(r.json()["id"])
    await app_client.app.state.runner.wait(run_id)
    result = next(e for e in await _events(app_client.app, run_id) if e.type == "tool_result")
    assert result.data["is_error"] and "outside the allowed paths" in result.data["content"]


async def test_refuses_when_claude_reports_an_api_key(app_client, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_KEYSRC", "1")
    r = await app_client.post(
        "/api/runs", json={"agent": "catalog-author", "instructions": "x", "brain": "claude-subscription"}
    )
    run_id = uuid.UUID(r.json()["id"])
    await app_client.app.state.runner.wait(run_id)
    run = (await app_client.get(f"/api/runs/{run_id}")).json()
    assert run["status"] == "failed" and "API key" in run["error"]


async def test_failed_result_fails_the_run(app_client, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_FAIL", "1")
    r = await app_client.post(
        "/api/runs", json={"agent": "catalog-author", "instructions": "x", "brain": "claude-subscription"}
    )
    run_id = uuid.UUID(r.json()["id"])
    await app_client.app.state.runner.wait(run_id)
    assert (await app_client.get(f"/api/runs/{run_id}")).json()["status"] == "failed"


async def test_validator_lab_flow_on_the_subscription_brain(app_client, repo_root):
    d = repo_root / "generated" / "winrm-validate-lab"
    d.mkdir(parents=True)
    (d / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')
    lab = await seed_lab(app_client.app, "winrm-validate-lab", LabState.DEPLOYED)
    r = await app_client.post(
        "/api/runs", json={"agent": "purple-validator", "lab_id": str(lab.id), "brain": "claude-subscription"}
    )
    run_id = uuid.UUID(r.json()["id"])
    await app_client.app.state.runner.wait(run_id)
    detail = (await app_client.get(f"/api/labs/{lab.id}")).json()
    assert detail["state"] == "validated" and detail["usage"]["total_tokens"] > 0


# --------------------------------------------------------------------------- availability / terms


async def test_brains_endpoint_and_single_user_rule(app_client, make_app, fake_claude):
    brains = {b["name"]: b for b in (await app_client.get("/api/brains")).json()}
    assert brains["claude-subscription"]["available"] is True
    # two users on one install → a personal subscription can't back it (Anthropic terms)
    s = AppSettings(_env_file=None, claude_bin=str(fake_claude), api_tokens={"a" * 30: "alice", "b" * 30: "bob"})
    from api.claude_brain import availability

    assert "one person's use" in availability(s)
    assert "not installed" in availability(AppSettings(_env_file=None, claude_bin="/nonexistent/claude"))


async def test_unavailable_brain_is_refused_before_anything_runs(make_app, tmp_path):
    app = make_app(
        registry=default_registry(),
        settings={"claude_bin": str(tmp_path / "missing"), "api_tokens": {"tok-alice-0123456789abcdefghij": "alice"}},
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            r = await c.post(
                "/api/runs", json={"agent": "catalog-author", "instructions": "x", "brain": "claude-subscription"}
            )
            assert r.status_code == 422 and "not installed" in r.json()["detail"]
            assert (await c.get("/api/runs")).json() == []


# --------------------------------------------------------------------------- the agent-tools MCP server itself


async def test_agent_tools_server_gates_infra_actions_on_a_human(tmp_path, repo_root, sessionmaker, engine):
    async with transaction(sessionmaker) as s:
        run = await repo.create_run(s, "default", agent="deploy-operator", task="t")
        run.status = RunState.RUNNING
    db = DatabaseSettings(_env_file=None, database_url=str(engine.url.render_as_string(hide_password=False)))
    app = AppSettings(_env_file=None, repo_root=repo_root, approval_timeout_seconds=10)
    server = build_server(
        run_id=str(run.id),
        toolset="deploy-operator",
        tenant="default",
        lab="winrm-validate-lab",
        spec="specs/winrm-validate-lab.yml",
        app=app,
        db=db,
    )
    import asyncio

    async with Client(server) as c:
        assert {t.name for t in await c.list_tools()} == {"forge", "forge_wait", "bash", "read_file", "grep", "glob"}
        call = asyncio.create_task(c.call_tool("bash", {"command": "echo approved-run"}, raise_on_error=False))
        for _ in range(200):  # not read-only → waits for a human
            async with sessionmaker() as s:
                pending = await repo.list_run_approvals(s, "default", run.id)
            if pending:
                break
            await asyncio.sleep(0.02)
        async with sessionmaker() as s:
            assert (await repo.get_run(s, "default", run.id)).status is RunState.WAITING_APPROVAL
        async with transaction(sessionmaker) as s:
            await repo.decide_approval(s, "default", pending[0].id, approved=True, by="user:alice")
        r = await asyncio.wait_for(call, 20)
        assert not r.is_error and "approved-run" in r.content[0].text
        denied = await c.call_tool("bash", {"command": "cat .env"}, raise_on_error=False)
        assert denied.is_error and "deny rule" in denied.content[0].text
    async with sessionmaker() as s:
        approvals = await repo.list_run_approvals(s, "default", run.id)
    assert [a.status for a in approvals] == [ApprovalStatus.APPROVED] and os.environ.get("PATH")
