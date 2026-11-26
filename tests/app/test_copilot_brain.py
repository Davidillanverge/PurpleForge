"""GitHub Copilot-subscription brain: headless `copilot` drives the agent's OWN tools via the
per-run agent-tools MCP server. A fake `copilot` (tests/app/fake_copilot.py) checks the
isolation flags and really launches that server over stdio — no Copilot usage spent."""

from __future__ import annotations

import stat
import sys
import uuid
from pathlib import Path

import httpx
import pytest
from _appkit import ALICE, seed_lab

from api.copilot_brain import CopilotSubscriptionBrain, _sum_tokens
from api.registry import default_registry
from api.settings import AppSettings
from db import repository as repo
from db.states import LabState

FAKE = Path(__file__).with_name("fake_copilot.py")
ONE_USER = {"tok-alice-0123456789abcdefghij": "alice"}


@pytest.fixture
def fake_copilot(tmp_path):
    exe = tmp_path / "bin" / "copilot"
    exe.parent.mkdir()
    exe.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


@pytest.fixture
async def app_client(make_app, fake_copilot, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-must-never-reach-copilot")
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "gho_host_login_token")
    app = make_app(registry=default_registry(), settings={"copilot_bin": str(fake_copilot), "api_tokens": ONE_USER})
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            c.app = app
            yield c


async def _run(client, **body):
    r = await client.post("/api/runs", json={"brain": "copilot-subscription", **body})
    assert r.status_code == 202, r.text
    run_id = uuid.UUID(r.json()["id"])
    await client.app.state.runner.wait(run_id)
    async with client.app.state.sessionmaker() as s:
        events = list(await repo.list_events(s, "default", run_id))
    return (await client.get(f"/api/runs/{run_id}")).json(), events


async def test_catalog_author_on_the_copilot_brain(app_client):
    run, events = await _run(app_client, agent="catalog-author", instructions="check asreproast")
    assert run["status"] == "completed", run["error"]
    assert run["provider"] == "github copilot (subscription)" and run["model"] == "claude-sonnet-4.6"
    assert (run["input_tokens"], run["output_tokens"], run["turns"]) == (1200 + 300 + 1800 + 1200, 65, 2)
    assert [e.seq for e in events] == list(range(1, len(events) + 1))
    result = next(e for e in events if e.type == "tool_result")  # recorded by the MCP side via the engine
    assert result.data["name"] == "read_file" and not result.data["is_error"] and "asreproast" in result.data["content"]
    texts = " ".join(e.data.get("content", "") for e in events if e.type == "assistant_message")
    assert "token=True" in texts and "anthropic=False" in texts  # its own login token back; no LLM API keys
    assert "tools=['catalog_check', 'edit_file', 'glob', 'grep', 'read_file', 'web_fetch', 'write_file']" in texts
    done = next(e for e in events if e.type == "run_completed")
    assert done.data["premium_requests"] == 1 and done.data["output"].startswith("tools=")


async def test_lane_holds_on_the_copilot_brain(app_client, monkeypatch):
    monkeypatch.setenv("FAKE_COPILOT_TOOL", "write_file")
    monkeypatch.setenv("FAKE_COPILOT_ARGS", '{"path": "specs/evil.yml", "content": "x"}')
    run, events = await _run(app_client, agent="catalog-author", instructions="x")
    result = next(e for e in events if e.type == "tool_result")
    assert result.data["is_error"] and "outside the allowed paths" in result.data["content"]


async def test_auth_failure_is_a_clear_failed_run(app_client, monkeypatch):
    monkeypatch.setenv("FAKE_COPILOT_AUTHFAIL", "1")
    run, _ = await _run(app_client, agent="catalog-author", instructions="x")
    assert run["status"] == "failed" and "authentication" in run["error"]


async def test_validator_lab_flow_on_the_copilot_brain(app_client, repo_root):
    d = repo_root / "generated" / "winrm-validate-lab"
    d.mkdir(parents=True)
    (d / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')
    lab = await seed_lab(app_client.app, "winrm-validate-lab", LabState.DEPLOYED)
    run, _ = await _run(app_client, agent="purple-validator", lab_id=str(lab.id))
    detail = (await app_client.get(f"/api/labs/{lab.id}")).json()
    assert run["status"] == "completed" and detail["state"] == "validated"


async def test_brains_list_and_availability(app_client, fake_copilot):
    brains = {b["name"]: b for b in (await app_client.get("/api/brains")).json()}
    assert brains["copilot-subscription"]["available"] and brains["copilot-subscription"]["label"].startswith("GitHub")
    two = AppSettings(_env_file=None, copilot_bin=str(fake_copilot), api_tokens={"a" * 30: "alice", "b" * 30: "bob"})
    assert "one person's use" in CopilotSubscriptionBrain.availability(two)
    assert "not installed" in CopilotSubscriptionBrain.availability(AppSettings(_env_file=None, copilot_bin="/nope"))


def test_usage_file_token_sum():
    metrics = {
        "m1": {"usage": {"inputTokens": 10, "cacheReadTokens": 5, "outputTokens": 3}},
        "m2": [{"outputTokens": 2}],
    }
    assert _sum_tokens(metrics) == (15, 5)
