"""Shared app-level test kit: a tmp repo, a scripted-LLM queue, the app factory,
a gated test agent (needs human approval) and a few async helpers."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import httpx
import pytest
from _fakes import ScriptedLLM
from pydantic import BaseModel

from agents import Tool, ToolResult
from agents.engine import AgentEngine
from api.app import create_app
from api.registry import VALIDATOR, AgentSpec, PreparedRun
from api.settings import AppSettings
from db import repository as repo
from db.session import transaction
from db.settings import DatabaseSettings
from db.states import LabState

REPO_ROOT = Path(__file__).resolve().parents[2]
ALICE = {"Authorization": "Bearer tok-alice-0123456789abcdefghij"}
KEY = "s" * 40


# --------------------------------------------------------------------------- fixtures


class GateIn(BaseModel):
    action: str


class GatedTool(Tool):
    name = "gated"
    description = "a tool that needs a human OK"
    Input = GateIn

    def needs_approval(self, args):
        return f"{args.action} touches live infra"

    async def run(self, args):
        return ToolResult(content=f"did {args.action}")


def _gated_prepare(ctx):
    engine = AgentEngine(
        ctx.llm,
        [GatedTool()],
        system_prompt="s",
        agent_name="gated-agent",
        on_event=ctx.on_event,
        approver=ctx.approver,
    )
    return PreparedRun(task="gated test", execute=lambda run_id: engine.run("do it", run_id=run_id))


GATED = AgentSpec(name="gated-agent", description="test", prepare=_gated_prepare, requires_lab=False)


class LLMQueue:
    """Each run takes the next ScriptedLLM."""

    def __init__(self):
        self.items: list[ScriptedLLM] = []

    async def __call__(self, session, tenant):
        return self.items.pop(0)


@pytest.fixture
def repo_root(tmp_path):
    root = tmp_path / "repo"
    (root / ".claude" / "agents").mkdir(parents=True)
    for md in ("purple-validator", "lab-designer", "deploy-operator", "catalog-author"):
        shutil.copy(REPO_ROOT / ".claude" / "agents" / f"{md}.md", root / ".claude" / "agents")
    shutil.copytree(REPO_ROOT / "catalog", root / "catalog")
    (root / "specs").mkdir()
    shutil.copy(REPO_ROOT / "specs" / "winrm-validate-lab.yml", root / "specs")
    (root / "specs" / "bare-lab.yml").write_text("lab:\n  name: bare-lab\n  provider: aws\n")
    return root


@pytest.fixture
def llms():
    return LLMQueue()


@pytest.fixture
def make_app(tmp_path, repo_root, llms):
    def _make(**overrides):
        extra = dict(overrides.pop("settings", {}))
        settings = AppSettings(
            _env_file=None,
            repo_root=repo_root,
            auto_migrate=True,
            api_tokens=extra.pop(
                "api_tokens", {"tok-alice-0123456789abcdefghij": "alice", "tok-bob-0123456789abcdefghijkl": "bob"}
            ),
            approval_timeout_seconds=overrides.pop("approval_timeout_seconds", 5),
            sse_heartbeat_seconds=0.05,
            **extra,
        )
        db = DatabaseSettings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}", secret_key=KEY)
        registry = overrides.pop("registry", None) or {VALIDATOR.name: VALIDATOR, GATED.name: GATED}
        return create_app(settings, db, registry=registry, llm_factory=llms)

    return _make


@pytest.fixture
async def client(make_app):
    app = make_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            c.app = app
            yield c


async def wait_for(predicate, timeout=5.0):
    async def loop():
        while not await predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(loop(), timeout)


async def seed_lab(app, name, state, *, spec="specs/winrm-validate-lab.yml"):
    """Put a lab directly into a forge/agent-driven state (as a deploy would)."""
    path = [
        LabState.DESIGNED,
        LabState.COMPILED,
        LabState.READY,
        LabState.APPROVED,
        LabState.DEPLOYING,
        LabState.DEPLOYED,
    ]
    async with transaction(app.state.sessionmaker) as s:
        lab = await repo.create_lab(s, "default", name=name, spec_path=spec)
        for st in path[: path.index(state) + 1]:
            await repo.transition_lab(
                s, "default", lab, st, actor="user:alice" if st is LabState.APPROVED else "system"
            )
    return lab
