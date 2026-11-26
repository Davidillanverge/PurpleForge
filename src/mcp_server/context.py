"""Process-wide state of the MCP server: DB, settings, identity, background tasks.

The MCP server is the *second execution mode*: Claude Code (or any MCP client) is
the LLM; this process only exposes deterministic lab operations over the SAME
database, FSM, services, tools and outcomes as the standalone engine.
"""

from __future__ import annotations

import asyncio
import contextlib
import getpass
import logging
import os
import secrets
import socket
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from api.app import wait_for_database
from api.auth import Principal
from api.registry import AgentSpec, default_registry
from api.settings import AppSettings
from db import repository as repo
from db.base import utcnow
from db.migrate import upgrade_head
from db.session import create_engine, create_sessionmaker, transaction
from db.settings import DatabaseSettings

log = logging.getLogger(__name__)


class McpSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PF_MCP_", env_file=".env", extra="ignore")

    #: Where humans approve gated actions (shown in tool replies).
    dashboard_url: str = "http://127.0.0.1:8000"
    #: Label for the MCP side in the lab timeline ("mcp:<actor>"). Never a "user:" actor:
    #: the LLM driving this server can't approve deploys.
    actor: str = Field(default_factory=lambda: f"claude-code({getpass.getuser()})")
    #: How often a pending human approval is re-checked in the shared DB.
    approval_poll_seconds: float = 1.0


@dataclass(frozen=True)
class McpPrincipal(Principal):
    """Acts on behalf of the MCP client (an LLM). Its actor is ``mcp:<name>``, so the
    FSM and the approval gate (which require ``user:``) reject it as an approver."""

    label: str = "claude-code"

    @property
    def actor(self) -> str:
        return f"mcp:{self.label}"


@dataclass
class McpContext:
    app: AppSettings
    mcp: McpSettings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    registry: dict[str, AgentSpec]
    principal: McpPrincipal
    worker_id: str
    tasks: dict[uuid.UUID, asyncio.Task[Any]] = field(default_factory=dict)

    @property
    def tenant(self) -> str:
        return self.principal.tenant

    def spawn(self, run_id: uuid.UUID, coro: Any) -> None:
        """Run a gated operation in the background (deploys take an hour; MCP tool
        calls must return quickly). It dies with this process — orphan recovery
        on the next start fails it if so."""
        task = asyncio.create_task(coro, name=f"mcp-run-{run_id}")
        self.tasks[run_id] = task
        task.add_done_callback(lambda _t: self.tasks.pop(run_id, None))


_ctx: McpContext | None = None
_lock = asyncio.Lock()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def worker_is_alive(worker_id: str | None, *, host: str) -> bool:
    """MCP worker ids are ``mcp-<host>-<pid>-<rand>``. Same host → check the pid;
    another host → can't know, assume alive (never kill what we can't see)."""
    if not worker_id or not worker_id.startswith("mcp-"):
        return False
    try:
        rest, _rand = worker_id[len("mcp-") :].rsplit("-", 1)
        wid_host, pid = rest.rsplit("-", 1)
        return _pid_alive(int(pid)) if wid_host == host else True
    except ValueError:
        return False


async def recover_mcp_orphans(ctx: McpContext) -> dict[str, int]:
    host = socket.gethostname()
    async with ctx.sessionmaker() as s:
        active = await repo.active_runs(s, ctx.tenant, source="mcp")
    alive = {r.worker_id for r in active if r.worker_id and worker_is_alive(r.worker_id, host=host)}
    alive.add(ctx.worker_id)
    rollback = {
        sp.running_state: sp.failure_state
        for sp in ctx.registry.values()
        if sp.running_state is not None and sp.failure_state is not None
    }
    async with transaction(ctx.sessionmaker) as s:
        counts = await repo.recover_orphans(
            s, rollback, alive_workers=alive, source="mcp", started_before=utcnow() - timedelta(seconds=5)
        )
    if any(counts.values()):
        log.warning("recovered orphaned MCP runs: %s", counts)
    return counts


async def get_context() -> McpContext:
    global _ctx
    async with _lock:
        if _ctx is None:
            _ctx = await build_context()
        return _ctx


async def build_context(
    app: AppSettings | None = None, db: DatabaseSettings | None = None, mcp: McpSettings | None = None
) -> McpContext:
    app = app or AppSettings()
    db = db or DatabaseSettings()
    mcp = mcp or McpSettings()
    engine = create_engine(settings=db)
    await wait_for_database(engine, app.db_wait_seconds)
    if app.auto_migrate:
        await upgrade_head(engine)
    ctx = McpContext(
        app=app,
        mcp=mcp,
        engine=engine,
        sessionmaker=create_sessionmaker(engine),
        registry=default_registry(),
        principal=McpPrincipal(user=mcp.actor, tenant=app.default_tenant, label=mcp.actor),
        worker_id=f"mcp-{socket.gethostname()}-{os.getpid()}-{secrets.token_hex(3)}",
    )
    await recover_mcp_orphans(ctx)
    return ctx


async def close_context() -> None:
    global _ctx
    if _ctx is not None:
        for task in list(_ctx.tasks.values()):
            task.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*_ctx.tasks.values(), return_exceptions=True)
        await _ctx.engine.dispose()
        _ctx = None


def set_context(ctx: McpContext | None) -> None:
    """Tests inject a context bound to their own DB / repo."""
    global _ctx
    _ctx = ctx
