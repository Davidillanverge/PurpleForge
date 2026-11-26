"""Tenant-scoped data access.

Every function takes ``tenant_id`` explicitly and filters by it; nothing here
uses ``session.get()`` (it would bypass the tenant filter). Functions don't
commit — callers own the transaction (see db.session.transaction) — except
DbEventSink, which is a standalone engine callback with its own sessions.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.engine import AgentResult, ApprovalRequest
from agents.events import AgentEvent as EngineEvent
from agents.events import EventType
from db.base import utcnow
from db.crypto import SecretCipher
from db.models import AgentEvent, AgentRun, Approval, Lab, LabTransition, ProviderConfig
from db.states import INFRA_STATES, ApprovalStatus, LabState, ProviderKind, RunState, check_transition
from llm.anthropic_provider import AnthropicProvider
from llm.gemini_provider import DEFAULT_BASE_URL as GEMINI_DEFAULT_BASE_URL
from llm.gemini_provider import GeminiProvider
from llm.ollama_provider import DEFAULT_NUM_CTX, OllamaProvider
from llm.pool import FailoverCallback, LLMPool
from llm.provider import LLMProvider
from llm.settings import LLMSettings, build_pool


class NotFound(LookupError):
    pass


class ApprovalAlreadyDecided(RuntimeError):
    pass


class ActorNotAllowed(PermissionError):
    pass


def _uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


# --------------------------------------------------------------------------- labs


async def create_lab(
    session: AsyncSession,
    tenant_id: str,
    *,
    name: str,
    description: str = "",
    spec_path: str | None = None,
    cloud: str | None = None,
    actor: str = "system",
) -> Lab:
    lab = Lab(
        tenant_id=tenant_id,
        name=name,
        description=description,
        spec_path=spec_path,
        cloud=cloud,
        state=LabState.DRAFT,
        state_changed_at=utcnow(),
    )
    lab.transitions.append(
        LabTransition(tenant_id=tenant_id, from_state=None, to_state=LabState.DRAFT, actor=actor, reason="created")
    )
    session.add(lab)
    await session.flush()
    return lab


async def get_lab(session: AsyncSession, tenant_id: str, lab_id: uuid.UUID | str, *, for_update: bool = False) -> Lab:
    stmt = select(Lab).where(Lab.tenant_id == tenant_id, Lab.id == _uuid(lab_id))
    if for_update:  # serialises concurrent transitions on Postgres (no-op on SQLite)
        stmt = stmt.with_for_update()
    lab = (await session.execute(stmt)).scalar_one_or_none()
    if lab is None:
        raise NotFound(f"lab {lab_id} not found")
    return lab


async def get_lab_by_name(session: AsyncSession, tenant_id: str, name: str) -> Lab | None:
    stmt = select(Lab).where(Lab.tenant_id == tenant_id, Lab.name == name)
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_labs(
    session: AsyncSession, tenant_id: str, *, states: Iterable[LabState] | None = None
) -> Sequence[Lab]:
    stmt = select(Lab).where(Lab.tenant_id == tenant_id)
    if states is not None:
        stmt = stmt.where(Lab.state.in_(list(states)))
    return (await session.execute(stmt.order_by(Lab.created_at.desc()))).scalars().all()


async def list_transitions(session: AsyncSession, tenant_id: str, lab_id: uuid.UUID | str) -> Sequence[LabTransition]:
    stmt = (
        select(LabTransition)
        .where(LabTransition.tenant_id == tenant_id, LabTransition.lab_id == _uuid(lab_id))
        .order_by(LabTransition.id)
    )
    return (await session.execute(stmt)).scalars().all()


async def transition_lab(
    session: AsyncSession,
    tenant_id: str,
    lab: Lab,
    target: LabState,
    *,
    actor: str,
    reason: str = "",
    run_id: uuid.UUID | str | None = None,
    error: str | None = None,
) -> LabTransition:
    """Move a lab through the FSM and append the history row.

    Approval is a human act: only a ``user:<id>`` actor may move a lab to
    APPROVED — no agent or system process can approve its own deploy.
    """
    if lab.tenant_id != tenant_id:
        raise NotFound(f"lab {lab.id} not found")
    check_transition(lab.state, target)
    if target is LabState.APPROVED and not actor.startswith("user:"):
        raise ActorNotAllowed(f"only a human (user:<id>) can approve a deploy, not {actor!r}")
    row = LabTransition(
        tenant_id=tenant_id,
        lab_id=lab.id,
        from_state=lab.state,
        to_state=target,
        actor=actor,
        reason=reason,
        run_id=_uuid(run_id) if run_id else None,
    )
    lab.state = target
    lab.state_changed_at = row.at = utcnow()
    lab.last_error = error if target is LabState.FAILED else None
    session.add(row)
    await session.flush()
    return row


# --------------------------------------------------------------------------- runs + events


async def create_run(
    session: AsyncSession,
    tenant_id: str,
    *,
    agent: str,
    task: str,
    lab_id: uuid.UUID | str | None = None,
    created_by: str | None = None,
    worker_id: str | None = None,
    source: str = "engine",
) -> AgentRun:
    if lab_id is not None:
        await get_lab(session, tenant_id, lab_id)  # tenant check on the FK target
    run = AgentRun(
        tenant_id=tenant_id,
        agent=agent,
        task=task,
        lab_id=_uuid(lab_id) if lab_id else None,
        created_by=created_by,
        worker_id=worker_id,
        source=source,
        status=RunState.QUEUED,
        created_at=utcnow(),
    )
    session.add(run)
    await session.flush()
    return run


async def get_run_any_tenant(session: AsyncSession, run_id: uuid.UUID | str) -> AgentRun:
    """SYSTEM use only (a background job / tool that knows its run id but not its tenant)."""
    run = (await session.execute(select(AgentRun).where(AgentRun.id == _uuid(run_id)))).scalar_one_or_none()
    if run is None:
        raise NotFound(f"run {run_id} not found")
    return run


async def get_run(session: AsyncSession, tenant_id: str, run_id: uuid.UUID | str) -> AgentRun:
    stmt = select(AgentRun).where(AgentRun.tenant_id == tenant_id, AgentRun.id == _uuid(run_id))
    run = (await session.execute(stmt)).scalar_one_or_none()
    if run is None:
        raise NotFound(f"run {run_id} not found")
    return run


async def list_runs(
    session: AsyncSession, tenant_id: str, *, lab_id: uuid.UUID | str | None = None, limit: int = 50
) -> Sequence[AgentRun]:
    stmt = select(AgentRun).where(AgentRun.tenant_id == tenant_id)
    if lab_id is not None:
        stmt = stmt.where(AgentRun.lab_id == _uuid(lab_id))
    return (await session.execute(stmt.order_by(AgentRun.created_at.desc()).limit(limit))).scalars().all()


_TERMINAL_EVENTS: dict[EventType, RunState] = {
    EventType.RUN_COMPLETED: RunState.COMPLETED,
    EventType.RUN_FAILED: RunState.FAILED,
    EventType.BUDGET_EXCEEDED: RunState.BUDGET_EXCEEDED,
    EventType.RUN_CANCELLED: RunState.CANCELLED,
}


def _apply_event(run: AgentRun, event: EngineEvent) -> None:
    """Keep the run row's status/counters in step with its event stream."""
    data = event.data
    budget: dict[str, Any] = data.get("budget") or {}
    if budget:
        run.turns = budget.get("turns", run.turns)
        run.input_tokens = budget.get("input_tokens", run.input_tokens)
        run.output_tokens = budget.get("output_tokens", run.output_tokens)
    if event.type is EventType.RUN_STARTED:
        run.status = RunState.RUNNING
        run.started_at = event.ts
        run.provider = data.get("provider")
        run.model = data.get("model")
    elif event.type is EventType.ASSISTANT_MESSAGE:
        run.provider = data.get("provider") or run.provider  # actual server after failover
        run.model = data.get("model") or run.model
    elif event.type is EventType.APPROVAL_REQUESTED:
        run.status = RunState.WAITING_APPROVAL
    elif event.type is EventType.APPROVAL_RESOLVED:
        run.status = RunState.RUNNING
    elif event.type in _TERMINAL_EVENTS:
        run.status = _TERMINAL_EVENTS[event.type]
        run.finished_at = event.ts
        if "output" in data:
            run.output = data["output"] or ""
        if data.get("error") or data.get("reason"):
            run.error = data.get("error") or data.get("reason")


async def record_event(session: AsyncSession, tenant_id: str, event: EngineEvent) -> AgentEvent:
    run = await get_run(session, tenant_id, event.run_id)
    row = AgentEvent(
        tenant_id=tenant_id,
        run_id=run.id,
        seq=event.seq,
        type=event.type.value,
        data=event.model_dump(mode="json")["data"],
        ts=event.ts,
    )
    session.add(row)
    _apply_event(run, event)
    await session.flush()
    return row


async def list_events(
    session: AsyncSession, tenant_id: str, run_id: uuid.UUID | str, *, after_seq: int = 0, limit: int = 1000
) -> Sequence[AgentEvent]:
    """Events after ``after_seq`` — SSE replay via Last-Event-ID."""
    stmt = (
        select(AgentEvent)
        .where(AgentEvent.tenant_id == tenant_id, AgentEvent.run_id == _uuid(run_id), AgentEvent.seq > after_seq)
        .order_by(AgentEvent.seq)
        .limit(limit)
    )
    return (await session.execute(stmt)).scalars().all()


async def finish_run(session: AsyncSession, tenant_id: str, result: AgentResult) -> AgentRun:
    """Authoritative final state from the engine's AgentResult."""
    run = await get_run(session, tenant_id, result.run_id)
    run.status = RunState.from_result(result.status)
    run.output = result.output
    run.error = result.error
    run.turns = result.turns
    run.input_tokens = result.usage.input_tokens
    run.output_tokens = result.usage.output_tokens
    run.finished_at = run.finished_at or utcnow()
    await session.flush()
    return run


class DbEventSink:
    """Engine ``on_event`` callback that persists each event in its own transaction
    (an agent run lasts minutes to hours — never hold one session open for it)."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], tenant_id: str) -> None:
        self.sessionmaker = sessionmaker
        self.tenant_id = tenant_id

    async def __call__(self, event: EngineEvent) -> None:
        """The engine numbers its own events, but another writer may append to the same
        run meanwhile (a background forge job streaming its output, agents.background):
        on a seq collision, take the next free seq — the event keeps its place in time."""
        for attempt in range(20):
            try:
                async with self.sessionmaker() as session, session.begin():
                    if attempt:
                        event.seq = max(event.seq, await max_event_seq(session, self.tenant_id, event.run_id) + 1)
                    await record_event(session, self.tenant_id, event)
                return
            except IntegrityError:
                if attempt == 19:
                    raise
                await asyncio.sleep(0.01 * (attempt + 1))


# --------------------------------------------------------------------------- approvals


async def create_approval(
    session: AsyncSession, tenant_id: str, request: ApprovalRequest, *, lab_id: uuid.UUID | str | None = None
) -> Approval:
    run = await get_run(session, tenant_id, request.run_id)
    approval = Approval(
        tenant_id=tenant_id,
        run_id=run.id,
        lab_id=_uuid(lab_id) if lab_id else run.lab_id,
        tool_call_id=request.tool_call.id,
        tool_name=request.tool_call.name,
        arguments=request.tool_call.arguments,
        reason=request.reason,
        status=ApprovalStatus.PENDING,
        requested_at=utcnow(),
    )
    session.add(approval)
    await session.flush()
    return approval


async def get_approval(session: AsyncSession, tenant_id: str, approval_id: uuid.UUID | str) -> Approval:
    stmt = select(Approval).where(Approval.tenant_id == tenant_id, Approval.id == _uuid(approval_id))
    approval = (await session.execute(stmt)).scalar_one_or_none()
    if approval is None:
        raise NotFound(f"approval {approval_id} not found")
    return approval


async def decide_approval(
    session: AsyncSession,
    tenant_id: str,
    approval_id: uuid.UUID | str,
    *,
    approved: bool,
    by: str,
    comment: str | None = None,
) -> Approval:
    if not by.startswith("user:"):
        raise ActorNotAllowed(f"approvals are decided by humans (user:<id>), not {by!r}")
    stmt = select(Approval).where(Approval.tenant_id == tenant_id, Approval.id == _uuid(approval_id)).with_for_update()
    approval = (await session.execute(stmt)).scalar_one_or_none()
    if approval is None:
        raise NotFound(f"approval {approval_id} not found")
    if approval.status is not ApprovalStatus.PENDING:
        raise ApprovalAlreadyDecided(f"approval {approval_id} is already {approval.status.value}")
    approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
    approval.decided_by = by
    approval.comment = comment
    approval.decided_at = utcnow()
    await session.flush()
    return approval


async def list_pending_approvals(session: AsyncSession, tenant_id: str) -> Sequence[Approval]:
    stmt = (
        select(Approval)
        .where(Approval.tenant_id == tenant_id, Approval.status == ApprovalStatus.PENDING)
        .order_by(Approval.requested_at)
    )
    return (await session.execute(stmt)).scalars().all()


# --------------------------------------------------------------------------- provider configs

_UNSET: Any = object()


async def upsert_provider_config(
    session: AsyncSession,
    tenant_id: str,
    *,
    name: str,
    kind: ProviderKind,
    model: str,
    enabled: bool = True,
    priority: int = 100,
    base_url: str | None = None,
    timeout_seconds: float | None = None,
    options: dict[str, Any] | None = None,
    api_key: str | None = _UNSET,
    cipher: SecretCipher | None = None,
) -> ProviderConfig:
    """``api_key``: omit to keep the stored key, None to clear it, a string to replace it."""
    stmt = select(ProviderConfig).where(ProviderConfig.tenant_id == tenant_id, ProviderConfig.name == name)
    cfg = (await session.execute(stmt)).scalar_one_or_none()
    if cfg is None:
        cfg = ProviderConfig(tenant_id=tenant_id, name=name)
        session.add(cfg)
    cfg.kind = kind
    cfg.model = model
    cfg.enabled = enabled
    cfg.priority = priority
    cfg.base_url = base_url
    cfg.timeout_seconds = timeout_seconds
    cfg.options = options or {}
    if api_key is not _UNSET:
        if api_key:
            if cipher is None:
                raise ValueError("a SecretCipher is required to store an API key")
            cfg.api_key_encrypted = cipher.encrypt(api_key)
        else:
            cfg.api_key_encrypted = None
    await session.flush()
    return cfg


async def list_provider_configs(
    session: AsyncSession, tenant_id: str, *, enabled_only: bool = False
) -> Sequence[ProviderConfig]:
    stmt = select(ProviderConfig).where(ProviderConfig.tenant_id == tenant_id)
    if enabled_only:
        stmt = stmt.where(ProviderConfig.enabled.is_(True))
    return (await session.execute(stmt.order_by(ProviderConfig.priority, ProviderConfig.name))).scalars().all()


def provider_from_config(cfg: ProviderConfig, cipher: SecretCipher | None) -> LLMProvider:
    if cfg.kind is ProviderKind.ANTHROPIC:
        key = cipher.decrypt(cfg.api_key_encrypted) if (cfg.api_key_encrypted and cipher) else None
        if cfg.api_key_encrypted and cipher is None:
            raise ValueError(f"provider {cfg.name!r} has a stored key but no PF_SECRET_KEY is configured")
        return AnthropicProvider(
            name=cfg.name, api_key=key, model=cfg.model, base_url=cfg.base_url, timeout=cfg.timeout_seconds or 120.0
        )
    if cfg.kind is ProviderKind.GEMINI:
        if cfg.api_key_encrypted and cipher is None:
            raise ValueError(f"provider {cfg.name!r} has a stored key but no PF_SECRET_KEY is configured")
        gkey = cipher.decrypt(cfg.api_key_encrypted) if (cfg.api_key_encrypted and cipher) else None
        return GeminiProvider(
            name=cfg.name,
            api_key=gkey,
            model=cfg.model,
            base_url=cfg.base_url or GEMINI_DEFAULT_BASE_URL,
            timeout=cfg.timeout_seconds or 600.0,
        )
    if cfg.kind is ProviderKind.OLLAMA:
        return OllamaProvider(
            num_ctx=int(cfg.options.get("num_ctx", DEFAULT_NUM_CTX)),
            name=cfg.name,
            model=cfg.model,
            base_url=cfg.base_url or "http://localhost:11434",
            timeout=cfg.timeout_seconds or 300.0,
        )
    raise ValueError(f"unknown provider kind {cfg.kind!r}")


async def build_tenant_pool(
    session: AsyncSession,
    tenant_id: str,
    *,
    cipher: SecretCipher | None = None,
    settings: LLMSettings | None = None,
    on_failover: FailoverCallback | None = None,
) -> LLMPool:
    """The tenant's enabled ProviderConfigs (by priority); falls back to the
    PF_LLM_* env pool when the tenant has configured none."""
    settings = settings or LLMSettings()
    configs = await list_provider_configs(session, tenant_id, enabled_only=True)
    if not configs:
        return build_pool(settings, on_failover=on_failover)
    return LLMPool(
        [provider_from_config(c, cipher) for c in configs],
        max_retries=settings.max_retries,
        backoff_base=settings.backoff_base,
        backoff_max=settings.backoff_max,
        cooldown_seconds=settings.cooldown_seconds,
        max_retry_after=settings.max_retry_after,
        on_failover=on_failover,
    )


# --------------------------------------------------------------------------- API helpers


class LabHasInfrastructure(RuntimeError):
    pass


async def delete_lab(session: AsyncSession, tenant_id: str, lab: Lab) -> None:
    """Refuses while cloud resources may exist: tear the lab down first."""
    if lab.tenant_id != tenant_id:
        raise NotFound(f"lab {lab.id} not found")
    if lab.state in INFRA_STATES:
        raise LabHasInfrastructure(
            f"lab {lab.name} is {lab.state.value}: infrastructure may exist — destroy it before deleting the record"
        )
    await session.delete(lab)
    await session.flush()


async def fail_run(
    session: AsyncSession, tenant_id: str, run_id: uuid.UUID | str, *, status: RunState, error: str | None
) -> AgentRun:
    """Terminal state for a run that ended without an AgentResult (crash/cancel)."""
    run = await get_run(session, tenant_id, run_id)
    if not run.status.is_terminal:  # keep a terminal state the event stream already set
        run.status = status
    run.error = error or run.error
    run.finished_at = run.finished_at or utcnow()
    await session.flush()
    return run


async def expire_approval(session: AsyncSession, tenant_id: str, approval_id: uuid.UUID | str) -> bool:
    """PENDING → EXPIRED; False if a human decided first."""
    stmt = select(Approval).where(Approval.tenant_id == tenant_id, Approval.id == _uuid(approval_id)).with_for_update()
    approval = (await session.execute(stmt)).scalar_one_or_none()
    if approval is None or approval.status is not ApprovalStatus.PENDING:
        return False
    approval.status = ApprovalStatus.EXPIRED
    approval.decided_at = utcnow()
    approval.decided_by = "system"
    approval.comment = "timed out waiting for a human decision"
    await session.flush()
    return True


async def list_run_approvals(session: AsyncSession, tenant_id: str, run_id: uuid.UUID | str) -> Sequence[Approval]:
    stmt = (
        select(Approval)
        .where(Approval.tenant_id == tenant_id, Approval.run_id == _uuid(run_id))
        .order_by(Approval.requested_at)
    )
    return (await session.execute(stmt)).scalars().all()


async def delete_provider_config(session: AsyncSession, tenant_id: str, name: str) -> bool:
    stmt = select(ProviderConfig).where(ProviderConfig.tenant_id == tenant_id, ProviderConfig.name == name)
    cfg = (await session.execute(stmt)).scalar_one_or_none()
    if cfg is None:
        return False
    await session.delete(cfg)
    await session.flush()
    return True


async def get_provider_config(session: AsyncSession, tenant_id: str, name: str) -> ProviderConfig:
    stmt = select(ProviderConfig).where(ProviderConfig.tenant_id == tenant_id, ProviderConfig.name == name)
    cfg = (await session.execute(stmt)).scalar_one_or_none()
    if cfg is None:
        raise NotFound(f"provider {name!r} not found")
    return cfg


ACTIVE_RUN_STATES = (RunState.QUEUED, RunState.RUNNING, RunState.WAITING_APPROVAL)


async def recover_orphans(
    session: AsyncSession,
    lab_rollback: Mapping[LabState, LabState | Callable[[Lab], LabState]],
    *,
    alive_workers: Iterable[str] | None,
    started_before: datetime | None = None,
    source: str = "engine",
) -> dict[str, int]:
    """SYSTEM maintenance, deliberately cross-tenant. Runs live inside one API
    worker process, so a run whose worker is gone will never finish. Fail those
    runs, expire *their* pending approvals, and move labs they owned back
    (``lab_rollback``: running_state → failure_state).

    ``alive_workers``: worker ids known alive (their runs are left alone). None
    means "no worker is alive" (single-process startup: everything active is dead).
    ``started_before``: grace period — ignore runs created after this instant
    (a just-created run whose worker hasn't heartbeated yet).
    ``source``: only runs of this execution mode ("engine" or "mcp").
    """
    # each mode only judges its own runs: the API can't know whether an MCP server
    # process (spawned by Claude Code) is alive, and vice versa
    stmt = select(AgentRun).where(AgentRun.status.in_(ACTIVE_RUN_STATES), AgentRun.source == source)
    alive = set(alive_workers or ())
    if alive:
        stmt = stmt.where((AgentRun.worker_id.is_(None)) | (AgentRun.worker_id.not_in(alive)))
    if started_before is not None:
        stmt = stmt.where(AgentRun.created_at < started_before)
    runs = (await session.execute(stmt.with_for_update())).scalars().all()
    run_ids = [r.id for r in runs]
    for run in runs:
        run.status = RunState.FAILED
        run.error = "its API worker stopped while the run was active (restart/crash)"
        run.finished_at = utcnow()

    approvals: Sequence[Approval] = []
    if run_ids:
        approvals = (
            (
                await session.execute(
                    select(Approval).where(Approval.status == ApprovalStatus.PENDING, Approval.run_id.in_(run_ids))
                )
            )
            .scalars()
            .all()
        )
    for approval in approvals:
        approval.status = ApprovalStatus.EXPIRED
        approval.decided_at = utcnow()
        approval.decided_by = "system"
        approval.comment = "the agent run died before a decision"
    await session.flush()

    # Labs stuck in a run-owned state with no live run left behind them.
    labs = (
        (await session.execute(select(Lab).where(Lab.state.in_(list(lab_rollback))).with_for_update())).scalars().all()
    )
    rolled = 0
    for lab in labs:
        still_running = (
            await session.execute(
                select(AgentRun.id).where(AgentRun.lab_id == lab.id, AgentRun.status.in_(ACTIVE_RUN_STATES)).limit(1)
            )
        ).first()
        if still_running is None:
            target = lab_rollback[lab.state]
            await transition_lab(
                session,
                lab.tenant_id,
                lab,
                target(lab) if callable(target) else target,
                actor="system",
                reason="the agent run that owned this lab died (worker restart/crash)",
                error="agent run died",
            )
            rolled += 1
    await session.flush()
    return {"runs": len(runs), "approvals": len(approvals), "labs": rolled}


async def list_recent_approvals(session: AsyncSession, tenant_id: str, *, limit: int = 20) -> Sequence[Approval]:
    stmt = (
        select(Approval)
        .where(Approval.tenant_id == tenant_id, Approval.status != ApprovalStatus.PENDING)
        .order_by(Approval.decided_at.desc())
        .limit(limit)
    )
    return (await session.execute(stmt)).scalars().all()


async def count_active_runs(session: AsyncSession, tenant_id: str) -> int:
    from sqlalchemy import func

    stmt = select(func.count()).where(AgentRun.tenant_id == tenant_id, AgentRun.status.in_(ACTIVE_RUN_STATES))
    return int((await session.execute(stmt)).scalar_one())


async def lab_names(session: AsyncSession, tenant_id: str, ids: Iterable[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    stmt = select(Lab.id, Lab.name).where(Lab.tenant_id == tenant_id, Lab.id.in_(wanted))
    return {row.id: row.name for row in (await session.execute(stmt)).all()}


# --------------------------------------------------------------------------- token usage


@dataclass(frozen=True)
class Usage:
    """Tokens consumed by a set of agent runs (thinking tokens count as output)."""

    input_tokens: int = 0
    output_tokens: int = 0
    runs: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


_SUM_IN = func.coalesce(func.sum(AgentRun.input_tokens), 0)
_SUM_OUT = func.coalesce(func.sum(AgentRun.output_tokens), 0)


async def usage_total(session: AsyncSession, tenant_id: str, *, lab_id: uuid.UUID | str | None = None) -> Usage:
    stmt = select(_SUM_IN, _SUM_OUT, func.count(AgentRun.id)).where(AgentRun.tenant_id == tenant_id)
    if lab_id is not None:
        stmt = stmt.where(AgentRun.lab_id == _uuid(lab_id))
    i, o, n = (await session.execute(stmt)).one()
    return Usage(int(i), int(o), int(n))


async def usage_by_lab(session: AsyncSession, tenant_id: str) -> dict[uuid.UUID, Usage]:
    """lab_id → usage, for every lab that ran at least one agent (runs without a lab are excluded)."""
    stmt = (
        select(AgentRun.lab_id, _SUM_IN, _SUM_OUT, func.count(AgentRun.id))
        .where(AgentRun.tenant_id == tenant_id, AgentRun.lab_id.is_not(None))
        .group_by(AgentRun.lab_id)
    )
    return {lab: Usage(int(i), int(o), int(n)) for lab, i, o, n in (await session.execute(stmt)).all() if lab}


async def usage_by_agent(
    session: AsyncSession, tenant_id: str, *, lab_id: uuid.UUID | str | None = None
) -> dict[str, Usage]:
    stmt = (
        select(AgentRun.agent, _SUM_IN, _SUM_OUT, func.count(AgentRun.id))
        .where(AgentRun.tenant_id == tenant_id)
        .group_by(AgentRun.agent)
        .order_by(AgentRun.agent)
    )
    if lab_id is not None:
        stmt = stmt.where(AgentRun.lab_id == _uuid(lab_id))
    return {agent: Usage(int(i), int(o), int(n)) for agent, i, o, n in (await session.execute(stmt)).all()}


async def max_event_seq(session: AsyncSession, tenant_id: str, run_id: uuid.UUID | str) -> int:
    stmt = select(func.coalesce(func.max(AgentEvent.seq), 0)).where(
        AgentEvent.tenant_id == tenant_id, AgentEvent.run_id == _uuid(run_id)
    )
    return int((await session.execute(stmt)).scalar_one())


async def active_runs(
    session: AsyncSession,
    tenant_id: str,
    *,
    lab_id: uuid.UUID | str | None = None,
    agent: str | None = None,
    source: str | None = None,
) -> Sequence[AgentRun]:
    stmt = select(AgentRun).where(AgentRun.tenant_id == tenant_id, AgentRun.status.in_(ACTIVE_RUN_STATES))
    if lab_id is not None:
        stmt = stmt.where(AgentRun.lab_id == _uuid(lab_id))
    if agent is not None:
        stmt = stmt.where(AgentRun.agent == agent)
    if source is not None:
        stmt = stmt.where(AgentRun.source == source)
    return (await session.execute(stmt.order_by(AgentRun.created_at.desc()))).scalars().all()
