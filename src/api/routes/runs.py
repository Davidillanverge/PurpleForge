"""Agent runs: launch, inspect, cancel, and stream events (SSE)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from api import services
from api.deps import BrokerDep, PrincipalDep, RunnerDep, SessionDep, SettingsDep
from api.schemas import AgentInfo, ApprovalOut, EventOut, RunCreate, RunOut
from api.sse import run_event_stream
from db import repository as repo

router = APIRouter(prefix="/api", tags=["runs"])


@router.get("/agents", response_model=list[AgentInfo])
async def list_agents(runner: RunnerDep, principal: PrincipalDep):
    return [
        AgentInfo(
            name=s.name,
            description=s.description,
            requires_lab=s.requires_lab,
            allowed_states=sorted(s.allowed_states, key=lambda x: x.value),
        )
        for s in runner.registry.values()
    ]


@router.get("/brains", response_model=list[services.BrainInfo])
async def list_brains(session: SessionDep, principal: PrincipalDep, settings: SettingsDep):
    """Brains an agent run can use here: the LLM API engine and/or your Claude subscription."""
    return await services.brains(session, principal, settings)


@router.post("/runs", response_model=RunOut, status_code=status.HTTP_202_ACCEPTED)
async def start_run(body: RunCreate, runner: RunnerDep, principal: PrincipalDep):
    run = await runner.start(
        principal, body.agent, lab_id=body.lab_id, instructions=body.instructions, brain=body.brain
    )
    return _out(run, runner)


@router.get("/runs", response_model=list[RunOut])
async def list_runs(
    session: SessionDep, principal: PrincipalDep, runner: RunnerDep, lab_id: uuid.UUID | None = None, limit: int = 50
):
    runs = await repo.list_runs(session, principal.tenant, lab_id=lab_id, limit=min(limit, 500))
    return [_out(r, runner) for r in runs]


@router.get("/runs/{run_id}", response_model=RunOut)
async def get_run(run_id: uuid.UUID, session: SessionDep, principal: PrincipalDep, runner: RunnerDep):
    return _out(await repo.get_run(session, principal.tenant, run_id), runner)


@router.post("/runs/{run_id}/cancel", response_model=RunOut)
async def cancel_run(run_id: uuid.UUID, request: Request, principal: PrincipalDep, runner: RunnerDep):
    async with request.app.state.sessionmaker() as s:
        run = await repo.get_run(s, principal.tenant, run_id)  # tenant check before touching the task
    if run.source == "mcp":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "MCP runs are driven by Claude Code: deny the pending approval to stop one before it touches infrastructure",
        )
    if not await runner.cancel(run_id, tenant=principal.tenant):
        raise HTTPException(status.HTTP_409_CONFLICT, "run is not active")
    async with request.app.state.sessionmaker() as s:
        return _out(await repo.get_run(s, principal.tenant, run_id), runner)


@router.get("/runs/{run_id}/events", response_model=list[EventOut])
async def list_events(run_id: uuid.UUID, session: SessionDep, principal: PrincipalDep, after: int = 0):
    await repo.get_run(session, principal.tenant, run_id)
    return await repo.list_events(session, principal.tenant, run_id, after_seq=after)


@router.get("/runs/{run_id}/approvals", response_model=list[ApprovalOut])
async def run_approvals(run_id: uuid.UUID, session: SessionDep, principal: PrincipalDep):
    await repo.get_run(session, principal.tenant, run_id)
    return await repo.list_run_approvals(session, principal.tenant, run_id)


@router.get("/runs/{run_id}/stream")
async def stream_events(
    run_id: uuid.UUID,
    request: Request,
    principal: PrincipalDep,
    runner: RunnerDep,
    broker: BrokerDep,
    settings: SettingsDep,
    after: int = 0,
    last_event_id: Annotated[str | None, Header()] = None,
):
    """SSE: replays the run's events after ``after`` / ``Last-Event-ID``, then
    streams live ones; ends with an ``end`` event carrying the final status."""
    if last_event_id and last_event_id.isdigit():
        after = max(after, int(last_event_id))
    async with request.app.state.sessionmaker() as s:
        await repo.get_run(s, principal.tenant, run_id)  # 404 before opening the stream
    gen = run_event_stream(
        sessionmaker=request.app.state.sessionmaker,
        broker=broker,
        tenant_id=principal.tenant,
        run_id=run_id,
        after_seq=after,
        heartbeat=settings.sse_heartbeat_seconds,
    )
    return StreamingResponse(
        gen,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


def _out(run, runner) -> RunOut:
    out = RunOut.model_validate(run)
    out.active = not run.status.is_terminal  # in flight on any worker
    return out
