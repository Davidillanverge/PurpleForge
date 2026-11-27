"""Lab operations for the MCP mode — thin orchestration over the shared core.

Nothing here re-implements a rule: lab use-cases come from ``api.services``,
forge runs through ``agents.tools.ForgeTool`` (spec lock, flag policy, env
scrubbing), allowed/running states from the ``api.registry`` AgentSpecs, and the
lab's next state from ``core.outcomes``. What this module adds is the recording
(MCP runs and events go to the same tables the dashboard streams from) and the
asynchronous human approval for infra-touching operations.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import timedelta
from typing import Any

from agents.deploy_operator import DeployOperatorAgent, DeployPreconditionError, Mode
from agents.events import EventType
from agents.lab_designer import LabDesignerAgent
from agents.tools import ForgeInput, ForgeTool, truncate
from agents.validator import ValidatorAgent, ValidatorPreconditionError
from api import integrations, services
from api.registry import DEPLOYER, DESIGNER, TEARDOWN, VALIDATOR, AgentSpec, OutcomeContext
from core.outcomes import Outcome, deploy_outcome, teardown_outcome, validate_outcome
from db import repository as repo
from db.base import utcnow
from db.models import AgentRun, Lab
from db.recorder import Recorder
from db.session import transaction
from db.states import ApprovalStatus, LabState
from llm.provider import ToolCall
from mcp_server.context import McpContext

PROVIDER_LABEL = "claude-code (mcp)"


class McpError(RuntimeError):
    """A refusal or precondition the MCP client should read and act on."""


# --------------------------------------------------------------------------- recording


async def _lab(ctx: McpContext, name: str, *, for_update: bool = False, session: Any = None) -> Lab:
    async def load(s: Any) -> Lab:
        lab = await repo.get_lab_by_name(s, ctx.tenant, name)
        if lab is None:
            raise McpError(f"no lab named {name!r} (lab_list shows them; lab_create makes one)")
        if for_update:
            lab = await repo.get_lab(s, ctx.tenant, lab.id, for_update=True)
        return lab

    if session is not None:
        return await load(session)
    async with ctx.sessionmaker() as s:
        return await load(s)


async def _start_run(ctx: McpContext, lab_name: str, spec: AgentSpec, task: str) -> tuple[AgentRun, Lab, Recorder]:
    """Lock the lab, check the agent may start, create the MCP run and move the lab into
    the agent's running state — exactly what the standalone runner does."""
    async with transaction(ctx.sessionmaker) as s:
        lab = await _lab(ctx, lab_name, for_update=True, session=s)
        if spec.allowed_states and lab.state not in spec.allowed_states:
            allowed = ", ".join(sorted(x.value for x in spec.allowed_states))
            raise McpError(f"{spec.name} can't start while {lab_name} is {lab.state.value} (needs: {allowed})")
        run = await repo.create_run(
            s,
            ctx.tenant,
            agent=spec.name,
            task=task,
            lab_id=lab.id,
            created_by=ctx.principal.actor,
            worker_id=ctx.worker_id,
            source="mcp",
        )
        if spec.running_state is not None:
            await repo.transition_lab(
                s,
                ctx.tenant,
                lab,
                spec.running_state,
                actor=ctx.principal.actor,
                reason=f"{spec.name} started from Claude Code (MCP)",
                run_id=run.id,
            )
    rec = Recorder(ctx.sessionmaker, ctx.tenant, run.id, spec.name)
    await rec.emit(
        EventType.RUN_STARTED, task=task, model=None, provider=PROVIDER_LABEL, tools=["forge"], source="mcp", limits={}
    )
    return run, lab, rec


async def _finish(ctx: McpContext, rec: Recorder, lab_id: uuid.UUID, spec: AgentSpec, outcome: Outcome) -> Outcome:
    async with transaction(ctx.sessionmaker) as s:
        lab = await repo.get_lab(s, ctx.tenant, lab_id, for_update=True)
        if lab.state is spec.running_state:  # don't clobber a state someone else set meanwhile
            await repo.transition_lab(
                s,
                ctx.tenant,
                lab,
                outcome.target,
                actor=f"agent:{spec.name}",
                reason=outcome.reason,
                run_id=rec.run_id,
                error=outcome.error,
            )
    terminal = EventType.RUN_COMPLETED if outcome.error is None else EventType.RUN_FAILED
    await rec.emit(terminal, output=outcome.reason, error=outcome.error)
    return outcome


async def _forge(
    rec: Recorder,
    tool: ForgeTool,
    subcommand: str,
    args: list[str],
    *,
    call_id: str | None = None,
    announce: bool = True,
) -> Any:
    call_id = call_id or f"mcp-{uuid.uuid4().hex[:12]}"
    if announce:
        await rec.emit(
            EventType.TOOL_CALL, id=call_id, name="forge", arguments={"subcommand": subcommand, "args": args}
        )
    started = asyncio.get_running_loop().time()
    result = await tool.run(ForgeInput(subcommand=subcommand, args=args, timeout_seconds=14_400))
    await rec.emit(
        EventType.TOOL_RESULT,
        id=call_id,
        name="forge",
        is_error=result.is_error,
        content=truncate(result.content, 4_000),
        data=result.data,
        duration_ms=int((asyncio.get_running_loop().time() - started) * 1000),
    )
    return result


# --------------------------------------------------------------------------- deterministic (no agent run)


async def create_lab(ctx: McpContext, name: str, description: str, spec_path: str | None) -> Lab:
    from api.schemas import LabCreate

    body = LabCreate(name=name, description=description, spec_path=spec_path)
    async with transaction(ctx.sessionmaker) as s:
        return await services.create_lab(
            s, ctx.principal, ctx.app, name=body.name, description=body.description, spec_path=body.spec_path
        )


async def check(ctx: McpContext, name: str) -> services.CompileOutcome:
    async with transaction(ctx.sessionmaker) as s:
        lab = await _lab(ctx, name, session=s)
        return (await services.check_lab(s, ctx.principal, ctx.app, lab.id))[1]


async def compile_(ctx: McpContext, name: str) -> tuple[Lab, services.CompileOutcome]:
    async with transaction(ctx.sessionmaker) as s:
        lab = await _lab(ctx, name, session=s)
        return await services.compile_lab(s, ctx.principal, ctx.app, lab.id)


async def generate(ctx: McpContext, name: str) -> services.GenerateOutcome:
    async with transaction(ctx.sessionmaker) as s:
        lab = await _lab(ctx, name, session=s)
        return (await services.generate_lab(s, ctx.principal, ctx.app, lab.id))[1]


# --------------------------------------------------------------------------- design (Claude Code writes the spec)


async def design_start(ctx: McpContext, name: str, request: str) -> tuple[AgentRun, str]:
    lab = await _lab(ctx, name)
    expected = LabDesignerAgent.spec_rel(lab.name)
    if lab.spec_path and lab.spec_path != expected:
        raise McpError(f"the designer writes {expected}; this lab uses {lab.spec_path}")
    designer = LabDesignerAgent(None, repo_root=ctx.app.repo_root)  # type: ignore[arg-type]  # prompt only
    full_request = "\n\n".join(x for x in (lab.description, request) if x and x.strip())
    task = designer.task(lab.name, full_request, existing=(ctx.app.repo_root / expected).is_file())
    run, _, _ = await _start_run(ctx, name, DESIGNER, f"design lab {lab.name} → {expected} (Claude Code)")
    return run, task


async def design_finish(ctx: McpContext, name: str) -> Outcome:
    """The spec on disk decides (same outcome as the standalone designer), not the client."""
    lab = await _lab(ctx, name)
    async with ctx.sessionmaker() as s:
        runs = await repo.active_runs(s, ctx.tenant, lab_id=lab.id, agent=DESIGNER.name, source="mcp")
    if not runs or lab.state is not LabState.DESIGNING:
        raise McpError(f"{name} has no design in progress — call lab_design_start first")
    rec = Recorder(ctx.sessionmaker, ctx.tenant, runs[0].id, DESIGNER.name)
    assert DESIGNER.outcome is not None
    async with transaction(ctx.sessionmaker) as s:
        locked = await repo.get_lab(s, ctx.tenant, lab.id, for_update=True)
        outcome = await DESIGNER.outcome(
            OutcomeContext(
                session=s,
                lab=locked,
                result=None,
                events=await rec.events(),
                repo_root=ctx.app.repo_root,
                previous_state=None,
            )
        )
        await repo.transition_lab(
            s,
            ctx.tenant,
            locked,
            outcome.target,
            actor=f"agent:{DESIGNER.name}",
            reason=outcome.reason,
            run_id=rec.run_id,
            error=outcome.error,
        )
    await rec.emit(
        EventType.RUN_COMPLETED if outcome.target is LabState.DESIGNED else EventType.RUN_FAILED,
        output=outcome.reason,
        error=outcome.error,
    )
    return outcome


# --------------------------------------------------------------------------- gated: deploy / teardown


async def _await_decision(ctx: McpContext, approval_id: uuid.UUID) -> Any:
    """Poll the shared approvals table until a human decides (or it times out)."""
    deadline = utcnow() + timedelta(seconds=ctx.app.approval_timeout_seconds)
    while True:
        async with ctx.sessionmaker() as s:
            approval = await repo.get_approval(s, ctx.tenant, approval_id)
        if approval.status is not ApprovalStatus.PENDING:
            return approval
        if utcnow() >= deadline:
            async with transaction(ctx.sessionmaker) as s:
                if await repo.expire_approval(s, ctx.tenant, approval_id):
                    return await repo.get_approval(s, ctx.tenant, approval_id)
        await asyncio.sleep(ctx.mcp.approval_poll_seconds)


async def gated(ctx: McpContext, name: str, mode: Mode) -> tuple[AgentRun, uuid.UUID]:
    """Start a deploy/teardown: preflight, run + human approval request, then hand the
    rest to a background task. Returns (run, approval id) immediately."""
    spec = DEPLOYER if mode is Mode.DEPLOY else TEARDOWN
    lab = await _lab(ctx, name)
    if not lab.spec_path:
        raise McpError(f"{name} has no spec")
    spec_path: str = lab.spec_path
    try:  # same toolchain preflight as the standalone deploy-operator
        DeployOperatorAgent(None, repo_root=ctx.app.repo_root).lab_context(spec_path, mode)  # type: ignore[arg-type]
    except DeployPreconditionError as exc:
        raise McpError(str(exc)) from exc
    run, lab, rec = await _start_run(ctx, name, spec, f"{mode.value} lab {lab.name} ({spec_path}) from Claude Code")
    overlay = await integrations.load_tenant_env(ctx.sessionmaker, ctx.tenant, ctx.cipher)
    tool = ForgeTool(
        ctx.app.repo_root,
        allowed_subcommands={"generate", "deploy"} if mode is Mode.DEPLOY else {"teardown"},
        spec_lock=spec_path,
        forbidden_flags={"--skip-guardrail"},
        required_flags={"teardown": {"--force"}},
        allow_cloud_credentials=True,
        environ=integrations.apply(os.environ, overlay),  # UI-configured integrations over .env
    )
    if mode is Mode.DEPLOY:  # fresh scripts BEFORE the human looks at the request
        gen = await _forge(rec, tool, "generate", [spec_path])
        if gen.is_error:
            await _finish(ctx, rec, lab.id, spec, deploy_outcome(await rec.events(), "forge generate failed"))
            raise McpError(f"forge generate failed — nothing deployed:\n{truncate(gen.content, 2000)}")
    sub, args = ("deploy", [spec_path]) if mode is Mode.DEPLOY else ("teardown", [spec_path, "--force"])
    inp = ForgeInput(subcommand=sub, args=args)
    reason = tool.needs_approval(inp) or f"`forge {sub}` acts on live infrastructure"
    call = ToolCall(id=f"mcp-{uuid.uuid4().hex[:12]}", name="forge", arguments={"subcommand": sub, "args": args})
    await rec.emit(EventType.TOOL_CALL, id=call.id, name=call.name, arguments=call.arguments)
    await rec.emit(EventType.APPROVAL_REQUESTED, id=call.id, name=call.name, arguments=call.arguments, reason=reason)
    from agents.engine import ApprovalRequest

    async with transaction(ctx.sessionmaker) as s:
        approval = await repo.create_approval(
            s, ctx.tenant, ApprovalRequest(run_id=str(run.id), agent=spec.name, tool_call=call, reason=reason)
        )
    ctx.spawn(run.id, _gated_tail(ctx, rec, lab, spec, mode, tool, call, approval.id))
    return run, approval.id


async def _gated_tail(
    ctx: McpContext,
    rec: Recorder,
    lab: Lab,
    spec: AgentSpec,
    mode: Mode,
    tool: ForgeTool,
    call: ToolCall,
    approval_id: uuid.UUID,
) -> Outcome:
    previous = None
    async with ctx.sessionmaker() as s:
        took = [
            t
            for t in await repo.list_transitions(s, ctx.tenant, lab.id)
            if t.run_id == rec.run_id and t.to_state is spec.running_state
        ]
        previous = took[-1].from_state if took else None
    try:
        decision = await _await_decision(ctx, approval_id)
        approved = decision.status is ApprovalStatus.APPROVED
        await rec.emit(
            EventType.APPROVAL_RESOLVED, id=call.id, approved=approved, by=decision.decided_by, comment=decision.comment
        )
        if approved:
            await _forge(
                rec, tool, call.arguments["subcommand"], call.arguments["args"], call_id=call.id, announce=False
            )
        else:
            await rec.emit(
                EventType.TOOL_RESULT,
                id=call.id,
                name="forge",
                is_error=True,
                content=f"denied by human approval gate ({decision.status.value})",
                data={},
            )
        events = await rec.events()
        outcome = deploy_outcome(events) if mode is Mode.DEPLOY else teardown_outcome(events, previous)
    except asyncio.CancelledError:
        # MCP server shutting down mid-operation: the next start's orphan recovery decides the lab state
        raise
    return await _finish(ctx, rec, lab.id, spec, outcome)


# --------------------------------------------------------------------------- validate (no approval: isolated lab)


async def validate(ctx: McpContext, name: str) -> AgentRun:
    lab = await _lab(ctx, name)
    if not lab.spec_path:
        raise McpError(f"{name} has no spec")
    spec_path: str = lab.spec_path
    try:
        ValidatorAgent(None, repo_root=ctx.app.repo_root).lab_context(spec_path)  # type: ignore[arg-type]
    except ValidatorPreconditionError as exc:
        raise McpError(str(exc)) from exc
    run, lab, rec = await _start_run(ctx, name, VALIDATOR, f"validate lab {lab.name} ({spec_path}) from Claude Code")
    tool = ForgeTool(ctx.app.repo_root, allowed_subcommands={"validate"}, spec_lock=spec_path)

    async def tail() -> Outcome:
        since = time.time()
        await _forge(rec, tool, "validate", [spec_path, "--run"])
        lab_dir = ctx.app.repo_root / "generated" / lab.name
        return await _finish(ctx, rec, lab.id, VALIDATOR, validate_outcome(await rec.events(), lab_dir, since))

    ctx.spawn(run.id, tail())
    return run
