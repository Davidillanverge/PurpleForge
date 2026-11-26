"""Agents the API can launch, and how each one couples to the lab FSM.

A run's effect on its lab is decided by a deterministic **outcome** computed from
what actually happened (the persisted tool calls/results and the files on disk) —
never from the agent's own claim of success. E.g. a deploy is DEPLOYED only if
`forge deploy <its spec>` exited 0.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from agents.budget import BudgetLimits
from agents.catalog_author import CatalogAuthorAgent
from agents.deploy_operator import DeployOperatorAgent, DeployPreconditionError, Mode
from agents.engine import AgentResult, Approver
from agents.events import EventCallback
from agents.lab_designer import LabDesignerAgent
from agents.validator import ValidatorAgent, ValidatorPreconditionError
from api.forge_ops import SpecError, resolve_spec, run_forge
from db.models import AgentEvent, Lab
from db.states import LabState
from llm.provider import LLMProvider


class AgentPreconditionError(ValueError):
    """The agent can't start (missing spec/manifest/toolchain, wrong lab...). Maps to 422."""


@dataclass
class AgentContext:
    llm: LLMProvider
    repo_root: Path
    on_event: EventCallback
    approver: Approver
    lab: Lab | None
    instructions: str = ""
    limits: BudgetLimits | None = None


@dataclass
class PreparedRun:
    #: short human description stored on the AgentRun row
    task: str
    execute: Callable[[str], Awaitable[AgentResult]]  # run_id -> result


@dataclass
class OutcomeContext:
    session: AsyncSession
    lab: Lab
    result: AgentResult | None  # None: the run crashed or was cancelled
    events: Sequence[AgentEvent]
    repo_root: Path
    #: the state the lab was in right before this run took it over
    previous_state: LabState | None


@dataclass
class Outcome:
    target: LabState
    reason: str
    error: str | None = None


StateFn = Callable[[Lab], LabState]


@dataclass(frozen=True)
class AgentSpec:
    name: str
    description: str
    prepare: Callable[[AgentContext], PreparedRun]
    requires_lab: bool = True
    #: lab states in which the agent may start
    allowed_states: frozenset[LabState] = field(default_factory=frozenset)
    #: lab state while it runs (also serialises runs on one lab), then on success / failure
    running_state: LabState | None = None
    success_state: LabState | None = None
    failure_state: LabState | StateFn | None = None
    #: deterministic outcome overriding success/failure_state (see module docstring)
    outcome: Callable[[OutcomeContext], Awaitable[Outcome]] | None = None

    def failure_for(self, lab: Lab) -> LabState | None:
        return self.failure_state(lab) if callable(self.failure_state) else self.failure_state


# --------------------------------------------------------------------------- event helpers


def _calls_and_results(events: Sequence[AgentEvent]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    calls = {str(e.data.get("id")): e.data for e in events if e.type == "tool_call"}
    results = {str(e.data.get("id")): e.data for e in events if e.type == "tool_result"}
    return calls, results


def forge_call_succeeded(events: Sequence[AgentEvent], subcommand: str) -> bool:
    """Did a `forge <subcommand>` call actually run and exit 0?"""
    calls, results = _calls_and_results(events)
    for cid, call in calls.items():
        if call.get("name") == "forge" and (call.get("arguments") or {}).get("subcommand") == subcommand:
            res = results.get(cid) or {}
            if (res.get("data") or {}).get("exit_code") == 0:
                return True
    return False


def approved_action_ran(events: Sequence[AgentEvent]) -> bool:
    """Did any human-approved (= potentially infra-touching) tool call execute?"""
    _, results = _calls_and_results(events)
    approved = {str(e.data.get("id")) for e in events if e.type == "approval_resolved" and e.data.get("approved")}
    return any(cid in results for cid in approved)


# --------------------------------------------------------------------------- purple-validator


def _prepare_validator(ctx: AgentContext) -> PreparedRun:
    assert ctx.lab is not None
    if not ctx.lab.spec_path:
        raise AgentPreconditionError("lab has no spec_path")
    agent = ValidatorAgent(
        ctx.llm, repo_root=ctx.repo_root, on_event=ctx.on_event, approver=ctx.approver, limits=ctx.limits
    )
    try:
        agent.lab_context(ctx.lab.spec_path)
    except ValidatorPreconditionError as exc:
        raise AgentPreconditionError(str(exc)) from exc
    spec_path = ctx.lab.spec_path
    return PreparedRun(
        task=f"validate lab {ctx.lab.name} ({spec_path})",
        execute=lambda run_id: agent.run(spec_path, run_id=run_id, instructions=ctx.instructions),
    )


VALIDATOR = AgentSpec(
    name="purple-validator",
    description="Validate every injected vuln (applied + exploitable) and write lab-report.md",
    prepare=_prepare_validator,
    allowed_states=frozenset({LabState.DEPLOYED, LabState.VALIDATED}),
    running_state=LabState.VALIDATING,
    success_state=LabState.VALIDATED,
    # a failed validation run says nothing bad about the lab itself
    failure_state=LabState.DEPLOYED,
)


# --------------------------------------------------------------------------- lab-designer


def _prepare_designer(ctx: AgentContext) -> PreparedRun:
    assert ctx.lab is not None
    lab = ctx.lab
    expected = LabDesignerAgent.spec_rel(lab.name)
    if lab.spec_path and lab.spec_path != expected:
        raise AgentPreconditionError(f"the designer writes {expected}; this lab uses {lab.spec_path}")
    agent = LabDesignerAgent(
        ctx.llm, repo_root=ctx.repo_root, on_event=ctx.on_event, approver=ctx.approver, limits=ctx.limits
    )
    request = "\n\n".join(x for x in (lab.description, ctx.instructions) if x and x.strip())
    existing = (ctx.repo_root / expected).is_file()
    name = lab.name
    return PreparedRun(
        task=f"design lab {name} → {expected}",
        execute=lambda run_id: agent.run(name, request, existing=existing, run_id=run_id),
    )


async def _designer_outcome(ctx: OutcomeContext) -> Outcome:
    """The spec file on disk decides — not the agent's report."""
    lab = ctx.lab
    spec_rel = LabDesignerAgent.spec_rel(lab.name)
    try:
        _, data = resolve_spec(ctx.repo_root, spec_rel, lab.name)
    except SpecError as exc:
        back = LabState.DESIGNED if lab.spec_path else LabState.DRAFT
        return Outcome(back, f"lab-designer produced no valid spec: {exc}", error=str(exc))
    check = await run_forge(ctx.repo_root, "lab-spec", spec_rel, "--check-only", timeout=300)
    lab.spec_path = spec_rel
    lab.cloud = (data.get("lab") or {}).get("provider")
    verdict = "check-only PASS" if check.ok else f"check-only FAILED (exit {check.exit_code}) — fix before compiling"
    return Outcome(LabState.DESIGNED, f"lab-designer wrote {spec_rel}; {verdict}")


DESIGNER = AgentSpec(
    name="lab-designer",
    description="Natural-language request (lab description + notes) → specs/<lab>.yml, checked with forge",
    prepare=_prepare_designer,
    allowed_states=frozenset(
        {LabState.DRAFT, LabState.DESIGNED, LabState.COMPILED, LabState.READY, LabState.APPROVED, LabState.DESTROYED}
    ),
    running_state=LabState.DESIGNING,
    failure_state=lambda lab: LabState.DESIGNED if lab.spec_path else LabState.DRAFT,
    outcome=_designer_outcome,
)


# --------------------------------------------------------------------------- deploy-operator


def _prepare_deploy(mode: Mode) -> Callable[[AgentContext], PreparedRun]:
    def prepare(ctx: AgentContext) -> PreparedRun:
        assert ctx.lab is not None
        if not ctx.lab.spec_path:
            raise AgentPreconditionError("lab has no spec_path")
        agent = DeployOperatorAgent(
            ctx.llm, repo_root=ctx.repo_root, on_event=ctx.on_event, approver=ctx.approver, limits=ctx.limits
        )
        try:
            agent.lab_context(ctx.lab.spec_path, mode)  # spec + toolchain preflight, before any token
        except DeployPreconditionError as exc:
            raise AgentPreconditionError(str(exc)) from exc
        spec = ctx.lab.spec_path
        return PreparedRun(
            task=f"{mode.value} lab {ctx.lab.name} ({spec})",
            execute=lambda run_id: agent.run(spec, mode, run_id=run_id, instructions=ctx.instructions),
        )

    return prepare


async def _deploy_outcome(ctx: OutcomeContext) -> Outcome:
    if forge_call_succeeded(ctx.events, "deploy"):
        return Outcome(LabState.DEPLOYED, "forge deploy exited 0 (clean snapshot taken by deploy.sh)")
    if approved_action_ran(ctx.events):
        why = ctx.result.error if ctx.result and ctx.result.error else "forge deploy did not succeed"
        return Outcome(LabState.FAILED, f"deploy failed after touching infrastructure: {why}", error=why)
    return Outcome(LabState.READY, "deploy never touched infrastructure (no approved action ran) — re-approve to retry")


async def _teardown_outcome(ctx: OutcomeContext) -> Outcome:
    if forge_call_succeeded(ctx.events, "teardown"):
        return Outcome(LabState.DESTROYED, "forge teardown exited 0 (cost-zero verified)")
    if approved_action_ran(ctx.events):
        why = ctx.result.error if ctx.result and ctx.result.error else "forge teardown did not succeed"
        return Outcome(LabState.FAILED, f"teardown incomplete — resources may remain: {why}", error=why)
    back = (
        ctx.previous_state if ctx.previous_state in (LabState.DEPLOYED, LabState.VALIDATED, LabState.STOPPED) else None
    )
    if back is None:  # came from FAILED: stays failed (still possibly billable)
        return Outcome(LabState.FAILED, "teardown never ran — the lab still needs one", error="teardown not executed")
    return Outcome(back, "teardown never touched infrastructure (no approved action ran)")


DEPLOYER = AgentSpec(
    name="deploy-operator",
    description="Deploy an APPROVED lab: forge generate --plan → forge deploy (each infra action needs a human OK)",
    prepare=_prepare_deploy(Mode.DEPLOY),
    allowed_states=frozenset({LabState.APPROVED}),
    running_state=LabState.DEPLOYING,
    failure_state=LabState.FAILED,  # orphaned mid-deploy: infra state unknown → treat as possibly billable
    outcome=_deploy_outcome,
)

TEARDOWN = AgentSpec(
    name="deploy-operator-teardown",
    description="Tear a lab down to cost-zero: forge teardown --force + verification (needs a human OK)",
    prepare=_prepare_deploy(Mode.TEARDOWN),
    allowed_states=frozenset({LabState.DEPLOYED, LabState.VALIDATED, LabState.STOPPED, LabState.FAILED}),
    running_state=LabState.DESTROYING,
    failure_state=LabState.FAILED,
    outcome=_teardown_outcome,
)


# --------------------------------------------------------------------------- catalog-author


def _prepare_catalog(ctx: AgentContext) -> PreparedRun:
    if not ctx.instructions.strip():
        raise AgentPreconditionError("catalog-author needs a request (what to add or change)")
    agent = CatalogAuthorAgent(
        ctx.llm, repo_root=ctx.repo_root, on_event=ctx.on_event, approver=ctx.approver, limits=ctx.limits
    )
    request = ctx.instructions
    return PreparedRun(
        task=f"catalog: {request.strip().splitlines()[0][:120]}",
        execute=lambda run_id: agent.run(request, run_id=run_id),
    )


CATALOG = AgentSpec(
    name="catalog-author",
    description="Author/edit reusable catalog content (vulns, themes, defense) — validated with forge's schemas",
    prepare=_prepare_catalog,
    requires_lab=False,
)


def default_registry() -> dict[str, AgentSpec]:
    return {s.name: s for s in (DESIGNER, DEPLOYER, VALIDATOR, TEARDOWN, CATALOG)}
