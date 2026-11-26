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

from sqlalchemy.ext.asyncio import AsyncSession

from agents.budget import BudgetLimits
from agents.catalog_author import CatalogAuthorAgent
from agents.definitions import AgentDefinition
from agents.deploy_operator import DeployOperatorAgent, DeployPreconditionError, Mode
from agents.engine import AgentResult, Approver
from agents.events import EventCallback
from agents.lab_designer import LabDesignerAgent
from agents.validator import ValidatorAgent, ValidatorPreconditionError
from api.forge_ops import SpecError, resolve_spec, run_forge
from core.outcomes import (  # shared with the MCP mode
    Outcome,
    deploy_outcome,
    teardown_outcome,
)
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
    execute: Callable[[str], Awaitable[AgentResult]]  # run_id -> result (engine brain)
    #: what an external brain needs to run the SAME agent: full task, definition and toolset scope
    brief: str = ""
    definition: AgentDefinition | None = None
    lab_name: str | None = None
    spec_path: str | None = None


@dataclass
class OutcomeContext:
    session: AsyncSession
    lab: Lab
    result: AgentResult | None  # None: the run crashed or was cancelled
    events: Sequence[AgentEvent]
    repo_root: Path
    #: the state the lab was in right before this run took it over
    previous_state: LabState | None


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
        brief=agent.task(spec_path, ctx.instructions),
        definition=agent.definition,
        lab_name=ctx.lab.name,
        spec_path=spec_path,
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
        brief=agent.task(name, request, existing=existing),
        definition=agent.definition,
        lab_name=name,
        spec_path=expected,
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
            spec_rel, lab_name, _ = agent.lab_context(ctx.lab.spec_path, mode)  # spec + toolchain preflight
        except DeployPreconditionError as exc:
            raise AgentPreconditionError(str(exc)) from exc
        spec = ctx.lab.spec_path
        return PreparedRun(
            task=f"{mode.value} lab {ctx.lab.name} ({spec})",
            execute=lambda run_id: agent.run(spec, mode, run_id=run_id, instructions=ctx.instructions),
            brief=agent.task(spec_rel, lab_name, mode, ctx.instructions),
            definition=agent.definition,
            lab_name=ctx.lab.name,
            spec_path=spec_rel,
        )

    return prepare


async def _deploy_outcome(ctx: OutcomeContext) -> Outcome:
    return deploy_outcome(ctx.events, ctx.result.error if ctx.result else None)


async def _teardown_outcome(ctx: OutcomeContext) -> Outcome:
    return teardown_outcome(ctx.events, ctx.previous_state, ctx.result.error if ctx.result else None)


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
        brief=agent.task(request),
        definition=agent.definition,
    )


CATALOG = AgentSpec(
    name="catalog-author",
    description="Author/edit reusable catalog content (vulns, themes, defense) — validated with forge's schemas",
    prepare=_prepare_catalog,
    requires_lab=False,
)


def default_registry() -> dict[str, AgentSpec]:
    return {s.name: s for s in (DESIGNER, DEPLOYER, VALIDATOR, TEARDOWN, CATALOG)}
