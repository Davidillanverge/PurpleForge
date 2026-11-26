"""Lab lifecycle state machine and AgentRun / Approval statuses.

The lab FSM mirrors the CLAUDE.md flow:

    draft ─► designing ─► designed ─► compiled ─► ready ─► approved ─► deploying ─► deployed ─► validating ─► validated
          (lab-designer)          (forge lab-spec) (guardrail PASS) (HUMAN)  (deploy-operator:     (purple-validator)
                                                                              deploy.sh + snapshot)

Key rules encoded here:
- ``deploying`` is reachable ONLY from ``approved`` — no path skips the human gate.
- Approval is not inherited: editing the spec (back to ``designed``) or a failure
  sends the lab back through compile → guardrail → approval.
- ``destroyed`` is only reached through ``destroying`` (forge teardown).
- ``stopping`` / ``starting`` are the no-AI ``forge stop`` / ``forge start`` runs
  (deployed|validated ⇄ stopped); while they run nothing else may start on the lab.
- ``failed`` (a deploy/teardown went wrong; resources may exist) can only be left
  through ``destroying``: nobody can "forget" a half-deployed lab.
"""

from __future__ import annotations

from enum import Enum

from agents.engine import RunStatus


class LabState(str, Enum):
    DRAFT = "draft"
    DESIGNING = "designing"
    DESIGNED = "designed"
    COMPILED = "compiled"
    READY = "ready"
    APPROVED = "approved"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    VALIDATING = "validating"
    VALIDATED = "validated"
    STOPPING = "stopping"
    STOPPED = "stopped"
    STARTING = "starting"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    FAILED = "failed"


S = LabState
LAB_TRANSITIONS: dict[LabState, frozenset[LabState]] = {
    S.DRAFT: frozenset({S.DESIGNING, S.DESIGNED}),
    # the designer owns the spec while it runs; back to designed (spec written) or draft (none yet)
    S.DESIGNING: frozenset({S.DESIGNED, S.DRAFT}),
    S.DESIGNED: frozenset({S.DESIGNING, S.DESIGNED, S.COMPILED}),
    S.COMPILED: frozenset({S.DESIGNING, S.DESIGNED, S.READY}),
    S.READY: frozenset({S.DESIGNING, S.DESIGNED, S.APPROVED}),
    S.APPROVED: frozenset({S.DESIGNING, S.DESIGNED, S.DEPLOYING}),
    # READY: the deploy never touched infra (no approved action ran) — re-approval required
    S.DEPLOYING: frozenset({S.DEPLOYED, S.FAILED, S.READY}),
    S.DEPLOYED: frozenset({S.VALIDATING, S.STOPPING, S.STOPPED, S.DESTROYING}),
    S.VALIDATING: frozenset({S.VALIDATED, S.DEPLOYED, S.FAILED}),
    S.VALIDATED: frozenset({S.VALIDATING, S.DEPLOYED, S.STOPPING, S.STOPPED, S.DESTROYING}),
    # forge stop (stop.sh): powered off on success; a failed stop leaves the VMs as they
    # were (still running → deployed; validation isn't assumed to survive a failed stop)
    S.STOPPING: frozenset({S.STOPPED, S.DEPLOYED}),
    S.STOPPED: frozenset({S.STARTING, S.DEPLOYED, S.DESTROYING}),
    # forge start (start.sh): powered on + tunnel + connectivity check → deployed
    S.STARTING: frozenset({S.DEPLOYED, S.STOPPED}),
    # back to where it was when the teardown never touched infra (no approved action ran)
    S.DESTROYING: frozenset({S.DESTROYED, S.FAILED, S.DEPLOYED, S.VALIDATED, S.STOPPED}),
    S.DESTROYED: frozenset({S.DESIGNING, S.DESIGNED}),
    # a failed deploy/teardown may have left billable resources: the ONLY way out is a
    # teardown that verifies cost-zero (then destroyed → designed to start over)
    S.FAILED: frozenset({S.DESTROYING}),
}
del S

#: States in which cloud resources may exist (and cost money). FAILED is
#: included because a failed deploy can leave partial infra behind.
INFRA_STATES = frozenset(
    {
        LabState.DEPLOYING,
        LabState.DEPLOYED,
        LabState.VALIDATING,
        LabState.VALIDATED,
        LabState.STOPPING,
        LabState.STOPPED,
        LabState.STARTING,
        LabState.DESTROYING,
        LabState.FAILED,
    }
)


class InvalidTransition(ValueError):
    def __init__(self, current: LabState, target: LabState) -> None:
        allowed = ", ".join(sorted(s.value for s in LAB_TRANSITIONS[current])) or "none"
        super().__init__(f"lab cannot go {current.value} → {target.value} (allowed: {allowed})")
        self.current = current
        self.target = target


def check_transition(current: LabState, target: LabState) -> None:
    if target not in LAB_TRANSITIONS[current]:
        raise InvalidTransition(current, target)


class RunState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    BUDGET_EXCEEDED = "budget_exceeded"
    REFUSED = "refused"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in TERMINAL_RUN_STATES

    @classmethod
    def from_result(cls, status: RunStatus) -> RunState:
        return cls(status.value)


TERMINAL_RUN_STATES = frozenset(
    {RunState.COMPLETED, RunState.BUDGET_EXCEEDED, RunState.REFUSED, RunState.FAILED, RunState.CANCELLED}
)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ProviderKind(str, Enum):
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
