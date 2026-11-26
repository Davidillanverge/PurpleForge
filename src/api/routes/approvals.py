"""Human approval gate for gated tool calls (e.g. deploy-operator's `forge deploy`)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from api.deps import PrincipalDep, RunnerDep, SessionDep
from api.schemas import ApprovalDecisionIn, ApprovalOut
from db import repository as repo

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


@router.get("", response_model=list[ApprovalOut])
async def pending(session: SessionDep, principal: PrincipalDep):
    return await repo.list_pending_approvals(session, principal.tenant)


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_approval(approval_id: uuid.UUID, session: SessionDep, principal: PrincipalDep):
    return await repo.get_approval(session, principal.tenant, approval_id)


@router.post("/{approval_id}/decision", response_model=ApprovalOut)
async def decide(approval_id: uuid.UUID, body: ApprovalDecisionIn, principal: PrincipalDep, runner: RunnerDep):
    """Approve or deny. The decider is the authenticated human; a decision is
    final (a second one is a 409) and the waiting agent resumes immediately."""
    return await runner.decide(principal, approval_id, approved=body.approved, comment=body.comment)
