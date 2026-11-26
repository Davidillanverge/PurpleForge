"""Approver for agents whose tools run in ANOTHER process than the API (MCP-backed
brains). Same contract as the in-process runner approver: an Approval row in the
shared table, a human decides it in the dashboard/API, no decision before the
timeout ⇒ denied (fail closed). The decision is polled from the DB because the
deciding API process can't reach a Future in this process."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.engine import ApprovalDecision, ApprovalRequest
from db import repository as repo
from db.session import transaction
from db.states import ApprovalStatus


def db_polling_approver(
    sessionmaker: async_sessionmaker[AsyncSession],
    tenant: str,
    *,
    timeout_seconds: float,
    poll_seconds: float = 1.0,
) -> Callable[[ApprovalRequest], Awaitable[ApprovalDecision]]:
    async def approver(request: ApprovalRequest) -> ApprovalDecision:
        async with transaction(sessionmaker) as s:
            approval = await repo.create_approval(s, tenant, request)
        approval_id = approval.id
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            while True:
                async with sessionmaker() as s:
                    current = await repo.get_approval(s, tenant, approval_id)
                if current.status is not ApprovalStatus.PENDING:
                    return ApprovalDecision(
                        approved=current.status is ApprovalStatus.APPROVED,
                        by=current.decided_by,
                        comment=current.comment,
                    )
                if asyncio.get_running_loop().time() >= deadline:
                    async with transaction(sessionmaker) as s:
                        if await repo.expire_approval(s, tenant, approval_id):
                            return ApprovalDecision(approved=False, by="system", comment="approval timed out")
                    continue  # a human decided at the last moment: read it on the next loop
                await asyncio.sleep(poll_seconds)
        except asyncio.CancelledError:
            # run killed while waiting: never leave a PENDING approval behind
            async with transaction(sessionmaker) as s:
                await repo.expire_approval(s, tenant, approval_id)
            raise

    return approver


async def expire_pending_for_run(sessionmaker: async_sessionmaker[AsyncSession], tenant: str, run_id: object) -> int:
    """Safety net after a run ends: no approval of a dead run may stay clickable."""
    expired = 0
    async with transaction(sessionmaker) as s:
        for a in await repo.list_run_approvals(s, tenant, run_id):  # type: ignore[arg-type]
            if a.status is ApprovalStatus.PENDING and await repo.expire_approval(s, tenant, a.id):
                expired += 1
    return expired
