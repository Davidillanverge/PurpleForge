"""AgentRunner: launches agent runs as background tasks and owns their plumbing.

Per run it wires: the tenant's LLM pool → the agent; events → DB (durable log)
then broker (live SSE); tool approvals → an Approval row + a Future that the
approval endpoint resolves; and, when the run ends, the lab's FSM transition.

Runs live in the worker process that started them. Approval decisions and
cancellations may arrive at ANY worker: they are applied locally when this
worker owns the run, and otherwise relayed over the broker's control channel
to the owner. Each worker heartbeats through the broker; orphan recovery (at
startup and periodically) only fails runs whose worker is gone.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import socket
import uuid
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.engine import AgentResult, ApprovalDecision, ApprovalRequest, RunStatus, relay_failover
from agents.events import AgentEvent
from api.auth import Principal
from api.broker import Broker
from api.registry import AgentContext, AgentPreconditionError, AgentSpec, OutcomeContext, PreparedRun
from api.settings import AppSettings
from db import repository as repo
from db.base import utcnow
from db.crypto import SecretCipher
from db.models import AgentRun
from db.session import transaction
from db.states import LabState, RunState
from llm.provider import LLMProvider

log = logging.getLogger(__name__)

LLMFactory = Callable[[AsyncSession, str], Awaitable[LLMProvider]]


class UnknownAgent(LookupError):
    pass


class LabBusy(RuntimeError):
    """The lab isn't in a state this agent may start from (maps to 409)."""


class AgentRunner:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        broker: Broker,
        settings: AppSettings,
        registry: dict[str, AgentSpec],
        *,
        cipher: SecretCipher | None = None,
        llm_factory: LLMFactory | None = None,
    ) -> None:
        self.sessionmaker = sessionmaker
        self.broker = broker
        self.settings = settings
        self.registry = registry
        self.cipher = cipher
        self.llm_factory = llm_factory or self._default_llm
        self._tasks: dict[uuid.UUID, asyncio.Task[None]] = {}
        self._pending: dict[uuid.UUID, asyncio.Future[ApprovalDecision]] = {}
        self._background: asyncio.Task[None] | None = None
        #: unique per process lifetime; stored on every run this worker executes
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{secrets.token_hex(3)}"

    async def _default_llm(self, session: AsyncSession, tenant_id: str) -> LLMProvider:
        return await repo.build_tenant_pool(session, tenant_id, cipher=self.cipher, on_failover=relay_failover)

    # ------------------------------------------------------------------ start
    async def start(
        self, principal: Principal, agent: str, *, lab_id: uuid.UUID | None = None, instructions: str = ""
    ) -> AgentRun:
        spec = self.registry.get(agent)
        if spec is None:
            raise UnknownAgent(f"unknown agent {agent!r}; available: {', '.join(sorted(self.registry))}")
        if spec.requires_lab and lab_id is None:
            raise AgentPreconditionError(f"agent {agent} needs a lab")
        tenant = principal.tenant

        # 1) check the lab and build the LLM; 2) prepare (preconditions) outside any transaction
        async with transaction(self.sessionmaker) as s:
            lab = await repo.get_lab(s, tenant, lab_id) if lab_id else None
            if lab is not None:
                self._check_state(spec, lab.state)
            llm = await self.llm_factory(s, tenant)
        try:
            prepared = spec.prepare(
                AgentContext(
                    llm=llm,
                    repo_root=self.settings.repo_root,
                    on_event=self._event_sink(tenant),
                    approver=self._approver(tenant),
                    lab=lab,
                    instructions=instructions,
                )
            )
        except Exception:
            await llm.aclose()
            raise

        # 3) re-lock the lab, create the run and move the lab into the run-owned state
        try:
            async with transaction(self.sessionmaker) as s:
                if lab_id is not None:
                    lab = await repo.get_lab(s, tenant, lab_id, for_update=True)
                    self._check_state(spec, lab.state)  # someone may have raced us
                run = await repo.create_run(
                    s,
                    tenant,
                    agent=spec.name,
                    task=prepared.task,
                    lab_id=lab_id,
                    created_by=principal.actor,
                    worker_id=self.worker_id,
                )
                if lab is not None and spec.running_state is not None:
                    await repo.transition_lab(
                        s,
                        tenant,
                        lab,
                        spec.running_state,
                        actor=principal.actor,
                        reason=f"{spec.name} run started",
                        run_id=run.id,
                    )
        except Exception:
            await llm.aclose()
            raise

        self._tasks[run.id] = asyncio.create_task(
            self._execute(tenant, spec, prepared, run.id, lab_id, llm), name=f"agent-run-{run.id}"
        )
        return run

    @staticmethod
    def _check_state(spec: AgentSpec, state: LabState) -> None:
        if spec.allowed_states and state not in spec.allowed_states:
            allowed = ", ".join(sorted(s.value for s in spec.allowed_states))
            raise LabBusy(f"{spec.name} can't start while the lab is {state.value} (needs: {allowed})")

    # ------------------------------------------------------------------ execution
    async def _execute(
        self,
        tenant: str,
        spec: AgentSpec,
        prepared: PreparedRun,
        run_id: uuid.UUID,
        lab_id: uuid.UUID | None,
        llm: LLMProvider,
    ) -> None:
        result: AgentResult | None = None
        status, error = RunState.FAILED, None
        try:
            result = await prepared.execute(str(run_id))
        except asyncio.CancelledError:
            status, error = RunState.CANCELLED, "cancelled by operator"
        except Exception as exc:  # noqa: BLE001 - recorded on the run
            log.exception("agent run %s crashed", run_id)
            error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                await self._finalize(tenant, spec, run_id, lab_id, result, status, error)
            except Exception:  # noqa: BLE001
                log.exception("failed to finalize agent run %s", run_id)
            try:
                await llm.aclose()
            except Exception:  # noqa: BLE001
                log.exception("failed to close LLM for run %s", run_id)
            with contextlib.suppress(Exception):
                await self.broker.close_run(str(run_id))
            self._tasks.pop(run_id, None)

    async def _finalize(
        self,
        tenant: str,
        spec: AgentSpec,
        run_id: uuid.UUID,
        lab_id: uuid.UUID | None,
        result: AgentResult | None,
        status: RunState,
        error: str | None,
    ) -> None:
        async with transaction(self.sessionmaker) as s:
            if result is not None:
                await repo.finish_run(s, tenant, result)
            else:
                await repo.fail_run(s, tenant, run_id, status=status, error=error)
            if lab_id is None or spec.running_state is None:
                return
            lab = await repo.get_lab(s, tenant, lab_id, for_update=True)
            if lab.state is not spec.running_state:
                return  # moved by someone else meanwhile; don't clobber
            if spec.outcome is not None:
                # deterministic: decided from what actually happened, not from the agent's claim
                took_over = [
                    t
                    for t in await repo.list_transitions(s, tenant, lab_id)
                    if t.run_id == run_id and t.to_state is spec.running_state
                ]
                decided = await spec.outcome(
                    OutcomeContext(
                        session=s,
                        lab=lab,
                        result=result,
                        events=await repo.list_events(s, tenant, run_id, limit=100_000),
                        repo_root=self.settings.repo_root,
                        previous_state=took_over[-1].from_state if took_over else None,
                    )
                )
                await repo.transition_lab(
                    s,
                    tenant,
                    lab,
                    decided.target,
                    actor=f"agent:{spec.name}",
                    reason=decided.reason,
                    run_id=run_id,
                    error=decided.error,
                )
                return
            ok = result is not None and result.status is RunStatus.COMPLETED
            target = spec.success_state if ok else spec.failure_for(lab)
            if target is not None:
                outcome = result.status.value if result else status.value
                await repo.transition_lab(
                    s,
                    tenant,
                    lab,
                    target,
                    actor=f"agent:{spec.name}",
                    reason=f"{spec.name} run {outcome}",
                    run_id=run_id,
                    error=(result.error if result else error),
                )

    def _event_sink(self, tenant: str) -> Callable[[AgentEvent], Awaitable[None]]:
        db_sink = repo.DbEventSink(self.sessionmaker, tenant)

        async def sink(event: AgentEvent) -> None:
            try:
                await db_sink(event)  # durable first, so SSE replay never misses a live event
            finally:
                try:
                    await self.broker.publish(event)
                except Exception:  # noqa: BLE001 - live fan-out is best effort; the DB has it
                    log.exception("broker publish failed for run %s", event.run_id)

        return sink

    # ------------------------------------------------------------------ approvals
    def _approver(self, tenant: str) -> Callable[[ApprovalRequest], Awaitable[ApprovalDecision]]:
        async def approver(request: ApprovalRequest) -> ApprovalDecision:
            async with transaction(self.sessionmaker) as s:
                approval = await repo.create_approval(s, tenant, request)
            future: asyncio.Future[ApprovalDecision] = asyncio.get_running_loop().create_future()
            self._pending[approval.id] = future
            try:
                return await asyncio.wait_for(asyncio.shield(future), self.settings.approval_timeout_seconds)
            except asyncio.TimeoutError:
                expired = await self._expire(tenant, approval.id)
                if not expired and future.done():  # a human decided at the last moment
                    return future.result()
                return ApprovalDecision(approved=False, by="system", comment="approval timed out")
            except asyncio.CancelledError:
                # run cancelled while waiting: don't leave a PENDING approval a human could still click
                await asyncio.shield(self._expire(tenant, approval.id))
                raise
            finally:
                self._pending.pop(approval.id, None)

        return approver

    async def _expire(self, tenant: str, approval_id: uuid.UUID) -> bool:
        async with transaction(self.sessionmaker) as s:
            return await repo.expire_approval(s, tenant, approval_id)

    async def decide(
        self, principal: Principal, approval_id: uuid.UUID, *, approved: bool, comment: str | None = None
    ) -> Any:
        """Record the decision (DB is the source of truth), then wake the waiting
        agent — here if this worker owns the run, else via the control channel."""
        async with transaction(self.sessionmaker) as s:
            approval = await repo.decide_approval(
                s, principal.tenant, approval_id, approved=approved, by=principal.actor, comment=comment
            )
        decision = ApprovalDecision(approved=approved, by=principal.actor, comment=comment)
        if not self._resolve(approval_id, decision):
            await self.broker.publish_control(
                {"type": "approval", "approval_id": str(approval_id), "decision": decision.model_dump()}
            )
        return approval

    def _resolve(self, approval_id: uuid.UUID, decision: ApprovalDecision) -> bool:
        future = self._pending.get(approval_id)
        if future is None:
            return False
        if not future.done():
            future.set_result(decision)
        return True

    async def _on_control(self, message: dict[str, Any]) -> None:
        """Control messages from other workers (or loopback). Only the owner acts."""
        kind = message.get("type")
        if kind == "approval":
            self._resolve(uuid.UUID(message["approval_id"]), ApprovalDecision(**message["decision"]))
        elif kind == "cancel":
            task = self._tasks.get(uuid.UUID(message["run_id"]))
            if task is not None:
                task.cancel()

    # ------------------------------------------------------------------ control
    def is_active(self, run_id: uuid.UUID) -> bool:
        """True if THIS worker is executing the run (use the DB status for cluster-wide state)."""
        return run_id in self._tasks

    async def cancel(self, run_id: uuid.UUID, *, tenant: str, timeout: float = 10.0) -> bool:
        """Cancel a run wherever it executes. False if it isn't active anywhere."""
        task = self._tasks.get(run_id)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return True
        async with self.sessionmaker() as s:
            if (await repo.get_run(s, tenant, run_id)).status.is_terminal:
                return False
        await self.broker.publish_control({"type": "cancel", "run_id": str(run_id)})
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:  # wait for the owner to record the cancellation
            async with self.sessionmaker() as s:
                if (await repo.get_run(s, tenant, run_id)).status.is_terminal:
                    return True
            await asyncio.sleep(0.1)
        return True

    async def wait(self, run_id: uuid.UUID) -> None:
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    # ------------------------------------------------------------------ liveness
    def _rollback_map(self) -> dict[LabState, Any]:
        """running_state → failure state (or a function of the lab) for orphan recovery."""
        return {
            s.running_state: s.failure_state
            for s in self.registry.values()
            if s.running_state is not None and s.failure_state is not None
        }

    async def recover_orphans(self, *, grace: bool = False) -> dict[str, int]:
        """Fail runs whose worker is gone. Single-process broker: every active run
        is an orphan at startup. Redis broker: only runs of workers without a live
        heartbeat (``grace`` skips runs younger than the grace period)."""
        alive = await self.broker.alive_workers()
        alive_set = None if alive is None else {*alive, self.worker_id}
        started_before = utcnow() - timedelta(seconds=self.settings.orphan_grace_seconds) if grace else None
        async with transaction(self.sessionmaker) as s:
            counts = await repo.recover_orphans(
                s, self._rollback_map(), alive_workers=alive_set, started_before=started_before
            )
        if any(counts.values()):
            log.warning("recovered orphaned agent runs: %s", counts)
        return counts

    async def start_background(self) -> None:
        """Control channel + (when clustered) heartbeat and periodic orphan sweep."""
        await self.broker.start(self._on_control)
        interval = self.settings.worker_heartbeat_seconds
        await self.broker.heartbeat(self.worker_id, ttl=interval * 3)

        async def loop() -> None:
            while True:
                await asyncio.sleep(interval)
                try:
                    await self.broker.heartbeat(self.worker_id, ttl=interval * 3)
                    if await self.broker.alive_workers() is not None:
                        await self.recover_orphans(grace=True)
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001 - keep beating through transient errors
                    log.exception("heartbeat/orphan sweep failed")

        self._background = asyncio.create_task(loop(), name="pf-heartbeat")

    async def shutdown(self) -> None:
        if self._background is not None:
            self._background.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._background
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            await self.broker.forget_worker(self.worker_id)
