"""No-AI lab operations the API runs itself: validate, deploy, stop, start, teardown.

Each one is a single deterministic ``forge`` subcommand (the generated deploy.sh /
stop.sh / start.sh / teardown.sh behind it), started by a human click in the UI or
a call to the API. No LLM is involved, so the human click IS the approval: it is
recorded as an ``approval_resolved`` event (by the clicking user) so the run's audit trail and the shared outcome functions
(``core.outcomes``) work exactly as for agent and MCP runs.

Runs are recorded in the same tables as agent runs (``source="forge"``), so the
dashboard, run console (live output streamed as ``tool_output`` events) and the lab
timeline show them unchanged. The lab moves to the action's running state while it
runs — nothing else may start on the lab meanwhile — and its next state comes from
what forge actually did (exit code), never from a claim.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import signal
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.events import EventType
from api import integrations
from api.auth import Principal
from api.forge_ops import resolve_spec
from core.outcomes import (
    EventLike,
    Outcome,
    deploy_outcome,
    start_outcome,
    stop_outcome,
    teardown_outcome,
    validate_outcome,
)
from core.security import forge_pythonpath, scrub_env, truncate
from db import repository as repo
from db.crypto import SecretCipher
from db.models import AgentRun
from db.recorder import Recorder
from db.session import transaction
from db.states import LabState

log = logging.getLogger(__name__)

SOURCE = "forge"
PROVIDER_LABEL = "forge (sin IA)"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
#: deploy.sh can take well over an hour on a big lab (Windows promotions, CIS roles)
DEFAULT_TIMEOUT = 4 * 3600.0


class ForgeActionError(RuntimeError):
    """The action can't start (unknown action, wrong lab state, missing spec/scripts). Maps to 409/422."""


@dataclass(frozen=True)
class ForgeAction:
    name: str
    label: str
    #: lab states it may start from
    allowed_states: frozenset[LabState]
    #: lab state while it runs (serialises it against agents and other forge runs)
    running_state: LabState
    #: where an orphaned run (API restarted mid-run) leaves the lab
    orphan_state: LabState
    #: the forge calls, in order; the run stops at the first one that fails
    commands: Callable[[str], list[tuple[str, list[str]]]]
    #: (events, state before the run, generated/<lab>/, run start as epoch seconds) → next lab state
    outcome: Callable[[Sequence[EventLike], LabState | None, Path, float], Outcome]
    #: touches live infrastructure: record the human click as the approval
    infra: bool = True
    #: generated scripts the action needs (generated/<lab>/...)
    needs: tuple[str, ...] = ()
    timeout: float = DEFAULT_TIMEOUT


A = LabState
ACTIONS: dict[str, ForgeAction] = {
    a.name: a
    for a in (
        ForgeAction(
            name="validate",
            label="validar",
            allowed_states=frozenset({A.DEPLOYED, A.VALIDATED}),
            running_state=A.VALIDATING,
            orphan_state=A.DEPLOYED,
            commands=lambda spec: [("validate", [spec, "--run"])],
            outcome=lambda ev, _prev, lab_dir, since: validate_outcome(ev, lab_dir, since),
            infra=False,  # read-only probes over the WireGuard tunnel (isolated lab)
            needs=("lab-manifest.json",),
            timeout=3600.0,
        ),
        ForgeAction(
            name="deploy",
            label="desplegar",
            allowed_states=frozenset({A.APPROVED}),
            running_state=A.DEPLOYING,
            orphan_state=A.FAILED,  # infra state unknown → treat as possibly billable
            # fresh artifacts first (no infra exists yet in APPROVED), then deploy.sh behind the guardrail
            commands=lambda spec: [("generate", [spec]), ("deploy", [spec])],
            outcome=lambda ev, _prev, _dir, _since: deploy_outcome(ev),
        ),
        ForgeAction(
            name="stop",
            label="parar",
            allowed_states=frozenset({A.DEPLOYED, A.VALIDATED}),
            running_state=A.STOPPING,
            orphan_state=A.DEPLOYED,
            commands=lambda spec: [("stop", [spec])],
            outcome=lambda ev, _prev, _dir, _since: stop_outcome(ev),
            needs=("stop.sh",),
            timeout=3600.0,
        ),
        ForgeAction(
            name="start",
            label="encender",
            allowed_states=frozenset({A.STOPPED}),
            running_state=A.STARTING,
            orphan_state=A.STOPPED,
            commands=lambda spec: [("start", [spec])],
            outcome=lambda ev, _prev, _dir, _since: start_outcome(ev),
            needs=("start.sh",),
            timeout=3600.0,
        ),
        ForgeAction(
            name="teardown",
            label="destruir",
            allowed_states=frozenset({A.DEPLOYED, A.VALIDATED, A.STOPPED, A.FAILED}),
            running_state=A.DESTROYING,
            orphan_state=A.FAILED,
            # --force: teardown.sh's type-the-name prompt needs a TTY; the UI asks for the name instead
            commands=lambda spec: [("teardown", [spec, "--force"])],
            outcome=lambda ev, prev, _dir, _since: teardown_outcome(ev, prev),
        ),
    )
}
del A

#: running_state → where an orphaned forge run leaves the lab
ORPHAN_ROLLBACK: dict[LabState, LabState] = {a.running_state: a.orphan_state for a in ACTIONS.values()}


def available_actions(state: LabState) -> list[ForgeAction]:
    return [a for a in ACTIONS.values() if state in a.allowed_states]


def _clean(text: str) -> str:
    return _ANSI.sub("", text).replace("\r", "")


class ForgeJobs:
    """Starts and tracks the no-AI forge runs of this API process."""

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        repo_root: Path,
        *,
        worker_id: str | None = None,
        flush_seconds: float = 2.0,
        python: str = sys.executable,
        cipher: SecretCipher | None = None,
    ) -> None:
        self.sessionmaker = sessionmaker
        #: decrypts the tenant's UI-configured integrations (api.integrations) for the deploy env
        self.cipher = cipher
        self.repo_root = repo_root
        self.worker_id = worker_id
        self.flush_seconds = flush_seconds
        self.python = python
        self._tasks: dict[uuid.UUID, asyncio.Task[Outcome]] = {}

    # ------------------------------------------------------------------ start
    async def start(self, principal: Principal, lab_id: uuid.UUID, action_name: str) -> AgentRun:
        action = ACTIONS.get(action_name)
        if action is None:
            raise ForgeActionError(f"unknown action {action_name!r} (one of: {', '.join(ACTIONS)})")
        async with transaction(self.sessionmaker) as s:
            lab = await repo.get_lab(s, principal.tenant, lab_id, for_update=True)
            if lab.state not in action.allowed_states:
                allowed = ", ".join(sorted(x.value for x in action.allowed_states))
                raise ForgeActionError(f"can't {action.label} a lab that is {lab.state.value} (needs: {allowed})")
            if not lab.spec_path:
                raise ForgeActionError("lab has no spec_path")
            resolve_spec(self.repo_root, lab.spec_path, lab.name)  # SpecError → 422
            lab_dir = self.repo_root / "generated" / lab.name
            missing = [n for n in action.needs if not (lab_dir / n).is_file()]
            if missing:
                raise ForgeActionError(f"generated/{lab.name}/ lacks {', '.join(missing)} — generate the lab first")
            previous = lab.state
            spec_path = lab.spec_path
            run = await repo.create_run(
                s,
                principal.tenant,
                agent=f"forge-{action.name}",
                task=f"forge {action.name} {spec_path} (sin IA, lanzado desde la UI)",
                lab_id=lab.id,
                created_by=principal.actor,
                worker_id=self.worker_id,
                source=SOURCE,
            )
            await repo.transition_lab(
                s,
                principal.tenant,
                lab,
                action.running_state,
                actor=principal.actor,
                reason=f"forge {action.name} (no AI) started by {principal.actor}",
                run_id=run.id,
            )
        rec = Recorder(self.sessionmaker, principal.tenant, run.id, run.agent)
        await rec.emit(
            EventType.RUN_STARTED,
            task=run.task,
            model=None,
            provider=PROVIDER_LABEL,
            tools=["forge"],
            source=SOURCE,
            limits={},
        )
        task = asyncio.create_task(
            self._execute(principal, rec, lab.id, action, spec_path, previous, lab_dir), name=f"pf-forge-{run.id}"
        )
        run_id: uuid.UUID = run.id
        self._tasks[run_id] = task

        def _forget(_task: asyncio.Task[Outcome]) -> None:
            self._tasks.pop(run_id, None)

        task.add_done_callback(_forget)
        return run

    def is_active(self, run_id: uuid.UUID) -> bool:
        return run_id in self._tasks

    async def wait(self, run_id: uuid.UUID) -> None:
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)

    # ------------------------------------------------------------------ execution
    async def _execute(
        self,
        principal: Principal,
        rec: Recorder,
        lab_id: uuid.UUID,
        action: ForgeAction,
        spec_path: str,
        previous: LabState,
        lab_dir: Path,
    ) -> Outcome:
        error: str | None = None
        since = time.time()
        try:
            # UI-configured integrations (AWS/Azure/Proxmox/Elastic/MDE/Caldera...) over .env
            overlay = await integrations.load_tenant_env(self.sessionmaker, principal.tenant, self.cipher)
            for sub, args in action.commands(spec_path):
                call_id = f"forge-{uuid.uuid4().hex[:12]}"
                arguments = {"subcommand": sub, "args": args}
                await rec.emit(EventType.TOOL_CALL, id=call_id, name="forge", arguments=arguments)
                if action.infra and sub != "generate":
                    # the human's confirmed click is the approval: record it (same shape as the
                    # gate's decision, so core.outcomes sees an approved, infra-touching call)
                    await rec.emit(
                        EventType.APPROVAL_RESOLVED,
                        id=call_id,
                        approved=True,
                        by=principal.actor,
                        comment="lanzado desde la UI sin IA (el clic confirmado es la aprobación)",
                    )
                code = await self._run_forge(rec, call_id, sub, args, timeout=action.timeout, overlay=overlay)
                if code != 0:
                    error = f"forge {sub} exited {code}"
                    break
            outcome = action.outcome(await rec.events(), previous, lab_dir, since)
        except asyncio.CancelledError:
            # API shutting down: the process group was killed; the next start's orphan recovery decides the lab
            raise
        except Exception as exc:  # noqa: BLE001 - never leave the lab stuck in its running state
            log.exception("forge %s run %s crashed", action.name, rec.run_id)
            error = f"{type(exc).__name__}: {exc}"
            outcome = action.outcome(await rec.events(), previous, lab_dir, since)
            if outcome.error is None:
                outcome = Outcome(outcome.target, outcome.reason, error=error)
        return await self._finish(principal, rec, lab_id, action, outcome, error)

    async def _run_forge(
        self,
        rec: Recorder,
        call_id: str,
        sub: str,
        args: list[str],
        *,
        timeout: float,
        overlay: Mapping[str, str | None] | None = None,
    ) -> int | None:
        # deploy-time creds: this IS the deploy path (UI integrations win over .env)
        env = integrations.apply(scrub_env(os.environ, allow_cloud=True), overlay or {})
        env["PYTHONPATH"] = forge_pythonpath(env)
        env["PYTHONUNBUFFERED"] = "1"
        loop = asyncio.get_running_loop()
        started = loop.time()
        proc = await asyncio.create_subprocess_exec(
            self.python,
            "-m",
            "forge",
            sub,
            *args,
            cwd=str(self.repo_root),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        assert proc.stdout is not None
        full: list[str] = []
        pending: list[str] = []
        last_flush = loop.time()

        async def flush() -> None:
            nonlocal last_flush
            if pending:
                chunk = "".join(pending)
                pending.clear()
                await rec.emit(EventType.TOOL_OUTPUT, id=call_id, name="forge", content=chunk)
            last_flush = loop.time()

        timed_out = False
        try:
            deadline = started + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=min(remaining, self.flush_seconds))
                except asyncio.TimeoutError:
                    await flush()
                    continue
                if not line:
                    break
                text = _clean(line.decode("utf-8", errors="replace"))
                full.append(text)
                pending.append(text)
                if loop.time() - last_flush >= self.flush_seconds or len(pending) >= 200:
                    await flush()
            if timed_out:
                self._kill(proc)
            code = await proc.wait()
        except asyncio.CancelledError:
            self._kill(proc)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=10)
            raise
        await flush()
        output = "".join(full)
        content = (
            f"timed out after {timeout:.0f}s (process killed)\n" if timed_out else f"exit code: {code}\n"
        ) + truncate(output, 4_000)
        exit_code = None if timed_out else code
        await rec.emit(
            EventType.TOOL_RESULT,
            id=call_id,
            name="forge",
            is_error=exit_code != 0,
            content=content,
            data={"exit_code": exit_code, **({"timed_out": True} if timed_out else {})},
            duration_ms=int((loop.time() - started) * 1000),
        )
        return exit_code

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)

    async def _finish(
        self,
        principal: Principal,
        rec: Recorder,
        lab_id: uuid.UUID,
        action: ForgeAction,
        outcome: Outcome,
        error: str | None,
    ) -> Outcome:
        async with transaction(self.sessionmaker) as s:
            lab = await repo.get_lab(s, principal.tenant, lab_id, for_update=True)
            if lab.state is action.running_state:  # don't clobber a state someone else set meanwhile
                await repo.transition_lab(
                    s,
                    principal.tenant,
                    lab,
                    outcome.target,
                    actor="system",
                    reason=outcome.reason,
                    run_id=rec.run_id,
                    error=outcome.error,
                )
        # the run failed if forge did; forge succeeding with an unwelcome result (e.g. a
        # validation that couldn't confirm every vuln) is a completed run — the lab state
        # and its last_error carry that result
        failed = error is not None
        await rec.emit(
            EventType.RUN_FAILED if failed else EventType.RUN_COMPLETED,
            output=outcome.reason,
            error=error,
        )
        return outcome

    # ------------------------------------------------------------------ lifecycle
    async def recover_orphans(self, *, alive_workers: Any = None) -> dict[str, int]:
        """Forge runs live in this API process: at startup every active one is dead."""
        async with transaction(self.sessionmaker) as s:
            counts = await repo.recover_orphans(s, ORPHAN_ROLLBACK, alive_workers=alive_workers, source=SOURCE)
        if any(counts.values()):
            log.warning("recovered orphaned forge runs: %s", counts)
        return counts

    async def shutdown(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
