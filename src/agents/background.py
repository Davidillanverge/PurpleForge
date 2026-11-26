"""Long forge operations as detached background jobs, for agent runs.

Why: a ``forge deploy`` takes 20–90 minutes. Run as one blocking tool call it
outlives every external brain's MCP tool timeout (Copilot CLI gave up after ~3
minutes, Claude Code after 30), and when the brain gave up, the deploy — a child
of the brain's MCP server — was killed mid-Ansible, leaving billable, half-built
infrastructure behind.

How: when an agent's ``forge`` call is a long infra operation and this process
knows the service DB (``configure``), the ForgeTool starts it as a *detached* job
(``python -m agents.background``, its own session, survives the brain and its MCP
server) and returns at once with the job id (= the tool call id). The job

- streams forge's live output into the run as ``tool_output`` events (the run
  console shows every deploy.sh / Ansible step as it happens), and
- appends the call's final ``tool_result`` (``data.final``, ``exit_code``) when
  forge exits — the same event shape a blocking call would have produced, so
  ``core.outcomes`` decides the lab state from forge's real exit code.

The agent follows it with ``forge_wait`` (short, bounded waits no client times
out on), and the runner never finalises a run while one of its jobs is still
running (``wait_for_jobs``): the brain giving up can't turn a deploy that is
still running into a FAILED lab, nor kill it.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import contextvars
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from core.schemas import ToolResult
from core.security import truncate

#: forge subcommands that run long enough to need a background job
LONG_SUBCOMMANDS = frozenset({"deploy", "teardown", "destroy", "reset", "stop", "start", "restart", "validate"})
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SRC_DIR = Path(__file__).resolve().parents[1]

#: (run_id, call_id) of the tool call being executed — set by AgentEngine around tool.run
CURRENT_CALL: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar("pf_current_call", default=None)

_db_url: str | None = None


def configure(db_url: str | None) -> None:
    """Enable background jobs in this process (the API, the agent-tools MCP server)."""
    global _db_url
    _db_url = db_url


def db_url() -> str | None:
    return _db_url


def _db_settings(url: str) -> Any:
    from db.settings import DatabaseSettings

    return DatabaseSettings(_env_file=None, database_url=url)  # type: ignore[call-arg]  # pydantic-settings kwarg


def is_long(subcommand: str, args: Sequence[str]) -> bool:
    if subcommand == "validate":
        return "--run" in args  # without --run it only renders the checklist
    return subcommand in LONG_SUBCOMMANDS


def clean(text: str) -> str:
    return _ANSI.sub("", text).replace("\r", "")


# --------------------------------------------------------------------------- spawn (in the tool's process)

_children: list[subprocess.Popen[bytes]] = []  # keep a reference so they're reaped, never waited on


def spawn(
    *,
    run_id: str,
    call_id: str,
    command: list[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> int:
    """Start the detached job; returns its pid. Raises if no DB is configured."""
    url = _db_url
    if not url:
        raise RuntimeError("background jobs are not configured in this process")
    child_env = dict(env)
    child_env["PYTHONPATH"] = os.pathsep.join(p for p in (str(SRC_DIR), child_env.get("PYTHONPATH", "")) if p)
    child_env["PYTHONUNBUFFERED"] = "1"
    child_env["PF_BG_DATABASE_URL"] = url  # not on argv: may carry a DB password
    argv = [
        sys.executable,
        "-m",
        "agents.background",
        "--run-id",
        run_id,
        "--call-id",
        call_id,
        "--cwd",
        str(cwd),
        "--timeout",
        str(int(timeout)),
        "--",
        *command,
    ]
    log_dir = cwd / "generated" / ".jobs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / f"{call_id}.stderr.log", "ab") as err:
        proc = subprocess.Popen(
            argv,
            cwd=os.getcwd(),  # a relative sqlite URL resolves exactly as it does here
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=err,
            start_new_session=True,  # survives the brain, its MCP server and their signals
        )
    _children.append(proc)
    _children[:] = [p for p in _children if p.poll() is None]
    return proc.pid


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # a zombie child of ours is dead for our purposes
    with contextlib.suppress(Exception):
        for p in _children:
            if p.pid == pid and p.poll() is not None:
                return False
    return True


# --------------------------------------------------------------------------- job state (from the run's events)


class JobState(BaseModel):
    job: str
    subcommand: str | None = None
    pid: int | None = None
    started: bool = False
    finished: bool = False
    exit_code: int | None = None
    final_content: str = ""
    output_tail: str = ""


def jobs_of(events: Sequence[Any]) -> dict[str, JobState]:
    """Background jobs of a run, rebuilt from its events (works from any process)."""
    jobs: dict[str, JobState] = {}
    calls = {str(e.data.get("id")): e.data for e in events if e.type == "tool_call"}
    tails: dict[str, list[str]] = {}
    for e in events:
        d = e.data or {}
        jid = str(d.get("id"))
        if e.type == "tool_result" and (d.get("data") or {}).get("background"):
            st = jobs.setdefault(jid, JobState(job=jid))
            data = d.get("data") or {}
            st.subcommand = ((calls.get(jid) or {}).get("arguments") or {}).get("subcommand")
            if data.get("final"):
                st.finished, st.exit_code, st.final_content = True, data.get("exit_code"), d.get("content", "")
            else:
                st.started, st.pid = True, data.get("pid")
        elif e.type == "tool_output":
            tails.setdefault(jid, []).append(d.get("content", ""))
    for jid, st in jobs.items():
        st.output_tail = "".join(tails.get(jid, []))[-3000:]
    return jobs


async def wait_for_jobs(sessionmaker: Any, tenant: str, run_id: Any, *, poll: float = 5.0) -> None:
    """Block until every background job of the run has finished (or its process is gone)."""
    from db import repository as repo

    while True:
        async with sessionmaker() as s:
            events = await repo.list_events(s, tenant, run_id, limit=100_000)
        pending = [j for j in jobs_of(events).values() if j.started and not j.finished and pid_alive(j.pid)]
        if not pending:
            return
        await asyncio.sleep(poll)


def kill_jobs(events: Sequence[Any]) -> None:
    """Cancel: stop this run's still-running jobs (each job records its own final result)."""
    for job in jobs_of(events).values():
        if job.started and not job.finished and job.pid:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(job.pid, signal.SIGTERM)


# --------------------------------------------------------------------------- forge_wait tool


class ForgeWaitInput(BaseModel):
    job: str = Field(description="The job id a background `forge` call returned (its tool call id).")
    wait_seconds: int = Field(default=120, ge=5, le=3600, description="How long to wait for it to finish.")


def make_forge_wait_tool(*, max_wait: int = 600) -> Any:
    """``forge_wait``: a bounded wait for a background forge job of THIS run. A regular
    ``agents.tools.Tool``, built here so the import stays one-way (agents.tools → this)."""
    from agents.tools import Tool

    class _ForgeWait(Tool):
        name = "forge_wait"
        description = (
            "Wait for a background `forge` job (deploy/teardown/validate/stop/start...) started by an earlier "
            "`forge` call of this run, and get its live output. Returns when the job finishes or after "
            "`wait_seconds`; while it is still running, call it again. The job keeps running on its own — "
            "never start the same forge command twice."
        )
        Input = ForgeWaitInput

        def __init__(self) -> None:
            self.max_wait = max_wait
            self._sessionmaker: Any = None

        def _sm(self) -> Any:
            if self._sessionmaker is None:
                from db.session import create_engine, create_sessionmaker

                url = _db_url
                if not url:
                    raise RuntimeError("background jobs are not configured in this process")
                self._sessionmaker = create_sessionmaker(create_engine(settings=_db_settings(url)))
            return self._sessionmaker

        async def run(self, args: BaseModel) -> ToolResult:
            assert isinstance(args, ForgeWaitInput)
            current = CURRENT_CALL.get()
            if current is None:
                return ToolResult(content="forge_wait only works inside an agent run", is_error=True)
            run_id = current[0]
            from db import repository as repo

            sm = self._sm()
            async with sm() as s:
                run = await repo.get_run_any_tenant(s, run_id)
                tenant = run.tenant_id
            deadline = time.monotonic() + min(args.wait_seconds, self.max_wait)
            started = time.monotonic()
            while True:
                async with sm() as s:
                    events = await repo.list_events(s, tenant, run_id, limit=100_000)
                job = jobs_of(events).get(args.job)
                if job is None or not (job.started or job.finished):
                    return ToolResult(content=f"no background job {args.job!r} in this run", is_error=True)
                if job.finished:
                    return ToolResult(
                        content=f"job {args.job} (forge {job.subcommand}) finished.\n{job.final_content}",
                        is_error=job.exit_code != 0,
                        data={"job": args.job, "finished": True, "exit_code": job.exit_code},
                    )
                if not pid_alive(job.pid):
                    return ToolResult(
                        content=f"job {args.job} died without reporting a result. Last output:\n{job.output_tail}",
                        is_error=True,
                        data={"job": args.job, "finished": True, "exit_code": None},
                    )
                if time.monotonic() >= deadline:
                    lines = clean(job.output_tail).splitlines()[-40:]
                    return ToolResult(
                        content=(
                            f"job {args.job} (forge {job.subcommand}) is still running "
                            f"(waited {int(time.monotonic() - started)}s). Call forge_wait again. "
                            "Last output:\n" + "\n".join(lines)
                        ),
                        data={"job": args.job, "finished": False},
                    )
                await asyncio.sleep(2.0)

    return _ForgeWait()


# --------------------------------------------------------------------------- the detached job itself


async def _job(run_id: str, call_id: str, cwd: Path, timeout: float, command: list[str]) -> int:
    from agents.events import EventType
    from db import repository as repo
    from db.recorder import Recorder
    from db.session import create_engine, create_sessionmaker

    engine = create_engine(settings=_db_settings(os.environ["PF_BG_DATABASE_URL"]))
    sm = create_sessionmaker(engine)
    async with sm() as s:
        run = await repo.get_run_any_tenant(s, run_id)
        rec = Recorder(sm, run.tenant_id, run.id, run.agent)
    loop = asyncio.get_running_loop()
    started = loop.time()
    env = {k: v for k, v in os.environ.items() if k != "PF_BG_DATABASE_URL"}
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
    full: list[str] = []
    pending: list[str] = []
    last = loop.time()
    note = ""

    async def flush() -> None:
        nonlocal last
        if pending:
            chunk = "".join(pending)
            pending.clear()
            with contextlib.suppress(Exception):  # a DB hiccup must not kill the deploy
                await rec.emit(EventType.TOOL_OUTPUT, id=call_id, name="forge", content=chunk)
        last = loop.time()

    reader = asyncio.ensure_future(proc.stdout.readline())
    stopper = asyncio.ensure_future(stop.wait())
    try:
        while True:
            remaining = started + timeout - loop.time()
            if remaining <= 0:
                note = f"timed out after {timeout:.0f}s (process killed)"
                break
            done, _ = await asyncio.wait({reader, stopper}, timeout=min(2.0, remaining))
            if stopper in done:
                note = "stopped (job cancelled)"
                break
            if reader in done:
                line = reader.result()
                if not line:
                    break
                text = clean(line.decode("utf-8", errors="replace"))
                full.append(text)
                pending.append(text)
                reader = asyncio.ensure_future(proc.stdout.readline())
            if loop.time() - last >= 2.0 or len(pending) >= 200:
                await flush()
        if note:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        code = await proc.wait()
    finally:
        reader.cancel()
        stopper.cancel()
        await flush()
    exit_code = None if note else code
    content = (f"{note}\n" if note else f"exit code: {code}\n") + truncate("".join(full), 4_000)
    await rec.emit(
        EventType.TOOL_RESULT,
        id=call_id,
        name="forge",
        is_error=exit_code != 0,
        content=content,
        data={"exit_code": exit_code, "background": True, "final": True},
        duration_ms=int((loop.time() - started) * 1000),
    )
    await engine.dispose()
    return 0 if exit_code == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agents.background")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--call-id", required=True)
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout", type=float, default=4 * 3600)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command after --")
    uuid.UUID(args.run_id)
    return asyncio.run(_job(args.run_id, args.call_id, Path(args.cwd), args.timeout, command))


if __name__ == "__main__":
    sys.exit(main())
