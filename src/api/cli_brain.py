"""Shared machinery for "subscription brains": an official agentic CLI (Claude Code,
GitHub Copilot CLI) runs headless as the agent's brain, logged in with YOUR
subscription — no LLM API key.

What every CLI brain shares, by construction:
- tools: the CLI gets none of its own (shell/files/web are disabled or denied);
  it only reaches the per-run ``mcp_server.agent_tools`` server, i.e. the same
  toolset, lanes, spec lock and human approval gate as the API engine;
- events: CLI output → console events via the shared Recorder (the MCP side
  records tool calls into the same run);
- outcomes: the lab state still comes from ``core.outcomes`` (forge exit codes);
- terms: subscriptions are personal → refused on installs with several users.
Subclasses only say how to launch the CLI and how to read its stream.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.definitions import AgentDefinition, build_system_prompt
from agents.engine import AgentResult, RunStatus
from agents.events import EventType
from agents.tools import forge_pythonpath, scrub_env, truncate
from agents.toolsets import build_toolset
from api import integrations
from api.settings import AppSettings
from db.crypto import SecretCipher
from db.recorder import Recorder
from llm.provider import Usage

SRC_DIR = Path(__file__).resolve().parents[1]
MCP_SERVER_NAME = "pf"


def single_user_reason(settings: AppSettings, product: str) -> str | None:
    users = set(settings.api_tokens.values())
    if not settings.auth_disabled and len(users) > 1:
        return (
            f"a {product} subscription is for one person's use: this install has several users "
            f"({', '.join(sorted(users))}). Use an API provider for shared installs."
        )
    return None


@dataclass
class StreamState:
    """What a brain learns from the CLI stream while it runs."""

    model: str | None = None
    turns: int = 0
    tokens: dict[str, tuple[int, int]] = field(default_factory=dict)  # key (message/call id) → (in, out)
    final: str = ""
    error: str | None = None
    completed: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def usage(self) -> Usage:
        return Usage(
            input_tokens=sum(i for i, _ in self.tokens.values()),
            output_tokens=sum(o for _, o in self.tokens.values()),
        )

    def budget(self) -> dict[str, int]:
        u = self.usage()
        return {"turns": self.turns, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens}


@dataclass
class Emit:
    """An event a brain wants recorded for a stream line."""

    type: EventType
    data: dict[str, Any]


class CliBrain(ABC):
    #: registry/UI identity
    name: str = ""
    label: str = ""
    provider_label: str = ""

    def __init__(
        self,
        settings: AppSettings,
        sessionmaker: async_sessionmaker[AsyncSession],
        tenant: str,
        *,
        cipher: SecretCipher | None = None,
    ) -> None:
        self.settings = settings
        self.sessionmaker = sessionmaker
        self.tenant = tenant
        self.cipher = cipher

    # ------------------------------------------------------------------ to implement
    @classmethod
    @abstractmethod
    def availability(cls, settings: AppSettings) -> str | None:
        """Why this brain can't run on this install, or None."""

    @abstractmethod
    def mcp_config(self, command: str, args: list[str], env: dict[str, str]) -> dict[str, Any]:
        """The CLI's own MCP config format for the per-run agent-tools server."""

    @abstractmethod
    def argv(self, *, task: str, system_prompt: str, mcp_config_path: Path, workdir: Path) -> list[str]: ...

    @abstractmethod
    def auth_env(self) -> dict[str, str]:
        """Credentials the CLI needs (its own token vars), added after scrubbing."""

    @abstractmethod
    def handle(self, msg: dict[str, Any], state: StreamState) -> list[Emit]:
        """Fold one stream line into the state; return events to record."""

    def after_exit(self, state: StreamState, workdir: Path) -> None:  # noqa: B027 - optional hook
        """Read anything the CLI wrote on exit (e.g. a usage file)."""

    def wall_seconds(self) -> float | None:
        return None

    # ------------------------------------------------------------------ shared
    def _db_url(self) -> str:
        return str(self.sessionmaker.kw["bind"].url.render_as_string(hide_password=False))

    def _service_env(self) -> dict[str, str]:
        """What the agent-tools MCP server (the CLI's child) needs to reach the same DB/repo."""
        return {
            "PYTHONPATH": os.pathsep.join(p for p in (str(SRC_DIR), forge_pythonpath(os.environ)) if p),
            "PF_DATABASE_URL": self._db_url(),
            "PF_REPO_ROOT": str(self.settings.repo_root),
            "PF_APPROVAL_TIMEOUT_SECONDS": str(self.settings.approval_timeout_seconds),
        }

    def _cli_env(self, *, cloud: bool, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        env = scrub_env(os.environ, allow_cloud=cloud)  # no LLM API keys, no stray tokens
        for noise in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"):
            env.pop(noise, None)
        env.update(self.auth_env())
        env.update(self._service_env())
        env.update(extra or {})
        return env

    def system_prompt(self, definition: AgentDefinition, tool_names: list[str]) -> str:
        prompt = build_system_prompt(definition, tool_names, self.settings.repo_root)
        return (
            f"You run headless under the PurpleForge agent service. Your ONLY tools are the `{MCP_SERVER_NAME}` "
            "MCP server's (" + ", ".join(f"`{t}`" for t in sorted(tool_names)) + "); you have no shell, file or "
            "web tools of your own. Infra-touching calls wait for a human approval in the dashboard; a denial "
            "comes back as a tool error — don't retry it.\n\n" + prompt
        )

    async def run(
        self,
        *,
        run_id: str,
        agent_key: str,
        definition: AgentDefinition,
        task: str,
        lab_name: str | None,
        spec_path: str | None,
    ) -> AgentResult:
        rec = Recorder(self.sessionmaker, self.tenant, run_id, definition.name)
        tools = build_toolset(agent_key, self.settings.repo_root, lab_name=lab_name, spec_path=spec_path)
        tool_names = [t.name for t in tools]
        cloud = agent_key.startswith("deploy-operator")
        server_args = [
            "-m",
            "mcp_server.agent_tools",
            "--run-id",
            run_id,
            "--toolset",
            agent_key,
            "--tenant",
            self.tenant,
            *(["--lab", lab_name] if lab_name else []),
            *(["--spec", spec_path] if spec_path else []),
        ]
        workdir = Path(tempfile.mkdtemp(prefix=f"pf-{self.name}-"))
        cfg = workdir / "mcp.json"
        deploy_extra: dict[str, str] = {}
        if cloud:
            # the deploy tools run in the MCP child: hand it the tenant's UI-configured integrations.
            # Copilot gets them via mcp.json (0600, private temp dir removed after the run); Claude's
            # MCP children inherit the CLI env (the CLI itself has no shell/file tools).
            overlay = await integrations.load_tenant_env(self.sessionmaker, self.tenant, self.cipher)
            deploy_extra[integrations.OVERLAY_ENV] = json.dumps(overlay)
        service_env = self._service_env() | deploy_extra
        cfg.write_text(json.dumps(self.mcp_config(sys.executable, server_args, service_env)), "utf-8")
        os.chmod(cfg, 0o600)
        state = StreamState()
        wall = self.wall_seconds()
        await rec.emit(
            EventType.RUN_STARTED,
            task=task,
            model=None,
            provider=self.provider_label,
            tools=sorted(tool_names),
            brain=self.name,
            limits={"max_wall_seconds": wall},
        )
        proc = await asyncio.create_subprocess_exec(
            *self.argv(
                task=task,
                system_prompt=self.system_prompt(definition, tool_names),
                mcp_config_path=cfg,
                workdir=workdir,
            ),
            cwd=str(self.settings.repo_root),
            env=self._cli_env(cloud=cloud, extra=deploy_extra),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            limit=16 * 1024 * 1024,
        )

        async def consume() -> None:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue
                for ev in self.handle(msg, state):
                    await rec.emit(ev.type, **ev.data)

        status = RunStatus.FAILED
        try:
            await asyncio.wait_for(consume(), timeout=wall)
            await proc.wait()
            assert proc.stderr is not None
            stderr = (await proc.stderr.read()).decode("utf-8", "replace")
            self.after_exit(state, workdir)
            if state.completed and proc.returncode == 0 and not state.error:
                status = RunStatus.COMPLETED
            else:
                state.error = state.error or (
                    f"{self.name} exited {proc.returncode}: {truncate(stderr.strip(), 800) or 'no result'}"
                )
        except asyncio.TimeoutError:
            self._kill(proc)
            status, state.error = RunStatus.BUDGET_EXCEEDED, f"wall-clock limit reached ({wall:.0f}s)"
        except asyncio.CancelledError:
            self._kill(proc)
            with contextlib.suppress(Exception):
                await asyncio.shield(rec.emit(EventType.RUN_CANCELLED, budget=state.budget()))
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed run (e.g. API-key auth refused)
            self._kill(proc)
            status, state.error = RunStatus.FAILED, f"{type(exc).__name__}: {exc}"
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        if status is RunStatus.COMPLETED:
            await rec.emit(EventType.RUN_COMPLETED, output=state.final, budget=state.budget(), **state.extra)
        elif status is RunStatus.BUDGET_EXCEEDED:
            await rec.emit(EventType.BUDGET_EXCEEDED, reason=state.error, budget=state.budget())
        else:
            await rec.emit(EventType.RUN_FAILED, error=state.error, budget=state.budget())
        return AgentResult(
            run_id=run_id,
            agent=definition.name,
            status=status,
            output=state.final,
            error=None if status is RunStatus.COMPLETED else state.error,
            turns=state.turns,
            usage=state.usage(),
        )

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)  # the CLI AND its MCP child (same session)
