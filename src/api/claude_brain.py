"""Claude-subscription brain: drive the official ``claude`` CLI headless (as PentestGPT
does) instead of calling an LLM API — your Claude Pro/Max login, no API key.

Per run it launches::

    claude -p <task> --output-format stream-json --verbose
           --system-prompt <runtime preamble + .claude/agents/<agent>.md>
           --tools ""                      # none of Claude Code's own tools (no Bash/Edit/Read…)
           --mcp-config <pf agent-tools server for THIS run> --strict-mcp-config
           --allowedTools mcp__pf --permission-mode dontAsk --no-session-persistence

so Claude reaches ONLY this agent's tools, through ``mcp_server.agent_tools``, which
runs them via the engine's own ``_execute`` (same lanes, same human approval gate,
same events). The lab state is still decided by ``core.outcomes`` from what forge
did. ``ANTHROPIC_API_KEY`` is stripped from the child env so it always uses the
subscription (an API key would silently switch it to API billing).

Terms: Anthropic allows signing in to the unmodified Claude Code binary with your
own subscription for ordinary individual use, and forbids routing other users'
requests through subscription credentials. So this brain refuses to run on an
install configured for more than one user.
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
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.definitions import AgentDefinition, build_system_prompt
from agents.engine import AgentResult, RunStatus
from agents.events import EventType
from agents.tools import forge_pythonpath, scrub_env, truncate
from agents.toolsets import build_toolset
from api.settings import AppSettings
from db.recorder import Recorder
from llm.provider import Usage

BRAIN = "claude-subscription"
PROVIDER_LABEL = "claude (subscription)"
SRC_DIR = Path(__file__).resolve().parents[1]


def availability(settings: AppSettings) -> str | None:
    """Why this brain can't be used on this install, or None if it can."""
    if shutil.which(settings.claude_bin) is None:
        return f"`{settings.claude_bin}` (Claude Code CLI) is not installed or not on PATH"
    users = set(settings.api_tokens.values())
    if not settings.auth_disabled and len(users) > 1:
        return (
            "a Claude subscription is for ordinary individual use: this install has several users "
            f"({', '.join(sorted(users))}). Use an API provider for shared installs."
        )
    return None


def _usage_of(u: dict[str, Any]) -> tuple[int, int]:
    """Input counts every token the model read (fresh + cache writes + cache reads)."""
    tin = int(u.get("input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0)
    tin += int(u.get("cache_read_input_tokens") or 0)
    return tin, int(u.get("output_tokens") or 0)


class ClaudeSubscriptionBrain:
    def __init__(self, settings: AppSettings, sessionmaker: async_sessionmaker[AsyncSession], tenant: str) -> None:
        self.settings = settings
        self.sessionmaker = sessionmaker
        self.tenant = tenant

    def _db_url(self) -> str:
        bind = self.sessionmaker.kw["bind"]
        return str(bind.url.render_as_string(hide_password=False))

    def _env(self, *, cloud: bool) -> dict[str, str]:
        env = scrub_env(os.environ, allow_cloud=cloud)  # also drops ANTHROPIC_* → subscription, never API billing
        for noise in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"):
            env.pop(noise, None)
        token = self.settings.claude_oauth_token
        if token is not None:  # long-lived `claude setup-token` token (headless servers / Docker)
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token.get_secret_value()
        # what the agent-tools MCP server (a child of claude) needs to reach the same DB/repo
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(SRC_DIR), forge_pythonpath(env)) if p)
        env["PF_DATABASE_URL"] = self._db_url()
        env["PF_REPO_ROOT"] = str(self.settings.repo_root)
        env["PF_APPROVAL_TIMEOUT_SECONDS"] = str(self.settings.approval_timeout_seconds)
        return env

    def system_prompt(self, definition: AgentDefinition, tool_names: list[str]) -> str:
        prompt = build_system_prompt(definition, tool_names, self.settings.repo_root)
        return (
            "You run headless under the PurpleForge agent service, driven by the Claude Code CLI. Your tools "
            "are exposed as `mcp__pf__<name>` (e.g. `mcp__pf__forge`, `mcp__pf__read_file`) and are the ONLY "
            "tools you have. Infra-touching calls wait for a human approval in the dashboard; a denial comes back "
            "as a tool error — don't retry it.\n\n" + prompt
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
        wall_seconds: float | None = None,
    ) -> AgentResult:
        rec = Recorder(self.sessionmaker, self.tenant, run_id, definition.name)
        tools = build_toolset(agent_key, self.settings.repo_root, lab_name=lab_name, spec_path=spec_path)
        tool_names = [t.name for t in tools]
        cloud = agent_key.startswith("deploy-operator")
        mcp_config = {
            "mcpServers": {
                "pf": {
                    "command": sys.executable,
                    "args": [
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
                    ],
                }
            }
        }
        cfg_dir = Path(tempfile.mkdtemp(prefix="pf-claude-"))
        cfg = cfg_dir / "mcp.json"
        cfg.write_text(json.dumps(mcp_config), encoding="utf-8")
        os.chmod(cfg, 0o600)
        argv = [
            self.settings.claude_bin,
            "-p",
            task,
            "--output-format",
            "stream-json",
            "--verbose",
            "--system-prompt",
            self.system_prompt(definition, tool_names),
            "--tools",
            "",
            "--mcp-config",
            str(cfg),
            "--strict-mcp-config",
            "--allowedTools",
            "mcp__pf",
            "--permission-mode",
            "dontAsk",
            "--no-session-persistence",
            "--setting-sources",
            "",
            *(["--model", self.settings.claude_model] if self.settings.claude_model else []),
        ]
        await rec.emit(
            EventType.RUN_STARTED,
            task=task,
            model=self.settings.claude_model or "subscription default",
            provider=PROVIDER_LABEL,
            tools=sorted(tool_names),
            brain=BRAIN,
            limits={"max_wall_seconds": wall_seconds},
        )
        seen_messages: dict[str, tuple[int, int]] = {}
        turns, final, error, model = 0, "", None, self.settings.claude_model
        status = RunStatus.FAILED
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(self.settings.repo_root),
            env=self._env(cloud=cloud),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            limit=16 * 1024 * 1024,
        )

        def totals() -> Usage:
            return Usage(
                input_tokens=sum(i for i, _ in seen_messages.values()),
                output_tokens=sum(o for _, o in seen_messages.values()),
            )

        async def consume() -> None:
            nonlocal turns, final, error, model, status
            assert proc.stdout is not None
            async for raw in proc.stdout:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                kind = msg.get("type")
                if kind == "system" and msg.get("subtype") == "init":
                    model = msg.get("model") or model
                    if msg.get("apiKeySource") not in (None, "none"):
                        raise RuntimeError("claude is using an API key, not the subscription — refusing to bill it")
                elif kind == "assistant":
                    m = msg.get("message") or {}
                    mid = str(m.get("id") or uuid.uuid4())
                    new_turn = mid not in seen_messages
                    seen_messages[mid] = _usage_of(m.get("usage") or {})
                    if new_turn:
                        turns += 1
                    blocks = m.get("content") or []
                    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
                    calls = [
                        {"name": str(b.get("name", "")).removeprefix("mcp__pf__"), "arguments": b.get("input")}
                        for b in blocks
                        if b.get("type") == "tool_use"
                    ]
                    if text or calls:
                        u = totals()
                        tin, tout = seen_messages[mid]
                        await rec.emit(
                            EventType.ASSISTANT_MESSAGE,
                            content=text,
                            tool_calls=calls,
                            stop_reason="tool_use" if calls else "end_turn",
                            usage={"input_tokens": tin, "output_tokens": tout},
                            provider=PROVIDER_LABEL,
                            model=model,
                            budget={"turns": turns, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens},
                        )
                elif kind == "result":
                    final = str(msg.get("result") or "")
                    if msg.get("is_error") or msg.get("subtype") != "success":
                        error = final or str(msg.get("subtype"))
                    else:
                        status = RunStatus.COMPLETED

        stderr_tail = ""
        try:
            await asyncio.wait_for(consume(), timeout=wall_seconds)
            await proc.wait()
            assert proc.stderr is not None
            stderr_tail = (await proc.stderr.read()).decode("utf-8", "replace")[-2000:]
            if proc.returncode not in (0, None) and status is RunStatus.COMPLETED:
                status, error = RunStatus.FAILED, f"claude exited {proc.returncode}"
            if status is not RunStatus.COMPLETED and not error:
                error = f"claude exited {proc.returncode}: {truncate(stderr_tail, 800) or 'no result'}"
        except asyncio.TimeoutError:
            self._kill(proc)
            status, error = RunStatus.BUDGET_EXCEEDED, f"wall-clock limit reached ({wall_seconds:.0f}s)"
        except asyncio.CancelledError:
            self._kill(proc)
            u = totals()
            with contextlib.suppress(Exception):
                await asyncio.shield(
                    rec.emit(
                        EventType.RUN_CANCELLED,
                        budget={"turns": turns, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens},
                    )
                )
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed run
            self._kill(proc)
            status, error = RunStatus.FAILED, f"{type(exc).__name__}: {exc}"
        finally:
            shutil.rmtree(cfg_dir, ignore_errors=True)

        u = totals()
        budget = {"turns": turns, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens}
        if status is RunStatus.COMPLETED:
            await rec.emit(EventType.RUN_COMPLETED, output=final, budget=budget)
        elif status is RunStatus.BUDGET_EXCEEDED:
            await rec.emit(EventType.BUDGET_EXCEEDED, reason=error, budget=budget)
        else:
            await rec.emit(EventType.RUN_FAILED, error=error, budget=budget)
        return AgentResult(
            run_id=run_id, agent=definition.name, status=status, output=final, error=error, turns=turns, usage=u
        )

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)  # claude AND its MCP child (same session)
