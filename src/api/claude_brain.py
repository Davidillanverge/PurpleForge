"""Claude-subscription brain: the official ``claude`` CLI headless with your Claude
Pro/Max login, no API key (as PentestGPT does). See ``api.cli_brain`` for what every
subscription brain shares (per-run agent-tools MCP server, lanes, gate, outcomes).

    claude -p <task> --output-format stream-json --verbose --system-prompt <agent .md>
           --tools "" --mcp-config <pf> --strict-mcp-config --allowedTools mcp__pf
           --permission-mode dontAsk --no-session-persistence --setting-sources ""

``ANTHROPIC_API_KEY`` never reaches the CLI, and a run is aborted if Claude reports
API-key auth anyway — no silent API billing. Terms: Anthropic allows your own
subscription in the unmodified Claude Code binary for ordinary individual use and
forbids routing other users' requests through it.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any

from agents.events import EventType
from api.cli_brain import MCP_SERVER_NAME, CliBrain, Emit, StreamState, single_user_reason
from api.settings import AppSettings

BRAIN = "claude-subscription"
PROVIDER_LABEL = "claude (subscription)"


def availability(settings: AppSettings) -> str | None:
    return ClaudeSubscriptionBrain.availability(settings)


def _usage_of(u: dict[str, Any]) -> tuple[int, int]:
    """Input counts every token the model read (fresh + cache writes + cache reads)."""
    tin = int(u.get("input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0)
    tin += int(u.get("cache_read_input_tokens") or 0)
    return tin, int(u.get("output_tokens") or 0)


class ClaudeSubscriptionBrain(CliBrain):
    name = BRAIN
    label = "Claude (tu suscripción)"
    provider_label = PROVIDER_LABEL

    @classmethod
    def availability(cls, settings: AppSettings) -> str | None:
        if shutil.which(settings.claude_bin) is None:
            return f"`{settings.claude_bin}` (Claude Code CLI) is not installed or not on PATH"
        return single_user_reason(settings, "Claude")

    def wall_seconds(self) -> float | None:
        return self.settings.claude_wall_seconds

    def auth_env(self) -> dict[str, str]:
        token = self.settings.claude_oauth_token  # `claude setup-token` (headless hosts); else the host login
        return {"CLAUDE_CODE_OAUTH_TOKEN": token.get_secret_value()} if token is not None else {}

    def mcp_config(self, command: str, args: list[str], env: dict[str, str]) -> dict[str, Any]:
        # the CLI's env (incl. these vars) is inherited by its MCP children
        return {"mcpServers": {MCP_SERVER_NAME: {"command": command, "args": args}}}

    def argv(self, *, task: str, system_prompt: str, mcp_config_path: Path, workdir: Path) -> list[str]:
        return [
            self.settings.claude_bin,
            "-p",
            task,
            "--output-format",
            "stream-json",
            "--verbose",
            "--system-prompt",
            system_prompt,
            "--tools",
            "",  # none of Claude Code's own tools
            "--mcp-config",
            str(mcp_config_path),
            "--strict-mcp-config",
            "--allowedTools",
            f"mcp__{MCP_SERVER_NAME}",
            "--permission-mode",
            "dontAsk",
            "--no-session-persistence",
            "--setting-sources",
            "",
            *(["--model", self.settings.claude_model] if self.settings.claude_model else []),
        ]

    def handle(self, msg: dict[str, Any], state: StreamState) -> list[Emit]:
        kind = msg.get("type")
        if kind == "system" and msg.get("subtype") == "init":
            state.model = msg.get("model") or state.model
            if msg.get("apiKeySource") not in (None, "none"):
                raise RuntimeError("claude is using an API key, not the subscription — refusing to bill it")
            return []
        if kind == "assistant":
            m = msg.get("message") or {}
            mid = str(m.get("id") or uuid.uuid4())
            if mid not in state.tokens:
                state.turns += 1
            state.tokens[mid] = _usage_of(m.get("usage") or {})
            blocks = m.get("content") or []
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            calls = [
                {"name": str(b.get("name", "")).removeprefix(f"mcp__{MCP_SERVER_NAME}__"), "arguments": b.get("input")}
                for b in blocks
                if b.get("type") == "tool_use"
            ]
            if not (text or calls):
                return []
            tin, tout = state.tokens[mid]
            return [
                Emit(
                    EventType.ASSISTANT_MESSAGE,
                    {
                        "content": text,
                        "tool_calls": calls,
                        "stop_reason": "tool_use" if calls else "end_turn",
                        "usage": {"input_tokens": tin, "output_tokens": tout},
                        "provider": self.provider_label,
                        "model": state.model,
                        "budget": state.budget(),
                    },
                )
            ]
        if kind == "result":
            state.final = str(msg.get("result") or "")
            if msg.get("is_error") or msg.get("subtype") != "success":
                state.error = state.final or str(msg.get("subtype"))
            else:
                state.completed = True
        return []
