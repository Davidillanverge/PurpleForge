"""GitHub Copilot-subscription brain: the official ``copilot`` CLI headless with your
GitHub Copilot seat, no LLM API key. Same shape as the Claude brain (see
``api.cli_brain``): the CLI only reaches the per-run agent-tools MCP server.

    copilot -p <agent .md + task> --output-format json --stream off
            --additional-mcp-config @<pf> --disable-builtin-mcps --no-custom-instructions
            --no-ask-user --allow-tool pf
            --deny-tool shell --deny-tool write --deny-tool read --deny-tool url --deny-tool memory
            --usage-output-file <file> [--model <m>]

Isolation uses Copilot's own permission rules: in prompt mode anything not allowed is
denied, and deny rules win over every allow — so its shell, file reads/writes, web and
memory are off and only the ``pf`` MCP server's tools run. Copilot CLI has no
system-prompt flag, so the agent's .md travels at the top of the prompt.

Auth: the host's `copilot login`, or COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN
(``PF_COPILOT_GITHUB_TOKEN``). A Copilot seat belongs to one person — and an
Enterprise seat to your employer's agreement: check its policy allows this use.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from agents.events import EventType
from api.cli_brain import MCP_SERVER_NAME, CliBrain, Emit, StreamState, single_user_reason
from api.settings import AppSettings

BRAIN = "copilot-subscription"
PROVIDER_LABEL = "github copilot (subscription)"
#: Copilot CLI permission kinds that would let the model act outside our MCP tools
DENIED_KINDS = ("shell", "write", "read", "url", "memory")
#: Token variables Copilot CLI reads, in its precedence order (scrubbed, then re-added on purpose)
TOKEN_VARS = ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")


def availability(settings: AppSettings) -> str | None:
    return CopilotSubscriptionBrain.availability(settings)


def _text_of(content: Any) -> str:
    """content may be a string, a list of strings/{text} blocks, or {text}."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return str(content.get("text") or "")
    if isinstance(content, list):
        return "".join(_text_of(c) for c in content)
    return ""


def _sum_tokens(node: Any) -> tuple[int, int]:
    """Total input/output tokens anywhere under a usage-file metrics tree."""
    tin = tout = 0
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (int, float)) and k in ("inputTokens", "cacheReadTokens", "cacheWriteTokens"):
                tin += int(v)
            elif isinstance(v, (int, float)) and k == "outputTokens":
                tout += int(v)
            else:
                i, o = _sum_tokens(v)
                tin, tout = tin + i, tout + o
    elif isinstance(node, list):
        for v in node:
            i, o = _sum_tokens(v)
            tin, tout = tin + i, tout + o
    return tin, tout


class CopilotSubscriptionBrain(CliBrain):
    name = BRAIN
    label = "GitHub Copilot (tu suscripción)"
    provider_label = PROVIDER_LABEL

    @classmethod
    def availability(cls, settings: AppSettings) -> str | None:
        if shutil.which(settings.copilot_bin) is None:
            return f"`{settings.copilot_bin}` (GitHub Copilot CLI) is not installed or not on PATH"
        return single_user_reason(settings, "GitHub Copilot")

    def wall_seconds(self) -> float | None:
        return self.settings.copilot_wall_seconds

    def auth_env(self) -> dict[str, str]:
        token = self.settings.copilot_github_token
        if token is not None:
            return {"COPILOT_GITHUB_TOKEN": token.get_secret_value()}
        # scrub_env drops *TOKEN* vars; hand the CLI its own login token back if the host set one
        return {k: os.environ[k] for k in TOKEN_VARS if os.environ.get(k)}

    def mcp_config(self, command: str, args: list[str], env: dict[str, str]) -> dict[str, Any]:
        # explicit env: don't rely on the CLI forwarding its environment to MCP children
        # (PATH/HOME so forge can still find terraform/docker/az for the deploy tools)
        child_env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG") if os.environ.get(k)} | env
        return {
            "mcpServers": {
                MCP_SERVER_NAME: {"type": "local", "command": command, "args": args, "env": child_env, "tools": ["*"]}
            }
        }

    def argv(self, *, task: str, system_prompt: str, mcp_config_path: Path, workdir: Path) -> list[str]:
        prompt = f"{system_prompt}\n\n## Your task\n\n{task}"
        denies = [arg for kind in DENIED_KINDS for arg in ("--deny-tool", kind)]
        return [
            self.settings.copilot_bin,
            "-p",
            prompt,
            "--output-format",
            "json",
            "--stream",
            "off",
            "--additional-mcp-config",
            f"@{mcp_config_path}",
            "--disable-builtin-mcps",
            "--no-custom-instructions",
            "--no-ask-user",
            "--allow-tool",
            MCP_SERVER_NAME,
            *denies,
            "--disallow-temp-dir",
            "--usage-output-file",
            str(workdir / "usage.json"),
            *(["--model", self.settings.copilot_model] if self.settings.copilot_model else []),
        ]

    def handle(self, msg: dict[str, Any], state: StreamState) -> list[Emit]:
        kind = str(msg.get("type") or "")
        raw = msg.get("data")
        data: dict[str, Any] = raw if isinstance(raw, dict) else {}
        if kind == "assistant.message":
            text = _text_of(data.get("content"))
            calls = [{"name": r.get("name"), "arguments": r.get("arguments")} for r in data.get("toolRequests") or []]
            if text:
                state.final = text  # the last assistant text is the run's answer
            if not (text or calls):
                return []
            return [
                Emit(
                    EventType.ASSISTANT_MESSAGE,
                    {
                        "content": text,
                        "tool_calls": calls,
                        "stop_reason": "tool_use" if calls else "end_turn",
                        "usage": {"input_tokens": 0, "output_tokens": int(data.get("outputTokens") or 0)},
                        "provider": self.provider_label,
                        "model": state.model,
                        "budget": state.budget(),
                    },
                )
            ]
        if kind == "assistant.usage":
            state.model = data.get("model") or state.model
            key = str(data.get("apiCallId") or f"call-{len(state.tokens)}")
            tin = sum(int(data.get(k) or 0) for k in ("inputTokens", "cacheReadTokens", "cacheWriteTokens"))
            state.tokens[key] = (tin, int(data.get("outputTokens") or 0))
            return []
        if kind == "assistant.turn_end":
            state.turns += 1
            return []
        if kind == "session.error":
            state.error = f"{data.get('errorType', 'error')}: {data.get('message', '')}".strip()
            return []
        if kind == "result":
            code = msg.get("exitCode")
            raw_usage = msg.get("usage")
            usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
            if "premiumRequests" in usage:
                state.extra["premium_requests"] = usage["premiumRequests"]
            if code == 0 and not state.error:
                state.completed = True
            elif not state.error:
                state.error = f"copilot exited {code}"
        return []

    def after_exit(self, state: StreamState, workdir: Path) -> None:
        """Usage file: authoritative token totals (and AI credits) when the stream had none."""
        try:
            usage = json.loads((workdir / "usage.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not state.tokens:
            tin, tout = _sum_tokens(usage.get("modelMetrics") or {})
            if tin or tout:
                state.tokens["usage-file"] = (tin, tout)
        if not state.model:
            metrics = usage.get("modelMetrics") or {}
            if isinstance(metrics, dict) and metrics:
                state.model = next(iter(metrics))
        for src, dst in (("totalPremiumRequestCost", "premium_requests"), ("totalNanoAiu", "nano_ai_units")):
            if usage.get(src) is not None:
                state.extra[dst] = usage[src]
