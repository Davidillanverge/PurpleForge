"""API configuration (pydantic-settings, ``PF_`` prefix)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from db.base import DEFAULT_TENANT


def _default_repo_root() -> Path:
    from forge.core import REPO_ROOT  # reuse forge's resolution, don't re-derive it

    return Path(REPO_ROOT)


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PF_", env_file=".env", extra="ignore")

    #: Repository the agents operate on (specs/, generated/, catalog/, .claude/agents/).
    repo_root: Path = Field(default_factory=_default_repo_root)
    #: Run `alembic upgrade head` on startup (the container does; tests/dev opt in).
    auto_migrate: bool = False

    # --- auth -----------------------------------------------------------------
    #: Bearer token -> user id, as JSON: PF_API_TOKENS='{"<token>": "alice"}'.
    api_tokens: Annotated[dict[str, str], NoDecode] = Field(default_factory=dict)
    #: Local dev only: every request is user "dev". Never enable on a shared host.
    auth_disabled: bool = False
    default_tenant: str = DEFAULT_TENANT

    # --- agents ---------------------------------------------------------------
    #: A pending tool approval auto-expires (= denied) after this long.
    approval_timeout_seconds: float = 3600.0
    #: Timeout for the deterministic forge steps (compile/guardrail) run by the API.
    forge_timeout_seconds: float = 600.0

    @field_validator("api_tokens", mode="before")
    @classmethod
    def _parse_tokens(cls, value: object) -> object:
        if isinstance(value, str):
            if not value.strip():
                return {}  # empty template value: no tokens (every request → 401)
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError('PF_API_TOKENS must be JSON: {"<long-random-token>": "<user>"}') from exc
        if isinstance(value, dict):
            short = [user for token, user in value.items() if len(str(token)) < 24]
            if short:
                raise ValueError(f"PF_API_TOKENS: tokens must be >= 24 chars (weak token for {short})")
        return value

    # --- SSE ------------------------------------------------------------------
    sse_heartbeat_seconds: float = 15.0

    # --- multi-worker -----------------------------------------------------------
    #: Redis for cross-worker events/approvals/cancels + worker liveness. Unset =
    #: in-memory broker: then run exactly ONE uvicorn worker.
    redis_url: str | None = None
    #: Heartbeat period; a worker is dead after 3 missed beats.
    worker_heartbeat_seconds: float = 10.0
    #: The periodic sweep never fails runs younger than this (heartbeat race guard).
    orphan_grace_seconds: float = 60.0
    #: Startup: wait this long for the database to accept connections.
    db_wait_seconds: float = 60.0

    #: Level for the service's own loggers (uvicorn keeps its own config).
    log_level: str = "INFO"

    # --- agent brain ------------------------------------------------------------
    #: Default brain for runs launched without an explicit choice:
    #: "engine" (AgentEngine + LLM API pool) or "claude-subscription" (headless Claude Code CLI).
    agent_brain: Literal["engine", "claude-subscription"] = "engine"
    claude_bin: str = "claude"
    #: e.g. "sonnet" / "opus" / a full model id; unset = the subscription's default
    claude_model: str | None = None
    #: Long-lived token from `claude setup-token` (headless hosts/Docker). Unset = the host's `claude` login.
    claude_oauth_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("PF_CLAUDE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
    )
    #: Wall-clock cap for one Claude-brain run (the CLI has no turn cap).
    claude_wall_seconds: float = 7200.0
