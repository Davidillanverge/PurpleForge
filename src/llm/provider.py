"""Provider-neutral LLM contract.

Everything above this layer (agent engine, API, DB) speaks only these types;
each concrete provider translates them to/from its wire format. The shapes are
pydantic models so they serialize straight into AgentEvent rows and SSE frames.

Conversation model (mirrors the common denominator of Anthropic and Ollama):

- ``system`` prompt is passed separately to ``complete()``, never as a Message.
- An assistant turn may carry ``tool_calls``.
- Each tool result is its own ``Role.TOOL`` message, linked by ``tool_call_id``
  (and ``name``, which Ollama needs because its tool calls have no ids).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class Role(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    #: Opaque provider round-trip data (Gemini's thoughtSignature): must be sent back
    #: unchanged with this call in the next turn. Other providers ignore it.
    signature: str | None = None


class Message(BaseModel):
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    # Role.TOOL only: which call this answers, the tool's name, and whether the
    # tool failed (Anthropic surfaces it to the model as is_error).
    tool_call_id: str | None = None
    name: str | None = None
    is_error: bool = False

    @classmethod
    def user(cls, content: str) -> Message:
        return cls(role=Role.USER, content=content)

    @classmethod
    def assistant(cls, content: str = "", tool_calls: list[ToolCall] | None = None) -> Message:
        return cls(role=Role.ASSISTANT, content=content, tool_calls=tool_calls or [])

    @classmethod
    def tool_result(cls, call: ToolCall, content: str, *, is_error: bool = False) -> Message:
        return cls(role=Role.TOOL, content=content, tool_call_id=call.id, name=call.name, is_error=is_error)


class ToolSpec(BaseModel):
    """A tool the model may call. ``input_schema`` is a JSON Schema object."""

    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class StopReason(str, Enum):
    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"
    OTHER = "other"


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class LLMResponse(BaseModel):
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    stop_reason: StopReason = StopReason.END_TURN
    usage: Usage = Field(default_factory=Usage)
    model: str = ""
    provider: str = ""

    def to_message(self) -> Message:
        """The assistant turn to append to the conversation."""
        return Message.assistant(self.content, self.tool_calls)


# --------------------------------------------------------------------------- errors
#
# The pool's failover policy is driven entirely by the error class, so every
# provider MUST map its native exceptions onto exactly one of these.


class ProviderError(Exception):
    """Base for all provider failures."""

    #: worth retrying the SAME provider after a backoff
    retryable: bool = False
    #: worth trying the NEXT provider in the pool
    failover: bool = True

    def __init__(self, message: str, *, provider: str = "", status_code: int | None = None) -> None:
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code

    def __str__(self) -> str:
        prefix = f"[{self.provider}] " if self.provider else ""
        return f"{prefix}{super().__str__()}"


class TransientProviderError(ProviderError):
    """Timeouts, connection errors, 429, 5xx, overloaded: retry, then fail over."""

    retryable = True


class ProviderConfigError(ProviderError):
    """Bad/missing credentials, unknown model, permission denied: this provider
    can't serve us at all — skip to the next one without retrying."""


class InvalidRequestError(ProviderError):
    """The request itself is malformed (bad schema, bad message order). Another
    provider won't fix our bug, so the pool raises it immediately."""

    failover = False


class AllProvidersFailed(ProviderError):
    """Raised by LLMPool when every provider failed. ``errors`` keeps each cause."""

    failover = False

    def __init__(self, errors: list[ProviderError]) -> None:
        detail = "; ".join(str(e) for e in errors) or "no providers configured"
        super().__init__(f"all LLM providers failed: {detail}", provider="pool")
        self.errors = errors


# --------------------------------------------------------------------------- protocol


@runtime_checkable
class LLMProvider(Protocol):
    """What the agent engine needs from a model backend (LLMPool implements it too)."""

    name: str

    @property
    def model(self) -> str: ...  # read-only: a plain attribute or a property both satisfy it

    async def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
    ) -> LLMResponse: ...

    async def aclose(self) -> None: ...
