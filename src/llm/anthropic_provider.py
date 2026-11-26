"""Anthropic (Claude) provider over the official async SDK."""

from __future__ import annotations

from typing import Any

import anthropic

from llm.provider import (
    InvalidRequestError,
    LLMResponse,
    Message,
    ProviderConfigError,
    ProviderError,
    Role,
    StopReason,
    ToolCall,
    ToolSpec,
    TransientProviderError,
    Usage,
    parse_retry_after,
)

# The agent .md frontmatter says `model: sonnet`; resolve those short names.
MODEL_ALIASES: dict[str, str] = {
    "opus": "claude-opus-5-5",
    "sonnet": "claude-sonnet-5-5",
    "haiku": "claude-haiku-5-5",
    "fable": "claude-fable-5-2",
}
DEFAULT_MODEL = MODEL_ALIASES["sonnet"]

_STOP_REASONS: dict[str, StopReason] = {
    "end_turn": StopReason.END_TURN,
    "stop_sequence": StopReason.END_TURN,
    "tool_use": StopReason.TOOL_USE,
    "max_tokens": StopReason.MAX_TOKENS,
    "model_context_window_exceeded": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSAL,
}


def resolve_model(model: str) -> str:
    return MODEL_ALIASES.get(model, model)


def to_anthropic_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Translate neutral messages to the Messages API shape.

    All tool results answering one assistant turn must sit in the SAME following
    user message, so consecutive Role.TOOL messages are merged into one.
    """
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role is Role.USER:
            out.append({"role": "user", "content": msg.content})
        elif msg.role is Role.ASSISTANT:
            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            blocks.extend(
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments} for c in msg.tool_calls
            )
            if blocks:  # an empty assistant turn is invalid; dropping it is harmless
                out.append({"role": "assistant", "content": blocks})
        elif msg.role is Role.TOOL:
            if not msg.tool_call_id:
                raise InvalidRequestError("tool result without tool_call_id", provider="anthropic")
            block: dict[str, Any] = {"type": "tool_result", "tool_use_id": msg.tool_call_id, "content": msg.content}
            if msg.is_error:
                block["is_error"] = True
            prev = out[-1] if out else None
            if (
                prev is not None
                and prev["role"] == "user"
                and isinstance(prev["content"], list)
                and all(b.get("type") == "tool_result" for b in prev["content"])
            ):
                prev["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


def to_anthropic_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools]


def map_error(exc: Exception, provider: str = "anthropic") -> ProviderError:
    """Map SDK exceptions onto the pool's failover classes (by status code first,
    so the SDK's many specific 4xx subclasses don't need individual cases)."""
    if isinstance(exc, anthropic.APIConnectionError):  # includes APITimeoutError
        return TransientProviderError(f"connection error: {exc}", provider=provider)
    if isinstance(exc, anthropic.APIStatusError):
        code = exc.status_code
        msg = f"HTTP {code}: {exc.message}"
        if code in (408, 409, 429) or code >= 500:
            wait = parse_retry_after(exc.response.headers.get("retry-after")) if exc.response is not None else None
            return TransientProviderError(msg, provider=provider, status_code=code, retry_after=wait)
        if code in (401, 402, 403, 404):
            return ProviderConfigError(msg, provider=provider, status_code=code)
        return InvalidRequestError(msg, provider=provider, status_code=code)
    if isinstance(exc, anthropic.RetryableError):
        return TransientProviderError(str(exc), provider=provider)
    # e.g. no API key configured at all
    return ProviderConfigError(f"{type(exc).__name__}: {exc}", provider=provider)


class AnthropicProvider:
    """Claude via ``anthropic.AsyncAnthropic``.

    The SDK's own retries are disabled by default (``max_retries=0``): LLMPool
    owns retry/backoff/failover, and retrying in both layers multiplies latency.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 0,
        client: anthropic.AsyncAnthropic | None = None,
        name: str = "anthropic",
    ) -> None:
        self.name = name
        self.model = resolve_model(model)
        self._client = client or anthropic.AsyncAnthropic(
            api_key=api_key, base_url=base_url, timeout=timeout, max_retries=max_retries
        )

    async def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
    ) -> LLMResponse:
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": to_anthropic_messages(messages),
        }
        if system:
            params["system"] = system
        if tools:
            params["tools"] = to_anthropic_tools(tools)
        if temperature is not None:
            params["temperature"] = temperature

        try:
            resp = await self._client.messages.create(**params)
        except anthropic.AnthropicError as exc:
            raise map_error(exc, self.name) from exc
        except TypeError as exc:
            # the SDK raises a bare TypeError when no api_key/auth_token is configured
            if "authentication" in str(exc).lower():
                raise ProviderConfigError(f"no credentials: {exc}", provider=self.name) from exc
            raise

        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                texts.append(block.text)
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=dict(block.input or {})))
            # thinking / server-tool blocks are not part of the neutral contract

        stop = _STOP_REASONS.get(resp.stop_reason or "", StopReason.OTHER)
        if calls and stop is StopReason.END_TURN:
            stop = StopReason.TOOL_USE
        return LLMResponse(
            content="\n".join(texts),
            tool_calls=calls,
            stop_reason=stop,
            usage=Usage(input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens),
            model=resp.model,
            provider=self.name,
        )

    async def aclose(self) -> None:
        await self._client.close()
