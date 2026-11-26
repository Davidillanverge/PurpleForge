"""Google Gemini provider over the native REST API (``models/{model}:generateContent``).

Notes on the wire format:
- tools are declared with ``parametersJsonSchema`` (full JSON Schema, so the
  pydantic-generated schemas go through untouched);
- a function call comes back with an ``id`` and, on thinking models, a
  ``thoughtSignature`` that MUST be echoed back with that call in the next turn
  (kept in ``ToolCall.signature``);
- all tool results answering one model turn go in ONE following user content.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx

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

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-flash-latest"

_REFUSALS = {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"}


def to_gemini_contents(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role is Role.USER:
            out.append({"role": "user", "parts": [{"text": msg.content}]})
        elif msg.role is Role.ASSISTANT:
            parts: list[dict[str, Any]] = []
            if msg.content:
                parts.append({"text": msg.content})
            for c in msg.tool_calls:
                part: dict[str, Any] = {"functionCall": {"name": c.name, "args": c.arguments, "id": c.id}}
                if c.signature:
                    part["thoughtSignature"] = c.signature
                parts.append(part)
            if parts:
                out.append({"role": "model", "parts": parts})
        elif msg.role is Role.TOOL:
            response = {"error": msg.content} if msg.is_error else {"result": msg.content}
            part = {"functionResponse": {"name": msg.name or "", "id": msg.tool_call_id, "response": response}}
            prev = out[-1] if out else None
            if prev and prev["role"] == "user" and all("functionResponse" in p for p in prev["parts"]):
                prev["parts"].append(part)
            else:
                out.append({"role": "user", "parts": [part]})
    return out


def to_gemini_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "functionDeclarations": [
                {"name": t.name, "description": t.description, "parametersJsonSchema": t.input_schema} for t in tools
            ]
        }
    ]


def _error_detail(resp: httpx.Response) -> str:
    try:
        err = resp.json().get("error", {})
        return f"{err.get('status', '')}: {err.get('message', '')}".strip(": ")[:500]
    except ValueError:
        return resp.text[:500]


def _retry_delay(resp: httpx.Response) -> float | None:
    """Gemini puts the wait in error.details[RetryInfo].retryDelay ("34s")."""
    try:
        for detail in resp.json().get("error", {}).get("details", []) or []:
            if str(detail.get("@type", "")).endswith("google.rpc.RetryInfo"):
                return parse_retry_after(detail.get("retryDelay"))
    except (ValueError, AttributeError):
        pass
    return parse_retry_after(resp.headers.get("retry-after"))


class GeminiProvider:
    def __init__(
        self,
        *,
        api_key: str | None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 600.0,
        client: httpx.AsyncClient | None = None,
        name: str = "gemini",
    ) -> None:
        self.name = name
        self.model = model.removeprefix("models/")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
    ) -> LLMResponse:
        if not self._api_key:
            raise ProviderConfigError("no Gemini API key configured", provider=self.name)
        gen: dict[str, Any] = {"maxOutputTokens": max_tokens}
        if temperature is not None:
            gen["temperature"] = temperature
        payload: dict[str, Any] = {"contents": to_gemini_contents(messages), "generationConfig": gen}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}
        if tools:
            payload["tools"] = to_gemini_tools(tools)

        url = f"{self._base_url}/models/{self.model}:generateContent"
        try:
            # key in a header, never in the URL (URLs end up in logs)
            resp = await self._client.post(url, json=payload, headers={"x-goog-api-key": self._api_key})
        except httpx.TransportError as exc:
            raise TransientProviderError(f"{type(exc).__name__}: {exc}", provider=self.name) from exc
        if resp.status_code >= 400:
            raise self._status_error(resp)
        try:
            data = resp.json()
        except ValueError as exc:
            raise TransientProviderError(f"non-JSON response: {resp.text[:200]}", provider=self.name) from exc
        return self._parse(data)

    def _parse(self, data: dict[str, Any]) -> LLMResponse:
        meta = data.get("usageMetadata") or {}
        usage = Usage(
            input_tokens=int(meta.get("promptTokenCount") or 0),
            # thinking tokens are billed as output
            output_tokens=int(meta.get("candidatesTokenCount") or 0) + int(meta.get("thoughtsTokenCount") or 0),
        )
        model = data.get("modelVersion") or self.model
        candidates = data.get("candidates") or []
        if not candidates:
            block = (data.get("promptFeedback") or {}).get("blockReason")
            if block:
                return LLMResponse(
                    content=f"[blocked: {block}]",
                    stop_reason=StopReason.REFUSAL,
                    usage=usage,
                    model=model,
                    provider=self.name,
                )
            raise TransientProviderError("empty response (no candidates)", provider=self.name)

        cand = candidates[0]
        finish = cand.get("finishReason") or "STOP"
        if finish == "MALFORMED_FUNCTION_CALL":
            # the model botched the call syntax; a retry (or the next provider) usually fixes it
            raise TransientProviderError("model produced a malformed function call", provider=self.name)

        texts: list[str] = []
        calls: list[ToolCall] = []
        for part in (cand.get("content") or {}).get("parts") or []:
            if part.get("thought"):
                continue  # thought summaries are not part of the answer
            if "functionCall" in part:
                fc = part["functionCall"]
                calls.append(
                    ToolCall(
                        id=fc.get("id") or f"gemini-{uuid.uuid4().hex[:12]}",
                        name=fc.get("name", ""),
                        arguments=dict(fc.get("args") or {}),
                        signature=part.get("thoughtSignature"),
                    )
                )
            elif "text" in part:
                texts.append(part["text"])

        if calls:
            stop = StopReason.TOOL_USE
        elif finish == "MAX_TOKENS":
            stop = StopReason.MAX_TOKENS
        elif finish in _REFUSALS:
            stop = StopReason.REFUSAL
        elif finish == "STOP":
            stop = StopReason.END_TURN
        else:
            stop = StopReason.OTHER
        return LLMResponse(
            content="".join(texts), tool_calls=calls, stop_reason=stop, usage=usage, model=model, provider=self.name
        )

    def _status_error(self, resp: httpx.Response) -> ProviderError:
        code = resp.status_code
        msg = f"HTTP {code}: {_error_detail(resp)}"
        if code in (408, 429) or code >= 500:
            return TransientProviderError(msg, provider=self.name, status_code=code, retry_after=_retry_delay(resp))
        if code in (401, 403, 404):  # bad/expired key, API not enabled, unknown model
            return ProviderConfigError(msg, provider=self.name, status_code=code)
        if code == 400 and ("API_KEY" in msg or "API key" in msg):
            return ProviderConfigError(msg, provider=self.name, status_code=code)
        return InvalidRequestError(msg, provider=self.name, status_code=code)

    async def aclose(self) -> None:
        await self._client.aclose()
