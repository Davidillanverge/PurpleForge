"""Ollama provider (local dev at zero cost) over its native ``/api/chat``."""

from __future__ import annotations

import json
import re
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

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:8b"  # small, local, supports tool calling
#: Ollama's default context window is small and it TRUNCATES silently: an agent
#: conversation (system prompt + tool schemas + tool results) needs far more.
DEFAULT_NUM_CTX = 32_768

_FENCED = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)
_TAGGED = re.compile(r"^<tool_call>\s*(.*?)\s*</tool_call>$", re.S)


def text_tool_calls(content: str, tool_names: set[str]) -> list[dict[str, Any]]:
    """Fallback for local models that write the tool call as JSON *text* (bare, in a
    ```json fence or in <tool_call> tags) instead of a structured call. Strict on
    purpose: the WHOLE message must be the call(s), and every name must be a tool
    we offered — prose that merely contains JSON is never executed."""
    text = content.strip()
    for rx in (_FENCED, _TAGGED):
        m = rx.match(text)
        if m:
            text = m.group(1).strip()
    if not text.startswith(("{", "[")):
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    items = parsed if isinstance(parsed, list) else [parsed]
    calls = []
    for item in items:
        if not isinstance(item, dict) or item.get("name") not in tool_names:
            return []
        args = item.get("arguments", item.get("parameters", {}))
        args = _parse_arguments(args)
        calls.append({"name": item["name"], "arguments": args})
    return calls


def to_ollama_messages(messages: list[Message], system: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for msg in messages:
        if msg.role is Role.USER:
            out.append({"role": "user", "content": msg.content})
        elif msg.role is Role.ASSISTANT:
            entry: dict[str, Any] = {"role": "assistant", "content": msg.content}
            if msg.tool_calls:
                entry["tool_calls"] = [{"function": {"name": c.name, "arguments": c.arguments}} for c in msg.tool_calls]
            out.append(entry)
        elif msg.role is Role.TOOL:
            # Ollama tool calls carry no id; results are matched by tool name.
            content = f"ERROR: {msg.content}" if msg.is_error else msg.content
            entry = {"role": "tool", "content": content}
            if msg.name:
                entry["tool_name"] = msg.name
            out.append(entry)
    return out


def to_ollama_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}}
        for t in tools
    ]


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}
        return parsed if isinstance(parsed, dict) else {"_raw": parsed}
    return {}


def _error_detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:500]
    return str(body.get("error", body)) if isinstance(body, dict) else str(body)


class OllamaProvider:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 300.0,
        num_ctx: int = DEFAULT_NUM_CTX,
        client: httpx.AsyncClient | None = None,
        name: str = "ollama",
    ) -> None:
        self.name = name
        self.model = model
        self.num_ctx = num_ctx
        self._client = client or httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
    ) -> LLMResponse:
        options: dict[str, Any] = {"num_predict": max_tokens, "num_ctx": self.num_ctx}
        if temperature is not None:
            options["temperature"] = temperature
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": to_ollama_messages(messages, system),
            "stream": False,
            "options": options,
        }
        if tools:
            payload["tools"] = to_ollama_tools(tools)

        try:
            resp = await self._client.post("/api/chat", json=payload)
        except httpx.TransportError as exc:  # connect/read/timeout
            raise TransientProviderError(f"{type(exc).__name__}: {exc}", provider=self.name) from exc

        if resp.status_code >= 400:
            raise self._status_error(resp)

        try:
            data = resp.json()
        except ValueError as exc:
            raise TransientProviderError(f"non-JSON response: {resp.text[:200]}", provider=self.name) from exc

        msg = data.get("message") or {}
        raw_calls = [
            {
                "name": (tc.get("function") or {}).get("name", ""),
                "arguments": (tc.get("function") or {}).get("arguments"),
            }
            for tc in msg.get("tool_calls") or []
        ]
        content = msg.get("content") or ""
        if not raw_calls and tools:
            raw_calls = text_tool_calls(content, {t.name for t in tools})
            if raw_calls:
                content = ""  # the text WAS the call
        calls = [
            ToolCall(
                id=f"ollama-{uuid.uuid4().hex[:12]}",
                name=c["name"],
                arguments=_parse_arguments(c["arguments"]),
            )
            for c in raw_calls
        ]
        if calls:
            stop = StopReason.TOOL_USE
        elif data.get("done_reason") == "length":
            stop = StopReason.MAX_TOKENS
        else:
            stop = StopReason.END_TURN
        return LLMResponse(
            content=content,
            tool_calls=calls,
            stop_reason=stop,
            usage=Usage(
                input_tokens=int(data.get("prompt_eval_count") or 0),
                output_tokens=int(data.get("eval_count") or 0),
            ),
            model=data.get("model") or self.model,
            provider=self.name,
        )

    def _status_error(self, resp: httpx.Response) -> ProviderError:
        code = resp.status_code
        msg = f"HTTP {code}: {_error_detail(resp)}"
        if code in (408, 429) or code >= 500:
            wait = parse_retry_after(resp.headers.get("retry-after"))
            return TransientProviderError(msg, provider=self.name, status_code=code, retry_after=wait)
        if code in (401, 403, 404):  # 404 = model not pulled
            return ProviderConfigError(msg, provider=self.name, status_code=code)
        return InvalidRequestError(msg, provider=self.name, status_code=code)

    async def aclose(self) -> None:
        await self._client.aclose()
