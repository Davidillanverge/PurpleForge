"""AnthropicProvider against the real SDK with a mocked HTTP transport."""

from __future__ import annotations

import json

import anthropic
import httpx2
import pytest

from llm import (
    InvalidRequestError,
    Message,
    ProviderConfigError,
    StopReason,
    ToolCall,
    ToolSpec,
    TransientProviderError,
)
from llm.anthropic_provider import AnthropicProvider, to_anthropic_messages


def _provider(handler, model: str = "sonnet") -> AnthropicProvider:
    client = anthropic.AsyncAnthropic(
        api_key="test-key",
        max_retries=0,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )
    return AnthropicProvider(model=model, client=client)


def _message(content, stop_reason="end_turn"):
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-5-5",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 11, "output_tokens": 7},
    }


async def test_text_completion_and_request_shape():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx2.Response(200, json=_message([{"type": "text", "text": "hola"}]))

    p = _provider(handler)
    resp = await p.complete([Message.user("hi")], system="you are a validator", max_tokens=100)

    assert resp.content == "hola"
    assert resp.stop_reason is StopReason.END_TURN
    assert resp.usage.input_tokens == 11 and resp.usage.output_tokens == 7
    assert resp.provider == "anthropic"
    body = seen["body"]
    assert body["model"] == "claude-sonnet-5-5"  # alias resolved
    assert body["system"] == "you are a validator"
    assert body["max_tokens"] == 100
    assert "temperature" not in body and "tools" not in body


async def test_tool_use_round_trip():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx2.Response(
            200,
            json=_message(
                [
                    {"type": "text", "text": "checking"},
                    {"type": "tool_use", "id": "toolu_1", "name": "forge", "input": {"args": ["guardrail"]}},
                ],
                stop_reason="tool_use",
            ),
        )

    tool = ToolSpec(name="forge", description="run forge", input_schema={"type": "object"})
    resp = await _provider(handler).complete([Message.user("go")], tools=[tool])

    assert resp.stop_reason is StopReason.TOOL_USE
    assert resp.tool_calls == [ToolCall(id="toolu_1", name="forge", arguments={"args": ["guardrail"]})]
    assert seen["body"]["tools"] == [{"name": "forge", "description": "run forge", "input_schema": {"type": "object"}}]


def test_tool_results_merge_into_one_user_turn():
    a, b = ToolCall(id="t1", name="x"), ToolCall(id="t2", name="y")
    msgs = [
        Message.user("go"),
        Message.assistant("", [a, b]),
        Message.tool_result(a, "ok"),
        Message.tool_result(b, "boom", is_error=True),
        Message.assistant(""),  # empty assistant turn is dropped
    ]
    out = to_anthropic_messages(msgs)
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert out[1]["content"] == [
        {"type": "tool_use", "id": "t1", "name": "x", "input": {}},
        {"type": "tool_use", "id": "t2", "name": "y", "input": {}},
    ]
    assert out[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
        {"type": "tool_result", "tool_use_id": "t2", "content": "boom", "is_error": True},
    ]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (429, TransientProviderError),
        (500, TransientProviderError),
        (529, TransientProviderError),
        (401, ProviderConfigError),
        (404, ProviderConfigError),
        (400, InvalidRequestError),
    ],
)
async def test_http_errors_are_classified(status, expected):
    def handler(request):
        return httpx2.Response(status, json={"type": "error", "error": {"type": "x", "message": "nope"}})

    with pytest.raises(expected) as info:
        await _provider(handler).complete([Message.user("hi")])
    assert info.value.provider == "anthropic"
    assert info.value.status_code == status


async def test_connection_error_is_transient():
    def handler(request):
        raise httpx2.ConnectError("refused", request=request)

    with pytest.raises(TransientProviderError):
        await _provider(handler).complete([Message.user("hi")])


async def test_missing_credentials_is_a_config_error(monkeypatch):
    """Regression: with no key anywhere the SDK raises a bare TypeError at call time."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    client = anthropic.AsyncAnthropic(
        max_retries=0, http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(500)))
    )
    with pytest.raises(ProviderConfigError, match="no credentials"):
        await AnthropicProvider(client=client).complete([Message.user("hi")])
