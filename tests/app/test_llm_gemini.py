"""GeminiProvider against a mocked generateContent endpoint."""

from __future__ import annotations

import json

import httpx
import pytest

from agents.tools import scrub_env
from llm import (
    GeminiProvider,
    InvalidRequestError,
    Message,
    ProviderConfigError,
    StopReason,
    ToolCall,
    ToolSpec,
    TransientProviderError,
)
from llm.settings import LLMSettings, build_pool

KEY = "test-gemini-key"


def _provider(handler, **kw) -> GeminiProvider:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return GeminiProvider(api_key=KEY, model="gemini-flash-latest", client=client, **kw)


def _ok(parts, finish="STOP", usage=None):
    return httpx.Response(
        200,
        json={
            "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}],
            "usageMetadata": usage or {"promptTokenCount": 10, "candidatesTokenCount": 4, "thoughtsTokenCount": 6},
            "modelVersion": "gemini-3.8-flash",
        },
    )


async def test_request_shape_and_text_reply():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        seen["body"] = json.loads(request.content)
        return _ok([{"text": "hola"}])

    tool = ToolSpec(name="read_file", description="read", input_schema={"type": "object", "properties": {}})
    resp = await _provider(handler).complete([Message.user("hi")], system="SYS", tools=[tool], max_tokens=99)

    assert resp.content == "hola" and resp.stop_reason is StopReason.END_TURN
    assert resp.model == "gemini-3.8-flash" and resp.provider == "gemini"
    assert resp.usage.input_tokens == 10 and resp.usage.output_tokens == 10  # thinking tokens count as output
    assert seen["url"].endswith("/models/gemini-flash-latest:generateContent") and KEY not in seen["url"]
    assert seen["key"] == KEY
    body = seen["body"]
    assert body["systemInstruction"] == {"parts": [{"text": "SYS"}]}
    assert body["generationConfig"] == {"maxOutputTokens": 99}
    assert body["tools"][0]["functionDeclarations"][0]["parametersJsonSchema"] == {"type": "object", "properties": {}}


async def test_function_call_and_signature_round_trip():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return _ok(
            [
                {"thought": True, "text": "thinking about it"},
                {
                    "functionCall": {"name": "read_file", "args": {"path": "a.yml"}, "id": "call_1"},
                    "thoughtSignature": "SIG==",
                },
            ]
        )

    resp = await _provider(handler).complete([Message.user("read a.yml")])
    assert resp.stop_reason is StopReason.TOOL_USE and resp.content == ""  # thought summary not leaked as answer
    call = resp.tool_calls[0]
    assert (call.id, call.name, call.arguments, call.signature) == ("call_1", "read_file", {"path": "a.yml"}, "SIG==")

    # next turn: the call goes back WITH its signature, the results are merged into one user content
    other = ToolCall(id="call_2", name="glob", arguments={"pattern": "*"})
    history = [
        Message.user("read a.yml"),
        Message.assistant("", [call, other]),
        Message.tool_result(call, "content of a"),
        Message.tool_result(other, "boom", is_error=True),
    ]
    await _provider(handler).complete(history)
    contents = seen["body"]["contents"]
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[1]["parts"][0] == {
        "functionCall": {"name": "read_file", "args": {"path": "a.yml"}, "id": "call_1"},
        "thoughtSignature": "SIG==",
    }
    assert "thoughtSignature" not in contents[1]["parts"][1]
    assert contents[2]["parts"] == [
        {"functionResponse": {"name": "read_file", "id": "call_1", "response": {"result": "content of a"}}},
        {"functionResponse": {"name": "glob", "id": "call_2", "response": {"error": "boom"}}},
    ]


@pytest.mark.parametrize(
    ("finish", "stop"),
    [("MAX_TOKENS", StopReason.MAX_TOKENS), ("SAFETY", StopReason.REFUSAL), ("OTHER", StopReason.OTHER)],
)
async def test_finish_reasons(finish, stop):
    resp = await _provider(lambda r: _ok([{"text": "x"}], finish=finish)).complete([Message.user("hi")])
    assert resp.stop_reason is stop


async def test_malformed_call_and_empty_are_transient_blocked_prompt_is_refusal():
    with pytest.raises(TransientProviderError, match="malformed"):
        await _provider(lambda r: _ok([], finish="MALFORMED_FUNCTION_CALL")).complete([Message.user("hi")])
    with pytest.raises(TransientProviderError, match="no candidates"):
        await _provider(lambda r: httpx.Response(200, json={"candidates": []})).complete([Message.user("hi")])
    blocked = await _provider(
        lambda r: httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}})
    ).complete([Message.user("hi")])
    assert blocked.stop_reason is StopReason.REFUSAL


@pytest.mark.parametrize(
    ("status", "message", "expected"),
    [
        (429, "RESOURCE_EXHAUSTED", TransientProviderError),
        (503, "UNAVAILABLE", TransientProviderError),
        (403, "PERMISSION_DENIED", ProviderConfigError),
        (404, "model not found", ProviderConfigError),
        (400, "API key not valid. Please pass a valid API key.", ProviderConfigError),
        (400, "Invalid JSON payload", InvalidRequestError),
    ],
)
async def test_http_errors(status, message, expected):
    def handler(request):
        return httpx.Response(status, json={"error": {"code": status, "status": "X", "message": message}})

    with pytest.raises(expected):
        await _provider(handler).complete([Message.user("hi")])


async def test_missing_key_is_config_error_without_network():
    def handler(request):
        raise AssertionError("must not call the API without a key")

    p = GeminiProvider(api_key=None, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ProviderConfigError):
        await p.complete([Message.user("hi")])


def test_settings_and_pool(monkeypatch):
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PF_LLM_GEMINI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PF_LLM_PROVIDERS", "gemini,ollama")
    assert [p.name for p in build_pool(LLMSettings(_env_file=None)).providers] == ["ollama"]  # no key → skipped
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    pool = build_pool(LLMSettings(_env_file=None))
    assert [p.name for p in pool.providers] == ["gemini", "ollama"] and pool.providers[0].model == "gemini-flash-latest"


def test_tool_subprocesses_never_get_gemini_keys():
    env = {"GEMINI_API_KEY": "a", "GOOGLE_API_KEY": "b", "PATH": "/bin"}
    assert scrub_env(env) == {"PATH": "/bin"}
    assert scrub_env(env, allow_cloud=True) == {"PATH": "/bin"}  # not even the deploy-operator
