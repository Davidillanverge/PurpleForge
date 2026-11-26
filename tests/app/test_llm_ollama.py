"""OllamaProvider against a mocked /api/chat."""

from __future__ import annotations

import json

import httpx
import pytest

from llm import (
    InvalidRequestError,
    Message,
    OllamaProvider,
    ProviderConfigError,
    StopReason,
    ToolCall,
    ToolSpec,
    TransientProviderError,
)


def _provider(handler) -> OllamaProvider:
    client = httpx.AsyncClient(base_url="http://ollama.test", transport=httpx.MockTransport(handler))
    return OllamaProvider(model="qwen3:8b", client=client)


async def test_text_completion_and_request_shape():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "message": {"role": "assistant", "content": "hola"},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 5,
                "eval_count": 3,
            },
        )

    resp = await _provider(handler).complete([Message.user("hi")], system="sys", max_tokens=50, temperature=0.1)

    assert resp.content == "hola" and resp.stop_reason is StopReason.END_TURN
    assert resp.usage.total_tokens == 8 and resp.provider == "ollama"
    assert seen["path"] == "/api/chat"
    body = seen["body"]
    assert body["stream"] is False
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["options"] == {"num_predict": 50, "temperature": 0.1, "num_ctx": 32_768}


async def test_tool_calls_parsed_and_serialized():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "qwen3:8b",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "read_file", "arguments": {"path": "a.yml"}}},
                        {"function": {"name": "bash", "arguments": '{"cmd": "ls"}'}},  # some models send JSON text
                    ],
                },
                "done_reason": "stop",
            },
        )

    prior = ToolCall(id="c0", name="forge", arguments={"args": ["lab-spec"]})
    history = [Message.user("go"), Message.assistant("", [prior]), Message.tool_result(prior, "PASS")]
    tool = ToolSpec(name="read_file", description="read", input_schema={"type": "object"})
    resp = await _provider(handler).complete(history, tools=[tool])

    assert resp.stop_reason is StopReason.TOOL_USE
    assert [(c.name, c.arguments) for c in resp.tool_calls] == [
        ("read_file", {"path": "a.yml"}),
        ("bash", {"cmd": "ls"}),
    ]
    assert len({c.id for c in resp.tool_calls}) == 2  # synthesized ids are unique
    body = seen["body"]
    assert body["tools"][0]["function"]["name"] == "read_file"
    assert body["messages"][1]["tool_calls"] == [{"function": {"name": "forge", "arguments": {"args": ["lab-spec"]}}}]
    assert body["messages"][2] == {"role": "tool", "content": "PASS", "tool_name": "forge"}


async def test_length_stop_reason():
    def handler(request):
        return httpx.Response(200, json={"message": {"content": "trunc"}, "done_reason": "length"})

    resp = await _provider(handler).complete([Message.user("hi")])
    assert resp.stop_reason is StopReason.MAX_TOKENS


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, ProviderConfigError),
        (500, TransientProviderError),
        (429, TransientProviderError),
        (400, InvalidRequestError),
    ],
)
async def test_http_errors_are_classified(status, expected):
    def handler(request):
        return httpx.Response(status, json={"error": "model 'qwen3:8b' not found"})

    with pytest.raises(expected) as info:
        await _provider(handler).complete([Message.user("hi")])
    assert info.value.status_code == status


async def test_ollama_down_is_transient():
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(TransientProviderError):
        await _provider(handler).complete([Message.user("hi")])


async def test_num_ctx_is_always_sent():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"content": "ok"}, "done_reason": "stop"})

    await _provider(handler).complete([Message.user("hi")])
    assert seen["body"]["options"]["num_ctx"] == 32_768  # Ollama's small default truncates silently


@pytest.mark.parametrize(
    "content",
    [
        '{"name": "read_file", "arguments": {"path": "a.yml"}}',
        '```json\n{"name": "read_file", "arguments": {"path": "a.yml"}}\n```',
        '<tool_call>\n{"name": "read_file", "arguments": "{\\"path\\": \\"a.yml\\"}"}\n</tool_call>',
    ],
)
async def test_tool_call_written_as_text_is_recovered(content):
    """Regression (seen live with qwen2.5-coder:14b): the model wrote the call as JSON text."""

    def handler(request):
        return httpx.Response(200, json={"message": {"content": content}, "done_reason": "stop"})

    tool = ToolSpec(name="read_file", description="read", input_schema={"type": "object"})
    resp = await _provider(handler).complete([Message.user("go")], tools=[tool])
    assert resp.stop_reason is StopReason.TOOL_USE and resp.content == ""
    assert [(c.name, c.arguments) for c in resp.tool_calls] == [("read_file", {"path": "a.yml"})]


@pytest.mark.parametrize(
    "content",
    [
        'Sure! I will call {"name": "read_file", "arguments": {"path": "a.yml"}} next.',  # prose around it
        '{"name": "rm_rf", "arguments": {}}',  # not an offered tool
        '{"name": "read_file", "arguments": {"path": "a.yml"}',  # broken JSON
    ],
)
async def test_text_fallback_is_strict(content):
    def handler(request):
        return httpx.Response(200, json={"message": {"content": content}, "done_reason": "stop"})

    tool = ToolSpec(name="read_file", description="read", input_schema={"type": "object"})
    resp = await _provider(handler).complete([Message.user("go")], tools=[tool])
    assert resp.tool_calls == [] and resp.content == content
