"""Scripted LLM for engine/agent tests."""

from __future__ import annotations

from llm.provider import LLMResponse, Message, ProviderError, StopReason, ToolCall, Usage


def reply(text: str = "", *calls: ToolCall, stop: StopReason | None = None, tokens: int = 10) -> LLMResponse:
    if stop is None:
        stop = StopReason.TOOL_USE if calls else StopReason.END_TURN
    return LLMResponse(
        content=text,
        tool_calls=list(calls),
        stop_reason=stop,
        usage=Usage(input_tokens=tokens, output_tokens=tokens),
        model="fake-model",
        provider="fake",
    )


def call(name: str, id_: str = "c1", **arguments) -> ToolCall:
    return ToolCall(id=id_, name=name, arguments=arguments)


class ScriptedLLM:
    """Returns (or raises) the scripted items in order; records every request."""

    name = "fake"
    model = "fake-model"

    def __init__(self, *script: LLMResponse | ProviderError):
        self.script = list(script)
        self.requests: list[dict] = []

    async def complete(self, messages: list[Message], **kwargs) -> LLMResponse:
        self.requests.append({"messages": [m.model_copy(deep=True) for m in messages], **kwargs})
        if not self.script:
            raise AssertionError("ScriptedLLM ran out of replies")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self) -> None:
        pass
