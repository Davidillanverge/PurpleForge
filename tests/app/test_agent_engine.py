"""AgentEngine loop with a scripted provider."""

from __future__ import annotations

import asyncio

import pytest
from _fakes import ScriptedLLM, call, reply
from pydantic import BaseModel

from agents import (
    AgentEngine,
    ApprovalDecision,
    BudgetLimits,
    EventType,
    RunStatus,
    Tool,
    ToolResult,
    relay_failover,
)
from llm import LLMPool, ProviderConfigError, Role, StopReason, TransientProviderError


class EchoInput(BaseModel):
    text: str


class EchoTool(Tool):
    name = "echo"
    description = "echo text back"
    Input = EchoInput

    def __init__(self, approval: bool = False):
        self.approval = approval
        self.ran: list[str] = []

    def needs_approval(self, args):
        return "dangerous echo" if self.approval else None

    async def run(self, args):
        self.ran.append(args.text)
        if args.text == "explode":
            raise RuntimeError("kaboom")
        return ToolResult(content=f"echo: {args.text}")


def engine(llm, tools=(), **kw):
    events = []
    kw.setdefault("on_event", events.append)
    return AgentEngine(llm, list(tools), system_prompt="SYS", agent_name="t", **kw), events


def types(events):
    return [e.type for e in events]


async def test_tool_loop_then_final_answer():
    llm = ScriptedLLM(reply("let me check", call("echo", text="hi")), reply("done: hi"))
    tool = EchoTool()
    eng, events = engine(llm, [tool])
    res = await eng.run("do it")

    assert res.status is RunStatus.COMPLETED and res.output == "done: hi"
    assert res.turns == 2 and res.usage.total_tokens == 40
    assert tool.ran == ["hi"]
    assert types(events) == [
        EventType.RUN_STARTED,
        EventType.ASSISTANT_MESSAGE,
        EventType.TOOL_CALL,
        EventType.TOOL_RESULT,
        EventType.ASSISTANT_MESSAGE,
        EventType.RUN_COMPLETED,
    ]
    assert [e.seq for e in events] == list(range(1, 7))
    assert {e.run_id for e in events} == {res.run_id}
    # Second request carries assistant turn + tool result; system + tool specs passed through.
    second = llm.requests[1]
    assert [m.role for m in second["messages"]] == [Role.USER, Role.ASSISTANT, Role.TOOL]
    assert second["messages"][2].content == "echo: hi"
    assert second["system"] == "SYS" and second["tools"][0].name == "echo"


async def test_unknown_tool_and_bad_args_go_back_as_errors():
    llm = ScriptedLLM(
        reply("", call("nope", "a"), call("echo", "b", wrong=1)),
        reply("recovered"),
    )
    eng, events = engine(llm, [EchoTool()])
    res = await eng.run("x")
    assert res.status is RunStatus.COMPLETED
    results = [m for m in llm.requests[1]["messages"] if m.role is Role.TOOL]
    assert results[0].is_error and "unknown tool" in results[0].content
    assert results[1].is_error and "invalid arguments" in results[1].content


async def test_tool_exception_is_not_fatal():
    llm = ScriptedLLM(reply("", call("echo", text="explode")), reply("ok"))
    eng, events = engine(llm, [EchoTool()])
    res = await eng.run("x")
    assert res.status is RunStatus.COMPLETED
    tr = next(e for e in events if e.type is EventType.TOOL_RESULT)
    assert tr.data["is_error"] and "kaboom" in tr.data["content"]


async def test_approval_fails_closed_without_approver():
    tool = EchoTool(approval=True)
    llm = ScriptedLLM(reply("", call("echo", text="deploy")), reply("gave up"))
    eng, events = engine(llm, [tool])
    await eng.run("x")
    assert tool.ran == []
    resolved = next(e for e in events if e.type is EventType.APPROVAL_RESOLVED)
    assert resolved.data["approved"] is False
    assert EventType.APPROVAL_REQUESTED in types(events)


async def test_approval_granted_runs_tool():
    tool = EchoTool(approval=True)
    seen = []

    async def approver(req):
        seen.append(req)
        return ApprovalDecision(approved=True, by="operator")

    llm = ScriptedLLM(reply("", call("echo", text="deploy")), reply("deployed"))
    eng, events = engine(llm, [tool], approver=approver)
    await eng.run("x")
    assert tool.ran == ["deploy"]
    assert seen[0].reason == "dangerous echo" and seen[0].tool_call.name == "echo"
    # request → resolved → result, in that order
    t = types(events)
    assert t.index(EventType.APPROVAL_REQUESTED) < t.index(EventType.APPROVAL_RESOLVED) < t.index(EventType.TOOL_RESULT)


async def test_approval_denied_and_approver_crash():
    tool = EchoTool(approval=True)

    async def approver(req):
        raise RuntimeError("approval service down")

    llm = ScriptedLLM(reply("", call("echo", text="deploy")), reply("stopped"))
    eng, _ = engine(llm, [tool], approver=approver)
    await eng.run("x")
    assert tool.ran == []
    assert "denied" in llm.requests[1]["messages"][-1].content


async def test_turn_budget_stops_run():
    llm = ScriptedLLM(*[reply("again", call("echo", f"c{i}", text=str(i))) for i in range(5)])
    eng, events = engine(llm, [EchoTool()], limits=BudgetLimits(max_turns=2))
    res = await eng.run("loop forever")
    assert res.status is RunStatus.BUDGET_EXCEEDED and res.turns == 2
    assert "turn limit" in res.error
    assert events[-1].type is EventType.BUDGET_EXCEEDED


async def test_token_budget_caps_max_tokens_and_stops():
    llm = ScriptedLLM(reply("", call("echo", text="a"), tokens=30), reply("never"))
    eng, _ = engine(
        llm, [EchoTool()], limits=BudgetLimits(max_output_tokens=50, max_total_tokens=None), max_tokens_per_turn=4096
    )
    res = await eng.run("x")
    assert llm.requests[0]["max_tokens"] == 50
    assert res.status is RunStatus.COMPLETED and len(llm.requests) == 2
    assert llm.requests[1]["max_tokens"] == 20  # 50 - 30 already spent


async def test_truncated_tool_call_not_executed():
    tool = EchoTool()
    llm = ScriptedLLM(reply("", call("echo", text="half"), stop=StopReason.MAX_TOKENS), reply("retried"))
    eng, _ = engine(llm, [tool])
    res = await eng.run("x")
    assert tool.ran == [] and res.status is RunStatus.COMPLETED
    assert "NOT executed" in llm.requests[1]["messages"][-1].content


async def test_truncated_text_asks_to_continue():
    llm = ScriptedLLM(reply("part one", stop=StopReason.MAX_TOKENS), reply("part two"))
    eng, _ = engine(llm)
    res = await eng.run("x")
    assert res.output == "part two"
    assert llm.requests[1]["messages"][-1].role is Role.USER


async def test_provider_failure_marks_run_failed():
    llm = ScriptedLLM(ProviderConfigError("no key", provider="anthropic"))
    eng, events = engine(llm)
    res = await eng.run("x")
    assert res.status is RunStatus.FAILED and "no key" in res.error
    assert events[-1].type is EventType.RUN_FAILED


async def test_refusal():
    eng, _ = engine(ScriptedLLM(reply("I can't help", stop=StopReason.REFUSAL)))
    assert (await eng.run("x")).status is RunStatus.REFUSED


async def test_listener_errors_do_not_break_run():
    def bad_listener(event):
        raise RuntimeError("SSE client went away")

    eng, _ = engine(ScriptedLLM(reply("fine")), on_event=bad_listener)
    assert (await eng.run("x")).status is RunStatus.COMPLETED


async def test_cancellation_emits_event():
    started = asyncio.Event()

    class Slow(EchoTool):
        async def run(self, args):
            started.set()
            await asyncio.sleep(60)

    eng, events = engine(ScriptedLLM(reply("", call("echo", text="x"))), [Slow()])
    task = asyncio.create_task(eng.run("x"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert events[-1].type is EventType.RUN_CANCELLED


async def test_pool_failover_lands_in_run_events():
    class Down:
        name, model = "anthropic", "m"

        async def complete(self, *a, **k):
            raise TransientProviderError("overloaded")

        async def aclose(self):
            pass

    async def no_sleep(_):
        pass

    pool = LLMPool(
        [Down(), ScriptedLLM(reply("from ollama"))], max_retries=0, on_failover=relay_failover, sleep=no_sleep
    )
    eng, events = engine(pool)
    res = await eng.run("x")
    assert res.output == "from ollama"
    fo = next(e for e in events if e.type is EventType.PROVIDER_FAILOVER)
    assert fo.data["from_provider"] == "anthropic" and fo.data["to_provider"] == "fake"


async def test_unexpected_llm_exception_is_a_visible_failure():
    """Regression: a non-ProviderError from the LLM must still end with RUN_FAILED."""

    class Broken(ScriptedLLM):
        async def complete(self, messages, **kw):
            raise TypeError("boom")

    eng, events = engine(Broken())
    res = await eng.run("x")
    assert res.status is RunStatus.FAILED and "TypeError: boom" in res.error
    assert events[-1].type is EventType.RUN_FAILED
