"""AgentEngine: the tool-use loop shared by every agent.

    task ─► LLM ─► assistant turn ─► (tool calls? ─► [approval gate] ─► run ─► results) ─► LLM ...
                                    └─ no calls ─► done

Guarantees:
- Every step is emitted as an AgentEvent through ``on_event``.
- The budget is checked before EVERY LLM call; exceeding it ends the run
  cleanly with status BUDGET_EXCEEDED.
- A tool flagged ``needs_approval`` never runs without an explicit APPROVED
  decision from the ``approver``. No approver configured ⇒ denied (fail closed).
- Tool failures (unknown tool, bad args, exceptions) go back to the model as
  error results; they never crash the run.
- Tool calls run sequentially, in the order the model issued them: they have
  side effects on a shared lab, so no implicit parallelism.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from enum import Enum

from pydantic import BaseModel, Field, ValidationError

from agents.budget import Budget, BudgetLimits
from agents.events import EventCallback, EventEmitter, EventType
from agents.tools import Tool, ToolResult, truncate
from llm.pool import FailoverEvent
from llm.provider import LLMProvider, Message, ProviderError, Role, StopReason, ToolCall, Usage

#: Max chars of a tool result copied into the event stream (the model still gets it whole).
EVENT_RESULT_PREVIEW = 4_000


class RunStatus(str, Enum):
    COMPLETED = "completed"
    BUDGET_EXCEEDED = "budget_exceeded"
    REFUSED = "refused"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalRequest(BaseModel):
    run_id: str
    agent: str
    tool_call: ToolCall
    reason: str


class ApprovalDecision(BaseModel):
    approved: bool
    by: str | None = None
    comment: str | None = None


Approver = Callable[[ApprovalRequest], Awaitable[ApprovalDecision]]


class AgentResult(BaseModel):
    run_id: str
    agent: str
    status: RunStatus
    output: str = ""
    error: str | None = None
    turns: int = 0
    usage: Usage = Field(default_factory=Usage)
    messages: list[Message] = Field(default_factory=list)


# --------------------------------------------------------------------------- failover relay
#
# One LLMPool is shared by many concurrent runs, so its on_failover callback
# can't be bound to a single run. Build the pool with ``on_failover=relay_failover``:
# the engine sets the current run's emitter in a ContextVar, and asyncio copies
# context per task, so each failover lands in the right run's event stream.

_current_emitter: ContextVar[EventEmitter | None] = ContextVar("pf_agent_emitter", default=None)


async def relay_failover(event: FailoverEvent) -> None:
    emitter = _current_emitter.get()
    if emitter is not None:
        await emitter.emit(
            EventType.PROVIDER_FAILOVER,
            from_provider=event.from_provider,
            to_provider=event.to_provider,
            error=str(event.error),
        )


# --------------------------------------------------------------------------- engine

TRUNCATED_TOOL_CALL = (
    "Your previous reply hit the max_tokens limit while writing this tool call, so its arguments "
    "may be incomplete; it was NOT executed. Retry with smaller arguments (e.g. write the file in parts)."
)
TRUNCATED_TEXT = "Your previous reply was cut off by the max_tokens limit. Continue exactly where you stopped."


class AgentEngine:
    def __init__(
        self,
        llm: LLMProvider,
        tools: list[Tool],
        *,
        system_prompt: str,
        agent_name: str = "agent",
        limits: BudgetLimits | None = None,
        on_event: EventCallback | None = None,
        approver: Approver | None = None,
        max_tokens_per_turn: int = 8192,
        temperature: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        names = [t.name for t in tools]
        if len(set(names)) != len(names):
            raise ValueError(f"duplicate tool names: {names}")
        self.llm = llm
        self.tools = {t.name: t for t in tools}
        self.system_prompt = system_prompt
        self.agent_name = agent_name
        self.limits = limits or BudgetLimits()
        self.on_event = on_event
        self.approver = approver
        self.max_tokens_per_turn = max_tokens_per_turn
        self.temperature = temperature
        self._clock = clock

    async def run(self, task: str, *, run_id: str | None = None, history: list[Message] | None = None) -> AgentResult:
        run_id = run_id or uuid.uuid4().hex
        emitter = EventEmitter(run_id, self.agent_name, self.on_event)
        budget = Budget(self.limits, clock=self._clock)
        messages: list[Message] = [*(history or []), Message.user(task)]
        token = _current_emitter.set(emitter)

        def result(status: RunStatus, output: str = "", error: str | None = None) -> AgentResult:
            return AgentResult(
                run_id=run_id,
                agent=self.agent_name,
                status=status,
                output=output,
                error=error,
                turns=budget.turns,
                usage=budget.usage,
                messages=messages,
            )

        try:
            await emitter.emit(
                EventType.RUN_STARTED,
                task=task,
                model=self.llm.model,
                provider=self.llm.name,
                tools=sorted(self.tools),
                limits=self.limits.model_dump(),
            )
            specs = [t.spec() for t in self.tools.values()]
            while True:
                reason = budget.exceeded()
                if reason:
                    await emitter.emit(EventType.BUDGET_EXCEEDED, reason=reason, budget=budget.snapshot())
                    return result(RunStatus.BUDGET_EXCEEDED, _last_text(messages), reason)

                try:
                    resp = await self.llm.complete(
                        messages,
                        system=self.system_prompt,
                        tools=specs or None,
                        max_tokens=budget.cap_max_tokens(self.max_tokens_per_turn),
                        temperature=self.temperature,
                    )
                except ProviderError as exc:
                    await emitter.emit(EventType.RUN_FAILED, error=str(exc), budget=budget.snapshot())
                    return result(RunStatus.FAILED, _last_text(messages), str(exc))
                except Exception as exc:  # noqa: BLE001 - provider bug: still a clean, visible failure
                    err = f"LLM call failed: {type(exc).__name__}: {exc}"
                    await emitter.emit(EventType.RUN_FAILED, error=err, budget=budget.snapshot())
                    return result(RunStatus.FAILED, _last_text(messages), err)

                budget.charge(resp.usage)
                messages.append(resp.to_message())
                await emitter.emit(
                    EventType.ASSISTANT_MESSAGE,
                    content=resp.content,
                    tool_calls=[c.model_dump() for c in resp.tool_calls],
                    stop_reason=resp.stop_reason.value,
                    usage=resp.usage.model_dump(),
                    provider=resp.provider,
                    model=resp.model,
                    budget=budget.snapshot(),
                )

                if resp.stop_reason is StopReason.REFUSAL:
                    await emitter.emit(EventType.RUN_FAILED, error="model refused", budget=budget.snapshot())
                    return result(RunStatus.REFUSED, resp.content, "model refused")

                if resp.tool_calls:
                    truncated = resp.stop_reason is StopReason.MAX_TOKENS
                    for call in resp.tool_calls:
                        if truncated:
                            tr = ToolResult(content=TRUNCATED_TOOL_CALL, is_error=True)
                        else:
                            tr = await self._execute(call, emitter, run_id)
                        messages.append(Message.tool_result(call, tr.content, is_error=tr.is_error))
                    continue

                if resp.stop_reason is StopReason.MAX_TOKENS:
                    messages.append(Message.user(TRUNCATED_TEXT))
                    continue

                await emitter.emit(EventType.RUN_COMPLETED, output=resp.content, budget=budget.snapshot())
                return result(RunStatus.COMPLETED, resp.content)
        except asyncio.CancelledError:
            await asyncio.shield(emitter.emit(EventType.RUN_CANCELLED, budget=budget.snapshot()))
            raise
        finally:
            _current_emitter.reset(token)

    async def _execute(self, call: ToolCall, emitter: EventEmitter, run_id: str) -> ToolResult:
        await emitter.emit(EventType.TOOL_CALL, id=call.id, name=call.name, arguments=call.arguments)
        started = self._clock()
        tr = await self._execute_inner(call, emitter, run_id)
        await emitter.emit(
            EventType.TOOL_RESULT,
            id=call.id,
            name=call.name,
            is_error=tr.is_error,
            content=truncate(tr.content, EVENT_RESULT_PREVIEW),
            data=tr.data,
            duration_ms=int((self._clock() - started) * 1000),
        )
        return tr

    async def _execute_inner(self, call: ToolCall, emitter: EventEmitter, run_id: str) -> ToolResult:
        tool = self.tools.get(call.name)
        if tool is None:
            return ToolResult(
                content=f"unknown tool {call.name!r}; available: {', '.join(sorted(self.tools))}", is_error=True
            )
        try:
            args = tool.Input.model_validate(call.arguments)
        except ValidationError as exc:
            return ToolResult(content=f"invalid arguments for {call.name}: {exc}", is_error=True)

        reason = tool.needs_approval(args)
        if reason:
            decision = await self._request_approval(call, reason, emitter, run_id)
            if not decision.approved:
                note = f": {decision.comment}" if decision.comment else ""
                return ToolResult(
                    content=f"denied by human approval gate{note}. Do not retry this action "
                    "unless the operator asks for it.",
                    is_error=True,
                    data={"approved": False},
                )

        try:
            return await tool.run(args)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced to the model, not fatal
            return ToolResult(content=f"{call.name} failed: {type(exc).__name__}: {exc}", is_error=True)

    async def _request_approval(
        self, call: ToolCall, reason: str, emitter: EventEmitter, run_id: str
    ) -> ApprovalDecision:
        await emitter.emit(
            EventType.APPROVAL_REQUESTED, id=call.id, name=call.name, arguments=call.arguments, reason=reason
        )
        if self.approver is None:
            decision = ApprovalDecision(approved=False, comment="no approver configured (fail closed)")
        else:
            try:
                decision = await self.approver(
                    ApprovalRequest(run_id=run_id, agent=self.agent_name, tool_call=call, reason=reason)
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - an approver crash is a denial
                decision = ApprovalDecision(approved=False, comment=f"approver error: {exc}")
        await emitter.emit(EventType.APPROVAL_RESOLVED, id=call.id, **decision.model_dump())
        return decision


def _last_text(messages: list[Message]) -> str:
    for m in reversed(messages):
        if m.role is Role.ASSISTANT and m.content:
            return m.content
    return ""
