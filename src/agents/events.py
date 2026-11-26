"""Agent events: the single stream every run emits.

The engine never talks to the API/DB directly — it calls an ``on_event``
callback with these. Phase 4 turns them into SSE frames and AgentEvent rows.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


class EventType(str, Enum):
    RUN_STARTED = "run_started"
    ASSISTANT_MESSAGE = "assistant_message"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    #: a chunk of a long-running tool's live output (no-AI forge runs stream deploy.sh etc.)
    TOOL_OUTPUT = "tool_output"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RESOLVED = "approval_resolved"
    PROVIDER_FAILOVER = "provider_failover"
    BUDGET_EXCEEDED = "budget_exceeded"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    RUN_CANCELLED = "run_cancelled"


class AgentEvent(BaseModel):
    run_id: str
    agent: str
    seq: int
    type: EventType
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)


EventCallback = Callable[[AgentEvent], Awaitable[None] | None]


class EventEmitter:
    """Numbers events per run and shields the run from a failing listener (a
    dropped SSE client must never abort a deploy half-way)."""

    def __init__(self, run_id: str, agent: str, callback: EventCallback | None) -> None:
        self.run_id = run_id
        self.agent = agent
        self._callback = callback
        self._seq = 0
        self.history: list[AgentEvent] = []

    async def emit(self, type_: EventType, **data: Any) -> AgentEvent:
        self._seq += 1
        event = AgentEvent(run_id=self.run_id, agent=self.agent, seq=self._seq, type=type_, data=data)
        self.history.append(event)
        if self._callback is not None:
            try:
                result = self._callback(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:  # noqa: BLE001 - listener bugs must not kill the run
                log.exception("agent event listener failed on %s #%d", type_.value, event.seq)
        return event
