"""Write one agent run's events straight to agent_events from ANY process.

The engine streams events in-process (EventEmitter → DbEventSink + broker). When
the brain or the tools live in another process — the MCP server, or Claude Code
driving the agent's tools over MCP — two writers append to the same run, so the
next ``seq`` is taken from the DB and a collision on (run_id, seq) is retried.
Same event shapes as the engine, so the console, run status and outcomes work
unchanged.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.events import AgentEvent, EventType
from db import repository as repo
from db.session import transaction


class Recorder:
    def __init__(
        self, sessionmaker: async_sessionmaker[AsyncSession], tenant: str, run_id: uuid.UUID | str, agent: str
    ) -> None:
        self.sessionmaker = sessionmaker
        self.tenant = tenant
        self.run_id = uuid.UUID(str(run_id))
        self.agent = agent

    async def emit(self, type_: EventType, **data: Any) -> AgentEvent:
        for attempt in range(20):
            try:
                async with transaction(self.sessionmaker) as s:
                    seq = await repo.max_event_seq(s, self.tenant, self.run_id) + 1
                    event = AgentEvent(run_id=str(self.run_id), agent=self.agent, seq=seq, type=type_, data=data)
                    await repo.record_event(s, self.tenant, event)
                return event
            except IntegrityError:
                await asyncio.sleep(0.01 * (attempt + 1))  # the other writer took this seq
        raise RuntimeError(f"could not append event to run {self.run_id} (seq contention)")

    async def events(self) -> list[Any]:
        async with self.sessionmaker() as s:
            return list(await repo.list_events(s, self.tenant, self.run_id, limit=100_000))
