"""Server-Sent Events for one agent run: DB replay + live broker, de-duplicated by seq.

Order matters: subscribe to the broker FIRST, then replay from the DB. Any event
published in between sits in the queue and is dropped as a duplicate (seq ≤ last
sent), so a client never misses or double-receives an event. Reconnects resume
with ``Last-Event-ID`` (= seq).

``iter_run_events`` is the transport-agnostic core; the JSON API and the HTML
console are two formatters over it.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agents.events import EventType
from api.broker import Broker
from db import repository as repo

TERMINAL_EVENT_TYPES = frozenset(
    {
        EventType.RUN_COMPLETED.value,
        EventType.RUN_FAILED.value,
        EventType.BUDGET_EXCEEDED.value,
        EventType.RUN_CANCELLED.value,
    }
)


@dataclass
class StreamEvent:
    seq: int
    type: str
    ts: datetime
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamEnd:
    status: str


#: None = heartbeat (nothing happened for ``heartbeat`` seconds)
StreamItem = StreamEvent | StreamEnd | None


async def iter_run_events(
    *,
    sessionmaker: async_sessionmaker[AsyncSession],
    broker: Broker,
    tenant_id: str,
    run_id: uuid.UUID,
    after_seq: int = 0,
    heartbeat: float = 15.0,
    poll_seconds: float = 1.0,
) -> AsyncIterator[StreamItem]:
    """Events after ``after_seq`` until the run ends; always finishes with a StreamEnd.

    "Ended" is decided from the DB run status — valid cluster-wide, unlike
    "does this worker execute it" — so a client on worker B follows a run
    executing on worker A until its terminal event. Live events come from the
    broker; when it is quiet the DB is polled every ``poll_seconds``, which is how
    runs recorded by another process (the MCP server) stream live too.
    """
    last = after_seq
    async with broker.subscribe(str(run_id)) as queue:
        async with sessionmaker() as s:
            replay = await repo.list_events(s, tenant_id, run_id, after_seq=after_seq, limit=100_000)
            run = await repo.get_run(s, tenant_id, run_id)
        for ev in replay:
            last = ev.seq
            yield StreamEvent(seq=ev.seq, type=ev.type, ts=ev.ts, data=ev.data)
            if ev.type in TERMINAL_EVENT_TYPES:
                yield StreamEnd(run.status.value)
                return
        if run.status.is_terminal:
            yield StreamEnd(run.status.value)
            return

        idle = 0.0
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=poll_seconds)
            except asyncio.TimeoutError:
                # Nothing on the broker: events may come from ANOTHER process that only
                # writes to the DB (the MCP server, or a worker without Redis) — poll it.
                async with sessionmaker() as s:
                    fresh = await repo.list_events(s, tenant_id, run_id, after_seq=last, limit=1000)
                    status = (await repo.get_run(s, tenant_id, run_id)).status
                ended = False
                for ev in fresh:
                    last = ev.seq
                    yield StreamEvent(seq=ev.seq, type=ev.type, ts=ev.ts, data=ev.data)
                    ended = ended or ev.type in TERMINAL_EVENT_TYPES
                if ended or (status.is_terminal and not fresh):
                    break
                idle = 0.0 if fresh else idle + poll_seconds
                if idle >= heartbeat:
                    idle = 0.0
                    yield None
                continue
            if item is None:  # broker closed the run
                break
            if item.seq <= last:
                continue
            last = item.seq
            yield StreamEvent(seq=item.seq, type=item.type.value, ts=item.ts, data=item.model_dump(mode="json")["data"])
            if item.type.value in TERMINAL_EVENT_TYPES:
                break

    async with sessionmaker() as s:
        run = await repo.get_run(s, tenant_id, run_id)
    yield StreamEnd(run.status.value)


def format_sse(*, data: str, event: str | None = None, id_: int | None = None) -> str:
    lines = []
    if id_ is not None:
        lines.append(f"id: {id_}")
    if event is not None:
        lines.append(f"event: {event}")
    lines.extend(f"data: {chunk}" for chunk in data.split("\n"))
    return "\n".join(lines) + "\n\n"


def _json(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


async def run_event_stream(**kwargs: Any) -> AsyncIterator[str]:
    """JSON SSE for the API: ``event: <type>`` with ``{seq, ts, data}``, then ``event: end``."""
    async for item in iter_run_events(**kwargs):
        if item is None:
            yield ": keep-alive\n\n"
        elif isinstance(item, StreamEnd):
            yield format_sse(event="end", data=_json({"status": item.status}))
        else:
            yield format_sse(
                id_=item.seq, event=item.type, data=_json({"seq": item.seq, "ts": item.ts, "data": item.data})
            )
