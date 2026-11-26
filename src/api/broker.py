"""Cross-process plumbing for agent runs: live events, control messages, liveness.

Agent runs execute inside ONE API worker process (asyncio tasks). Everything
that must reach that process from another one goes through the broker:

- **events**  per run, fanned out to every SSE client on any worker;
- **control** approval decisions and cancellations, delivered to the worker
  that owns the run (whoever holds the waiting Future / the task acts on it);
- **liveness** worker heartbeats, so orphan recovery only fails the runs of
  workers that are actually gone.

``EventBroker`` is the in-memory single-process implementation (dev, tests,
one uvicorn worker). ``RedisEventBroker`` is the multi-worker one (compose).
The DB stays the durable log; brokers only carry live traffic.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from agents.events import AgentEvent

log = logging.getLogger(__name__)

#: A slow SSE client that falls this far behind is dropped (it reconnects and replays from the DB).
MAX_QUEUE = 1000

ControlHandler = Callable[[dict[str, Any]], Awaitable[None]]
EventQueue = asyncio.Queue[AgentEvent | None]


def _offer(queue: EventQueue, item: AgentEvent | None) -> bool:
    try:
        queue.put_nowait(item)
        return True
    except asyncio.QueueFull:
        return False


class EventBroker:
    """In-memory broker for a single process."""

    def __init__(self) -> None:
        self._subs: dict[str, set[EventQueue]] = defaultdict(set)
        self._control: ControlHandler | None = None

    # ---- events
    @asynccontextmanager
    async def subscribe(self, run_id: str) -> AsyncIterator[EventQueue]:
        queue: EventQueue = asyncio.Queue(maxsize=MAX_QUEUE)
        self._subs[run_id].add(queue)
        try:
            yield queue
        finally:
            self._subs[run_id].discard(queue)
            if not self._subs[run_id]:
                del self._subs[run_id]

    async def publish(self, event: AgentEvent) -> None:
        self._fanout(event.run_id, event)

    async def close_run(self, run_id: str) -> None:
        """Tell every subscriber of a run that no more events are coming."""
        self._fanout(run_id, None)

    def _fanout(self, run_id: str, item: AgentEvent | None) -> None:
        for queue in list(self._subs.get(run_id, ())):
            if not _offer(queue, item):
                self._subs[run_id].discard(queue)  # too slow: drop; its SSE ends on the next heartbeat

    def subscriber_count(self, run_id: str) -> int:
        return len(self._subs.get(run_id, ()))

    # ---- control (loopback: there is no other process)
    async def start(self, on_control: ControlHandler) -> None:
        self._control = on_control

    async def publish_control(self, message: dict[str, Any]) -> None:
        if self._control is not None:
            await self._control(message)

    # ---- liveness
    async def heartbeat(self, worker_id: str, ttl: float) -> None:
        pass

    async def forget_worker(self, worker_id: str) -> None:
        pass

    async def alive_workers(self) -> set[str] | None:
        """None = no cluster view (single process): only the caller is alive."""
        return None

    async def aclose(self) -> None:
        pass


class RedisEventBroker:
    """Redis pub/sub broker: any worker can serve any run's SSE, approvals and cancels."""

    EVENTS = "pf:run:{run_id}:events"
    CONTROL = "pf:control"
    WORKER = "pf:worker:{worker_id}"
    CLOSE = "__close__"

    def __init__(self, redis: Any) -> None:
        self.redis = redis
        self._control_task: asyncio.Task[None] | None = None

    # ---- events
    @asynccontextmanager
    async def subscribe(self, run_id: str) -> AsyncIterator[EventQueue]:
        queue: EventQueue = asyncio.Queue(maxsize=MAX_QUEUE)
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(self.EVENTS.format(run_id=run_id))
        await self._confirmed(pubsub)  # subscribed BEFORE the caller replays from the DB

        async def reader() -> None:
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                data = msg["data"]
                data = data.decode() if isinstance(data, bytes) else data
                if data == self.CLOSE:
                    _offer(queue, None)
                    return
                if not _offer(queue, AgentEvent.model_validate_json(data)):
                    _offer(queue, None)  # overflow → end this stream; the client reconnects and replays
                    return

        task = asyncio.create_task(reader())
        try:
            yield queue
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            with contextlib.suppress(Exception):
                await pubsub.unsubscribe()
                await pubsub.aclose()

    @staticmethod
    async def _confirmed(pubsub: Any, timeout: float = 5.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            msg = await pubsub.get_message(timeout=0.5)
            if msg and msg.get("type") == "subscribe":
                return
        raise TimeoutError("redis SUBSCRIBE not confirmed")

    async def publish(self, event: AgentEvent) -> None:
        await self.redis.publish(self.EVENTS.format(run_id=event.run_id), event.model_dump_json())

    async def close_run(self, run_id: str) -> None:
        await self.redis.publish(self.EVENTS.format(run_id=run_id), self.CLOSE)

    # ---- control
    async def start(self, on_control: ControlHandler) -> None:
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(self.CONTROL)
        await self._confirmed(pubsub)

        async def loop() -> None:
            try:
                async for msg in pubsub.listen():
                    if msg.get("type") != "message":
                        continue
                    try:
                        await on_control(json.loads(msg["data"]))
                    except Exception:  # noqa: BLE001 - one bad message must not stop the channel
                        log.exception("control message failed: %r", msg.get("data"))
            finally:
                with contextlib.suppress(Exception):
                    await pubsub.aclose()

        self._control_task = asyncio.create_task(loop(), name="pf-control")

    async def publish_control(self, message: dict[str, Any]) -> None:
        await self.redis.publish(self.CONTROL, json.dumps(message))

    # ---- liveness
    async def heartbeat(self, worker_id: str, ttl: float) -> None:
        await self.redis.set(self.WORKER.format(worker_id=worker_id), "1", px=int(ttl * 1000))

    async def forget_worker(self, worker_id: str) -> None:
        await self.redis.delete(self.WORKER.format(worker_id=worker_id))

    async def alive_workers(self) -> set[str] | None:
        prefix = self.WORKER.format(worker_id="")
        alive = set()
        async for key in self.redis.scan_iter(match=prefix + "*"):
            key = key.decode() if isinstance(key, bytes) else key
            alive.add(key[len(prefix) :])
        return alive

    async def aclose(self) -> None:
        if self._control_task is not None:
            self._control_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._control_task
        await self.redis.aclose()


Broker = EventBroker | RedisEventBroker
