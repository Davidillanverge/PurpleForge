"""Two API workers (two AgentRunners) sharing one DB and one Redis (fakeredis):
approvals, cancels and SSE must work no matter which worker the request hits,
and orphan recovery must only fail runs of workers that are gone."""

from __future__ import annotations

import asyncio

import fakeredis
import pytest
from _appkit import GATED, LLMQueue, wait_for
from _fakes import ScriptedLLM, call, reply

from api.auth import Principal
from api.broker import RedisEventBroker
from api.registry import VALIDATOR
from api.runner import AgentRunner
from api.settings import AppSettings
from api.sse import StreamEnd, StreamEvent, iter_run_events
from db import repository as repo
from db.session import transaction
from db.states import ApprovalStatus, LabState, RunState

ALICE = Principal(user="alice", tenant="default")


@pytest.fixture
async def cluster(sessionmaker, tmp_path):
    server = fakeredis.FakeServer()
    llms = LLMQueue()
    settings = AppSettings(
        _env_file=None,
        repo_root=tmp_path,
        approval_timeout_seconds=5,
        worker_heartbeat_seconds=0.05,
        orphan_grace_seconds=0,
    )
    runners = []
    for _ in range(2):
        broker = RedisEventBroker(fakeredis.FakeAsyncRedis(server=server))
        r = AgentRunner(
            sessionmaker, broker, settings, {GATED.name: GATED, VALIDATOR.name: VALIDATOR}, llm_factory=llms
        )
        await r.start_background()
        runners.append(r)
    yield runners[0], runners[1], llms
    for r in runners:
        await r.shutdown()
        await r.broker.aclose()


async def _pending(sessionmaker):
    async with sessionmaker() as s:
        return await repo.list_pending_approvals(s, "default")


async def test_workers_see_each_other(cluster):
    a, b, _ = cluster
    assert a.worker_id != b.worker_id
    assert {a.worker_id, b.worker_id} <= await b.broker.alive_workers()


async def test_approval_decided_on_other_worker(cluster, sessionmaker):
    a, b, llms = cluster
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy")), reply("deployed")))
    run = await a.start(ALICE, "gated-agent")
    assert run.worker_id == a.worker_id

    async def has_pending():
        return bool(await _pending(sessionmaker))

    await wait_for(has_pending)
    approval = (await _pending(sessionmaker))[0]
    assert not b.is_active(run.id)  # B doesn't own it…
    await b.decide(ALICE, approval.id, approved=True)  # …but can decide it
    await asyncio.wait_for(a.wait(run.id), 5)
    async with sessionmaker() as s:
        assert (await repo.get_run(s, "default", run.id)).status is RunState.COMPLETED


async def test_sse_on_other_worker_follows_the_run(cluster, sessionmaker):
    a, b, llms = cluster
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy")), reply("done")))
    run = await a.start(ALICE, "gated-agent")
    items: list = []

    async def consume():  # SSE client connected to worker B
        async for item in iter_run_events(
            sessionmaker=sessionmaker, broker=b.broker, tenant_id="default", run_id=run.id, heartbeat=0.05
        ):
            if item is not None:
                items.append(item)

    consumer = asyncio.create_task(consume())

    async def has_pending():
        return bool(await _pending(sessionmaker))

    await wait_for(has_pending)
    await asyncio.sleep(0.1)
    await b.decide(ALICE, (await _pending(sessionmaker))[0].id, approved=True)
    await asyncio.wait_for(consumer, 5)

    seqs = [i.seq for i in items if isinstance(i, StreamEvent)]
    assert seqs == list(range(1, len(seqs) + 1)) and len(seqs) >= 6  # no gaps, no dupes across the hop
    assert isinstance(items[-1], StreamEnd) and items[-1].status == "completed"


async def test_cancel_from_other_worker(cluster, sessionmaker):
    a, b, llms = cluster
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy"))))
    run = await a.start(ALICE, "gated-agent")

    async def has_pending():
        return bool(await _pending(sessionmaker))

    await wait_for(has_pending)
    assert await b.cancel(run.id, tenant="default") is True
    async with sessionmaker() as s:
        assert (await repo.get_run(s, "default", run.id)).status is RunState.CANCELLED
        approvals = await repo.list_run_approvals(s, "default", run.id)
    assert approvals[0].status is ApprovalStatus.EXPIRED
    assert await b.cancel(run.id, tenant="default") is False  # already over


async def test_sweep_only_fails_runs_of_dead_workers(cluster, sessionmaker):
    a, b, _ = cluster
    async with transaction(sessionmaker) as s:
        lab = await repo.create_lab(s, "default", name="lab-dead", spec_path="specs/x.yml")
        for st in (LabState.DESIGNED, LabState.COMPILED, LabState.READY):
            await repo.transition_lab(s, "default", lab, st, actor="system")
        await repo.transition_lab(s, "default", lab, LabState.APPROVED, actor="user:alice")
        for st in (LabState.DEPLOYING, LabState.DEPLOYED, LabState.VALIDATING):
            await repo.transition_lab(s, "default", lab, st, actor="system")
        dead = await repo.create_run(
            s, "default", agent="purple-validator", task="x", lab_id=lab.id, worker_id="crashed-worker"
        )
        dead.status = RunState.RUNNING
        alive = await repo.create_run(s, "default", agent="gated-agent", task="y", worker_id=a.worker_id)
        alive.status = RunState.RUNNING

    counts = await b.recover_orphans(grace=True)  # what the periodic sweep does
    assert counts == {"runs": 1, "approvals": 0, "labs": 1}
    async with sessionmaker() as s:
        assert (await repo.get_run(s, "default", dead.id)).status is RunState.FAILED
        assert (await repo.get_run(s, "default", alive.id)).status is RunState.RUNNING  # A is alive: untouched
        assert (await repo.get_lab(s, "default", lab.id)).state is LabState.DEPLOYED


async def test_worker_shutdown_withdraws_heartbeat(cluster):
    a, b, _ = cluster
    await a.shutdown()
    assert a.worker_id not in await b.broker.alive_workers()


def test_unique_worker_ids():
    ids = {AgentRunner(None, None, AppSettings(_env_file=None), {}).worker_id for _ in range(5)}  # type: ignore[arg-type]
    assert len(ids) == 5
