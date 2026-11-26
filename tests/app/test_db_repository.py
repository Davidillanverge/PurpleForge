"""Repository: lab FSM, tenant isolation, runs/events, approvals, provider configs."""

from __future__ import annotations

from datetime import timezone

import pytest
from _fakes import ScriptedLLM, call, reply
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from agents import AgentEngine, ApprovalRequest, Tool, ToolResult
from db import repository as repo
from db.crypto import SecretCipher, SecretKeyMissing
from db.states import (
    INFRA_STATES,
    LAB_TRANSITIONS,
    ApprovalStatus,
    InvalidTransition,
    LabState,
    ProviderKind,
    RunState,
)
from llm import AnthropicProvider, OllamaProvider, ToolCall

T1, T2 = "tenant-a", "tenant-b"
KEY = "k" * 40


# --------------------------------------------------------------------------- FSM


def test_deploying_only_reachable_from_approved():
    sources = {s for s, targets in LAB_TRANSITIONS.items() if LabState.DEPLOYING in targets}
    assert sources == {LabState.APPROVED}


def test_destroyed_only_via_destroying_and_every_state_has_entry():
    assert {s for s, t in LAB_TRANSITIONS.items() if LabState.DESTROYED in t} == {LabState.DESTROYING}
    assert set(LAB_TRANSITIONS) == set(LabState)
    assert LabState.FAILED in INFRA_STATES and LabState.READY not in INFRA_STATES


async def _walk(session, lab, *states, actor="system"):
    for st in states:
        await repo.transition_lab(session, T1, lab, st, actor="user:alice" if st is LabState.APPROVED else actor)


async def test_lab_happy_path_records_timeline(session):
    lab = await repo.create_lab(session, T1, name="lab1", spec_path="specs/lab1.yml", actor="user:alice")
    await _walk(
        session,
        lab,
        LabState.DESIGNED,
        LabState.COMPILED,
        LabState.READY,
        LabState.APPROVED,
        LabState.DEPLOYING,
        LabState.DEPLOYED,
        LabState.VALIDATING,
        LabState.VALIDATED,
        LabState.DESTROYING,
        LabState.DESTROYED,
    )
    await session.commit()
    rows = await repo.list_transitions(session, T1, lab.id)
    assert [r.to_state for r in rows][:3] == [LabState.DRAFT, LabState.DESIGNED, LabState.COMPILED]
    assert rows[0].from_state is None and rows[-1].to_state is LabState.DESTROYED
    assert rows[4].actor == "user:alice"
    assert lab.state_changed_at.tzinfo is not None
    fresh = await repo.get_lab(session, T1, lab.id)
    assert fresh.created_at.tzinfo == timezone.utc


async def test_cannot_skip_the_approval_gate(session):
    lab = await repo.create_lab(session, T1, name="lab1")
    await _walk(session, lab, LabState.DESIGNED, LabState.COMPILED, LabState.READY)
    with pytest.raises(InvalidTransition):
        await repo.transition_lab(session, T1, lab, LabState.DEPLOYING, actor="agent:deploy-operator")
    with pytest.raises(repo.ActorNotAllowed):
        await repo.transition_lab(session, T1, lab, LabState.APPROVED, actor="agent:deploy-operator")
    assert lab.state is LabState.READY


async def test_failure_records_error_and_only_exit_is_teardown(session):
    lab = await repo.create_lab(session, T1, name="lab1")
    await _walk(
        session, lab, LabState.DESIGNED, LabState.COMPILED, LabState.READY, LabState.APPROVED, LabState.DEPLOYING
    )
    await repo.transition_lab(session, T1, lab, LabState.FAILED, actor="agent:deploy-operator", error="apply failed")
    assert lab.last_error == "apply failed" and lab.state in INFRA_STATES
    for target in (LabState.DEPLOYING, LabState.DESIGNED, LabState.APPROVED):
        with pytest.raises(InvalidTransition):  # no re-deploy on inherited approval, no "forgetting" the infra
            await repo.transition_lab(session, T1, lab, target, actor="user:alice")
    await _walk(session, lab, LabState.DESTROYING, LabState.DESTROYED, LabState.DESIGNED)
    assert lab.last_error is None and lab.state not in INFRA_STATES


def test_failed_is_only_entered_from_live_operations():
    sources = {s for s, t in LAB_TRANSITIONS.items() if LabState.FAILED in t}
    assert sources == {LabState.DEPLOYING, LabState.VALIDATING, LabState.DESTROYING}


# --------------------------------------------------------------------------- tenants


async def test_tenant_isolation(session):
    lab = await repo.create_lab(session, T1, name="shared-name")
    await repo.create_lab(session, T2, name="shared-name")  # same name, other tenant: fine
    await session.commit()
    assert [lab_.tenant_id for lab_ in await repo.list_labs(session, T2)] == [T2]
    with pytest.raises(repo.NotFound):
        await repo.get_lab(session, T2, lab.id)
    with pytest.raises(repo.NotFound):
        await repo.transition_lab(session, T2, lab, LabState.DESIGNED, actor="system")
    with pytest.raises(repo.NotFound):  # can't attach a run to another tenant's lab
        await repo.create_run(session, T2, agent="purple-validator", task="x", lab_id=lab.id)


async def test_lab_name_unique_per_tenant(session):
    await repo.create_lab(session, T1, name="dup")
    with pytest.raises(IntegrityError):
        await repo.create_lab(session, T1, name="dup")


# --------------------------------------------------------------------------- runs + events


class EchoIn(BaseModel):
    text: str


class Echo(Tool):
    name = "echo"
    description = "echo"
    Input = EchoIn

    def needs_approval(self, args):
        return "gated" if args.text == "gated" else None

    async def run(self, args):
        return ToolResult(content=args.text)


async def test_db_event_sink_persists_a_real_engine_run(sessionmaker):
    async with sessionmaker() as s, s.begin():
        lab = await repo.create_lab(s, T1, name="lab1")
        run = await repo.create_run(
            s, T1, agent="purple-validator", task="validate", lab_id=lab.id, created_by="user:alice"
        )
    assert run.status is RunState.QUEUED

    sink = repo.DbEventSink(sessionmaker, T1)
    llm = ScriptedLLM(reply("", call("echo", text="hi")), reply("all good"))
    engine = AgentEngine(llm, [Echo()], system_prompt="s", agent_name="purple-validator", on_event=sink)
    result = await engine.run("validate", run_id=str(run.id))

    async with sessionmaker() as s:
        events = await repo.list_events(s, T1, run.id)
        assert [e.seq for e in events] == list(range(1, len(events) + 1))
        assert [e.type for e in events][0] == "run_started" and events[-1].type == "run_completed"
        assert (await repo.list_events(s, T1, run.id, after_seq=4))[0].seq == 5  # SSE replay
        assert await repo.list_events(s, T2, run.id) == []
        stored = await repo.get_run(s, T1, run.id)
        assert stored.status is RunState.COMPLETED and stored.output == "all good"
        assert stored.turns == 2 and stored.input_tokens == 20 and stored.provider == "fake"
        assert stored.started_at and stored.finished_at

    async with sessionmaker() as s, s.begin():
        final = await repo.finish_run(s, T1, result)
    assert final.status is RunState.COMPLETED


async def test_waiting_approval_status_follows_events(sessionmaker):
    async with sessionmaker() as s, s.begin():
        run = await repo.create_run(s, T1, agent="deploy-operator", task="deploy")
    seen = []

    async def approver(req):
        async with sessionmaker() as s:
            seen.append((await repo.get_run(s, T1, run.id)).status)
        from agents import ApprovalDecision

        return ApprovalDecision(approved=False)

    llm = ScriptedLLM(reply("", call("echo", text="gated")), reply("stopped"))
    engine = AgentEngine(
        llm, [Echo()], system_prompt="s", on_event=repo.DbEventSink(sessionmaker, T1), approver=approver
    )
    await engine.run("x", run_id=str(run.id))
    assert seen == [RunState.WAITING_APPROVAL]


# --------------------------------------------------------------------------- approvals


async def test_approval_lifecycle(session):
    run = await repo.create_run(session, T1, agent="deploy-operator", task="deploy")
    req = ApprovalRequest(
        run_id=str(run.id),
        agent="deploy-operator",
        reason="forge deploy acts on live infra",
        tool_call=ToolCall(id="c1", name="forge", arguments={"subcommand": "deploy"}),
    )
    approval = await repo.create_approval(session, T1, req)
    assert [a.id for a in await repo.list_pending_approvals(session, T1)] == [approval.id]
    assert await repo.list_pending_approvals(session, T2) == []

    with pytest.raises(repo.ActorNotAllowed):
        await repo.decide_approval(session, T1, approval.id, approved=True, by="agent:deploy-operator")
    with pytest.raises(repo.NotFound):
        await repo.decide_approval(session, T2, approval.id, approved=True, by="user:mallory")

    decided = await repo.decide_approval(session, T1, approval.id, approved=True, by="user:alice", comment="go")
    assert decided.status is ApprovalStatus.APPROVED and decided.decided_at is not None
    with pytest.raises(repo.ApprovalAlreadyDecided):
        await repo.decide_approval(session, T1, approval.id, approved=False, by="user:bob")


# --------------------------------------------------------------------------- providers


def test_cipher_roundtrip_and_requires_key():
    c = SecretCipher(KEY)
    token = c.encrypt("sk-ant-123")
    assert "sk-ant" not in token and c.decrypt(token) == "sk-ant-123"
    with pytest.raises(ValueError):
        SecretCipher("x" * 40).decrypt(token)
    with pytest.raises(SecretKeyMissing):
        SecretCipher("short")


async def test_provider_configs_build_tenant_pool(session):
    cipher = SecretCipher(KEY)
    await repo.upsert_provider_config(
        session,
        T1,
        name="local",
        kind=ProviderKind.OLLAMA,
        model="qwen3:8b",
        priority=20,
        base_url="http://gpu-box:11434",
    )
    cfg = await repo.upsert_provider_config(
        session,
        T1,
        name="claude",
        kind=ProviderKind.ANTHROPIC,
        model="sonnet",
        priority=10,
        api_key="sk-ant-123",
        cipher=cipher,
    )
    assert cfg.has_api_key and "sk-ant" not in cfg.api_key_encrypted
    # update without api_key keeps the stored key
    cfg = await repo.upsert_provider_config(
        session, T1, name="claude", kind=ProviderKind.ANTHROPIC, model="opus", priority=10
    )
    assert cfg.has_api_key
    await repo.upsert_provider_config(session, T1, name="off", kind=ProviderKind.OLLAMA, model="x", enabled=False)

    pool = await repo.build_tenant_pool(session, T1, cipher=cipher)
    assert [p.name for p in pool.providers] == ["claude", "local"]
    assert isinstance(pool.providers[0], AnthropicProvider) and pool.providers[0].model == "claude-opus-5-5"
    assert isinstance(pool.providers[1], OllamaProvider)
    await pool.aclose()

    with pytest.raises(ValueError):
        await repo.upsert_provider_config(
            session, T1, name="nokey", kind=ProviderKind.ANTHROPIC, model="m", api_key="sk"
        )


async def test_tenant_without_configs_falls_back_to_env(session, monkeypatch):
    from llm.settings import LLMSettings

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("PF_LLM_ANTHROPIC_API_KEY", raising=False)
    pool = await repo.build_tenant_pool(session, T2, settings=LLMSettings(_env_file=None))
    assert [p.name for p in pool.providers] == ["ollama"]
    await pool.aclose()
