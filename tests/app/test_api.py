"""HTTP API end-to-end (ASGI in-process, SQLite, scripted LLM)."""

from __future__ import annotations

import asyncio
import uuid

import httpx
from _appkit import ALICE, seed_lab, wait_for
from _fakes import ScriptedLLM, call, reply

from api.sse import run_event_stream
from db import repository as repo
from db.session import transaction
from db.states import LabState, RunState
from llm import ProviderConfigError

# --------------------------------------------------------------------------- auth + health


async def test_auth(client):
    assert (await client.get("/healthz", headers={"Authorization": ""})).status_code == 200
    assert (await client.get("/readyz")).json() == {"status": "ok"}
    assert (await client.get("/api/labs", headers={"Authorization": ""})).status_code == 401
    assert (await client.get("/api/labs", headers={"Authorization": "Bearer nope"})).status_code == 401
    cookie = await client.get(
        "/api/labs", headers={"Authorization": "", "Cookie": "pf_token=tok-bob-0123456789abcdefghijkl"}
    )
    assert cookie.status_code == 200


# --------------------------------------------------------------------------- labs


async def test_lab_crud_and_fsm_guards(client, repo_root):
    r = await client.post("/api/labs", json={"name": "draft-lab", "description": "x"})
    assert r.status_code == 201 and r.json()["state"] == "draft"
    lab_id = r.json()["id"]

    # spec picked up from specs/<name>.yml → designed, cloud from lab.provider
    r = await client.post("/api/labs", json={"name": "bare-lab"})
    assert r.json()["state"] == "designed" and r.json()["cloud"] == "aws"
    assert [t["to_state"] for t in r.json()["transitions"]] == ["draft", "designed"]
    assert r.json()["transitions"][1]["actor"] == "user:alice"

    assert (await client.post("/api/labs", json={"name": "bare-lab"})).status_code == 409
    assert (await client.post("/api/labs", json={"name": "Bad_Name"})).status_code == 422
    for bad in ("../etc/passwd.yml", "catalog/x.yml", "specs/bare-lab.yml"):  # last: name mismatch
        assert (await client.post("/api/labs", json={"name": "other-lab", "spec_path": bad})).status_code == 422

    r = await client.patch(f"/api/labs/{lab_id}", json={"description": "updated"})
    assert r.json()["description"] == "updated"

    # humans can't hand-mark forge-driven states, nor skip the FSM
    assert (await client.post(f"/api/labs/{lab_id}/transitions", json={"to": "ready"})).status_code == 403
    assert (await client.post(f"/api/labs/{lab_id}/transitions", json={"to": "approved"})).status_code == 409

    assert len((await client.get("/api/labs")).json()) == 2
    assert (await client.get("/api/labs", params={"state": "designed"})).json()[0]["name"] == "bare-lab"
    assert (await client.delete(f"/api/labs/{lab_id}")).status_code == 204
    assert (await client.get(f"/api/labs/{lab_id}")).status_code == 404


async def test_cannot_delete_lab_with_infrastructure(client):
    lab = await seed_lab(client.app, "live-lab", LabState.DEPLOYED)
    r = await client.delete(f"/api/labs/{lab.id}")
    assert r.status_code == 409 and "destroy it" in r.json()["detail"]


async def test_compile_guardrail_then_human_approval(client, repo_root):
    lab = (await client.post("/api/labs", json={"name": "winrm-validate-lab"})).json()
    r = await client.post(f"/api/labs/{lab['id']}/compile")
    body = r.json()
    assert r.status_code == 200 and body["ok"], body
    assert [s["command"].split()[1] for s in body["steps"]] == ["lab-spec", "guardrail"]
    assert "PASS" in body["steps"][1]["output"]
    assert body["lab"]["state"] == "ready"
    assert (repo_root / "generated" / "winrm-validate-lab" / "lab-manifest.json").is_file()

    r = await client.post(f"/api/labs/{lab['id']}/transitions", json={"to": "approved", "reason": "reviewed"})
    assert r.json()["state"] == "approved"
    assert r.json()["transitions"][-1]["actor"] == "user:alice"

    # recompiling drops the approval: back through designed → compiled → ready
    body = (await client.post(f"/api/labs/{lab['id']}/compile")).json()
    assert body["lab"]["state"] == "ready"
    states = [t["to_state"] for t in (await client.get(f"/api/labs/{lab['id']}/transitions")).json()]
    assert states[-4:] == ["approved", "designed", "compiled", "ready"]


async def test_compile_failure_stays_designed(client, repo_root):
    lab = (await client.post("/api/labs", json={"name": "bare-lab"})).json()  # not a valid full spec
    body = (await client.post(f"/api/labs/{lab['id']}/compile")).json()
    assert not body["ok"] and len(body["steps"]) == 1 and body["lab"]["state"] == "designed"


# --------------------------------------------------------------------------- runs + approvals + SSE


async def _pending(client):
    return (await client.get("/api/approvals")).json()


async def test_gated_run_approved_end_to_end(client, llms):
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy")), reply("deployed ok")))
    r = await client.post("/api/runs", json={"agent": "gated-agent"})
    assert r.status_code == 202
    run_id = r.json()["id"]

    await wait_for(lambda: _has_pending(client))
    run = (await client.get(f"/api/runs/{run_id}")).json()
    assert run["status"] == "waiting_approval" and run["active"]
    approval = (await _pending(client))[0]
    assert approval["tool_name"] == "gated" and approval["arguments"] == {"action": "deploy"}

    r = await client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": True, "comment": "go"})
    assert r.status_code == 200 and r.json()["decided_by"] == "user:alice"
    await client.app.state.runner.wait(uuid.UUID(run_id))

    run = (await client.get(f"/api/runs/{run_id}")).json()
    assert run["status"] == "completed" and run["output"] == "deployed ok" and not run["active"]
    assert run["created_by"] == "user:alice"
    events = (await client.get(f"/api/runs/{run_id}/events")).json()
    types = [e["type"] for e in events]
    assert types.index("approval_requested") < types.index("approval_resolved") < types.index("tool_result")
    assert next(e for e in events if e["type"] == "tool_result")["data"]["content"] == "did deploy"

    # a decision is final
    r = await client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": False})
    assert r.status_code == 409

    # SSE of a finished run: full replay, then `end`
    text = (await client.get(f"/api/runs/{run_id}/stream")).text
    assert text.count("event: ") == len(events) + 1 and text.rstrip().endswith('{"status":"completed"}')
    assert "id: 1\nevent: run_started" in text
    resumed = (await client.get(f"/api/runs/{run_id}/stream", headers={"Last-Event-ID": "3"})).text
    assert "id: 3\n" not in resumed and "id: 4\n" in resumed


async def _has_pending(client):
    return bool(await _pending(client))


async def test_denied_approval_does_not_run_tool(client, llms):
    llms.items.append(ScriptedLLM(reply("", call("gated", action="destroy")), reply("ok, not doing it")))
    run_id = (await client.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]
    await wait_for(lambda: _has_pending(client))
    approval = (await _pending(client))[0]
    await client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": False, "comment": "no"})
    await client.app.state.runner.wait(uuid.UUID(run_id))
    results = [e for e in (await client.get(f"/api/runs/{run_id}/events")).json() if e["type"] == "tool_result"]
    assert results[0]["data"]["is_error"] and "denied" in results[0]["data"]["content"]


async def test_approval_timeout_expires(make_app, llms):
    app = make_app(approval_timeout_seconds=0.1)
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy")), reply("timed out")))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            run_id = (await c.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]
            await app.state.runner.wait(uuid.UUID(run_id))
            approvals = (await c.get(f"/api/runs/{run_id}/approvals")).json()
            assert approvals[0]["status"] == "expired" and approvals[0]["decided_by"] == "system"
            r = await c.post(f"/api/approvals/{approvals[0]['id']}/decision", json={"approved": True})
            assert r.status_code == 409


async def test_cancel_while_waiting_expires_approval(client, llms):
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy"))))
    run_id = (await client.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]
    await wait_for(lambda: _has_pending(client))
    r = await client.post(f"/api/runs/{run_id}/cancel")
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    assert (await client.get(f"/api/runs/{run_id}/approvals")).json()[0]["status"] == "expired"
    assert await _pending(client) == []
    assert (await client.post(f"/api/runs/{run_id}/cancel")).status_code == 409


async def test_live_sse_stream_no_gaps_no_duplicates(client, llms):
    app = client.app
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy")), reply("done")))
    run_id = uuid.UUID((await client.post("/api/runs", json={"agent": "gated-agent"})).json()["id"])

    frames: list[str] = []

    async def consume():
        async for frame in run_event_stream(
            sessionmaker=app.state.sessionmaker,
            broker=app.state.broker,
            tenant_id="default",
            run_id=run_id,
            heartbeat=0.05,
        ):
            frames.append(frame)

    consumer = asyncio.create_task(consume())
    await wait_for(lambda: _has_pending(client))
    await asyncio.sleep(0.1)  # consumer is now live on the broker, past the replay
    approval = (await _pending(client))[0]
    await client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": True})
    await asyncio.wait_for(consumer, 5)

    ids = [int(f.split("\n")[0][4:]) for f in frames if f.startswith("id: ")]
    assert ids == list(range(1, len(ids) + 1))
    assert frames[-1].startswith("event: end") and '"completed"' in frames[-1]


# --------------------------------------------------------------------------- validator via API


async def _seed_generated(repo_root, name="winrm-validate-lab"):
    d = repo_root / "generated" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')


async def test_validator_run_drives_lab_state(client, llms, repo_root):
    await _seed_generated(repo_root)
    lab = await seed_lab(client.app, "winrm-validate-lab", LabState.DEPLOYED)
    gate = asyncio.Event()

    class HeldLLM(ScriptedLLM):
        async def complete(self, messages, **kw):
            await gate.wait()  # hold the run open so the lab stays VALIDATING
            return await super().complete(messages, **kw)

    llms.items.append(HeldLLM(reply("all vulns validated")))
    r = await client.post("/api/runs", json={"agent": "purple-validator", "lab_id": str(lab.id)})
    assert r.status_code == 202, r.text
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] == "validating"

    # one run per lab at a time
    llms.items.append(ScriptedLLM(reply("x")))
    dup = await client.post("/api/runs", json={"agent": "purple-validator", "lab_id": str(lab.id)})
    assert dup.status_code == 409 and "validating" in dup.json()["detail"]
    gate.set()

    await client.app.state.runner.wait(uuid.UUID(r.json()["id"]))
    detail = (await client.get(f"/api/labs/{lab.id}")).json()
    assert detail["state"] == "validated"
    assert detail["transitions"][-1]["actor"] == "agent:purple-validator"
    assert detail["runs"][0]["status"] == "completed"
    started = next(
        e for e in (await client.get(f"/api/runs/{r.json()['id']}/events")).json() if e["type"] == "run_started"
    )
    assert "forge validate specs/winrm-validate-lab.yml --run" in started["data"]["task"]


async def test_validator_failure_returns_lab_to_deployed(client, llms, repo_root):
    await _seed_generated(repo_root)
    lab = await seed_lab(client.app, "winrm-validate-lab", LabState.DEPLOYED)
    llms.items.append(ScriptedLLM(ProviderConfigError("no key", provider="anthropic")))
    run_id = (await client.post("/api/runs", json={"agent": "purple-validator", "lab_id": str(lab.id)})).json()["id"]
    await client.app.state.runner.wait(uuid.UUID(run_id))
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] == "deployed"
    assert (await client.get(f"/api/runs/{run_id}")).json()["status"] == "failed"


async def test_validator_preconditions(client, llms, repo_root):
    lab = await seed_lab(client.app, "winrm-validate-lab", LabState.DEPLOYED)
    llms.items.append(ScriptedLLM())
    r = await client.post("/api/runs", json={"agent": "purple-validator", "lab_id": str(lab.id)})
    assert r.status_code == 422 and "forge generate" in r.json()["detail"]  # no manifest yet
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] == "deployed"
    assert (await client.get("/api/runs")).json() == []

    ready = await seed_lab(client.app, "bare-lab", LabState.READY, spec="specs/bare-lab.yml")
    llms.items.append(ScriptedLLM())
    r = await client.post("/api/runs", json={"agent": "purple-validator", "lab_id": str(ready.id)})
    assert r.status_code == 409 and "needs: deployed, validated" in r.json()["detail"]
    assert (await client.post("/api/runs", json={"agent": "nope"})).status_code == 404
    assert [a["name"] for a in (await client.get("/api/agents")).json()] == ["purple-validator", "gated-agent"]


# --------------------------------------------------------------------------- providers


async def test_provider_config_api_never_returns_keys(client):
    r = await client.put(
        "/api/providers/claude",
        json={"kind": "anthropic", "model": "sonnet", "priority": 10, "api_key": "sk-ant-secret"},
    )
    assert r.status_code == 200 and r.json()["has_api_key"] and "sk-ant" not in r.text
    r = await client.put("/api/providers/claude", json={"kind": "anthropic", "model": "opus", "priority": 10})
    assert r.json()["has_api_key"] and r.json()["model"] == "opus"  # key kept
    r = await client.put("/api/providers/claude", json={"kind": "anthropic", "model": "opus", "api_key": None})
    assert not r.json()["has_api_key"]  # explicit null clears

    await client.put(
        "/api/providers/local",
        json={"kind": "ollama", "model": "qwen3:8b", "base_url": "http://127.0.0.1:9", "timeout_seconds": 1},
    )
    assert [p["name"] for p in (await client.get("/api/providers")).json()] == ["claude", "local"]
    assert "sk-ant" not in (await client.get("/api/providers")).text
    t = (await client.post("/api/providers/local/test")).json()
    assert t["ok"] is False and t["provider"] == "local" and t["error"]

    assert (await client.put("/api/providers/Bad Name", json={"kind": "ollama", "model": "m"})).status_code == 422
    assert (await client.delete("/api/providers/local")).status_code == 204
    assert (await client.delete("/api/providers/local")).status_code == 404


# --------------------------------------------------------------------------- restart recovery


async def test_startup_recovers_orphans(make_app, tmp_path):
    app = make_app()
    async with app.router.lifespan_context(app):
        lab = await seed_lab(app, "winrm-validate-lab", LabState.DEPLOYED)
        async with transaction(app.state.sessionmaker) as s:
            run = await repo.create_run(s, "default", agent="purple-validator", task="x", lab_id=lab.id)
            run.status = RunState.RUNNING
            lab = await repo.get_lab(s, "default", lab.id)
            await repo.transition_lab(s, "default", lab, LabState.VALIDATING, actor="system")
    # "crash": the next process starts against the same DB
    app2 = make_app()
    async with app2.router.lifespan_context(app2):
        async with app2.state.sessionmaker() as s:
            assert (await repo.get_run(s, "default", run.id)).status is RunState.FAILED
            assert (await repo.get_lab(s, "default", lab.id)).state is LabState.DEPLOYED
