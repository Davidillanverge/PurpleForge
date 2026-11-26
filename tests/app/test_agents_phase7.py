"""Phase 7 agents end-to-end through the API, with the REAL registry and real forge
(scripted LLM; deploy.sh/teardown.sh are local stubs, so no cloud is ever touched).

What these prove is the contract that matters for a security tool: the lab state
after a run comes from what actually happened (exit codes, approvals, files on
disk), never from what the agent claims."""

from __future__ import annotations

import uuid

import httpx
import pytest
from _appkit import ALICE, seed_lab, wait_for
from _fakes import ScriptedLLM, call, reply

from agents import deploy_operator
from api.forge_ops import compile_and_guardrail
from api.registry import default_registry

SPEC = "specs/winrm-validate-lab.yml"
LAB = "winrm-validate-lab"


@pytest.fixture
async def app_client(make_app):
    app = make_app(registry=default_registry())
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", headers=ALICE) as c:
            c.app = app
            yield c


@pytest.fixture
def toolchain(monkeypatch):
    """Pretend the operator toolchain is installed (the stubs below do the 'work')."""
    monkeypatch.setattr(deploy_operator.shutil, "which", lambda b: f"/usr/bin/{b}")


async def _render(repo_root, *, deploy_exit=0, teardown_exit=0):
    """A real forge-compiled manifest + stub lifecycle scripts in generated/<lab>/."""
    steps = await compile_and_guardrail(repo_root, repo_root / SPEC, LAB, timeout=120)
    assert all(s.ok for s in steps), steps
    lab_dir = repo_root / "generated" / LAB
    (lab_dir / "deploy.sh").write_text(f"#!/bin/bash\necho 'stub deploy.sh $1'\nexit {deploy_exit}\n")
    (lab_dir / "teardown.sh").write_text(f"#!/bin/bash\necho 'stub teardown.sh $@'\nexit {teardown_exit}\n")
    return lab_dir


async def _run(client, agent, lab_id=None, instructions=""):
    body = {"agent": agent, "instructions": instructions}
    if lab_id:
        body["lab_id"] = str(lab_id)
    r = await client.post("/api/runs", json=body)
    assert r.status_code == 202, r.text
    return uuid.UUID(r.json()["id"])


async def _decide_all(client, run_id, approved: bool):
    async def pending():
        return [a for a in (await client.get(f"/api/runs/{run_id}/approvals")).json() if a["status"] == "pending"]

    await wait_for(lambda: _nonempty(pending))
    for a in await pending():
        await client.post(f"/api/approvals/{a['id']}/decision", json={"approved": approved, "comment": "test"})


async def _nonempty(fn):
    return bool(await fn())


async def _lab(client, lab_id):
    return (await client.get(f"/api/labs/{lab_id}")).json()


# --------------------------------------------------------------------------- deploy-operator


async def test_deploy_succeeds_only_when_forge_deploy_exits_0(app_client, llms, repo_root, toolchain):
    await _render(repo_root, deploy_exit=0)
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(ScriptedLLM(reply("", call("forge", "d1", subcommand="deploy", args=[SPEC])), reply("deployed")))
    run_id = await _run(app_client, "deploy-operator", lab.id)
    assert (await _lab(app_client, lab.id))["state"] == "deploying"
    approval = None

    async def pending():
        return (await app_client.get(f"/api/runs/{run_id}/approvals")).json()

    await wait_for(lambda: _nonempty(pending))
    approval = (await pending())[0]
    assert approval["arguments"]["subcommand"] == "deploy" and "live infrastructure" in approval["reason"]
    await app_client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": True})
    await app_client.app.state.runner.wait(run_id)

    detail = await _lab(app_client, lab.id)
    assert detail["state"] == "deployed", detail["transitions"][-1]
    assert detail["transitions"][-1]["reason"].startswith("forge deploy exited 0")
    results = [e for e in (await app_client.get(f"/api/runs/{run_id}/events")).json() if e["type"] == "tool_result"]
    assert results[0]["data"]["data"]["background"]  # the call returned at once; forge ran as a job
    out = results[-1]  # the job's own final result
    assert out["data"]["data"]["final"] and out["data"]["data"]["exit_code"] == 0
    assert (
        "guardrail" in out["data"]["content"] and "stub deploy.sh" in out["data"]["content"]
    )  # real forge ran the gate


async def test_agent_claiming_success_does_not_make_a_lab_deployed(app_client, llms, repo_root, toolchain):
    await _render(repo_root, deploy_exit=1)  # deploy.sh fails after (pretend) terraform touched the cloud
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(
        ScriptedLLM(
            reply("", call("forge", "d1", subcommand="deploy", args=[SPEC])),
            reply("Deployment completed successfully!"),  # the agent lies / is wrong
        )
    )
    run_id = await _run(app_client, "deploy-operator", lab.id)
    await _decide_all(app_client, run_id, approved=True)
    await app_client.app.state.runner.wait(run_id)
    assert (await app_client.get(f"/api/runs/{run_id}")).json()["status"] == "completed"
    detail = await _lab(app_client, lab.id)
    assert detail["state"] == "failed" and "after touching infrastructure" in detail["transitions"][-1]["reason"]

    # failed ⇒ the only way out is a teardown (cost-zero verified)
    assert (await app_client.post(f"/api/labs/{lab.id}/transitions", json={"to": "designed"})).status_code == 409
    await _render(repo_root, teardown_exit=0)
    llms.items.append(
        ScriptedLLM(reply("", call("forge", "t1", subcommand="teardown", args=[SPEC, "--force"])), reply("gone"))
    )
    run_id = await _run(app_client, "deploy-operator-teardown", lab.id)
    await _decide_all(app_client, run_id, approved=True)
    await app_client.app.state.runner.wait(run_id)
    detail = await _lab(app_client, lab.id)
    assert detail["state"] == "destroyed" and "cost-zero" in detail["transitions"][-1]["reason"]


async def test_denied_deploy_never_touches_infra_and_needs_reapproval(app_client, llms, repo_root, toolchain):
    await _render(repo_root)
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(
        ScriptedLLM(reply("", call("forge", "d1", subcommand="deploy", args=[SPEC])), reply("ok, stopping"))
    )
    run_id = await _run(app_client, "deploy-operator", lab.id)
    await _decide_all(app_client, run_id, approved=False)
    await app_client.app.state.runner.wait(run_id)
    detail = await _lab(app_client, lab.id)
    assert detail["state"] == "ready" and "never touched infrastructure" in detail["transitions"][-1]["reason"]
    assert not (repo_root / "generated" / LAB / "stub-ran").exists()


async def test_deploy_agent_cannot_act_on_another_lab(app_client, llms, repo_root, toolchain):
    await _render(repo_root)
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(
        ScriptedLLM(
            reply(
                "",
                call("forge", "x1", subcommand="deploy", args=["specs/bare-lab.yml"]),
                call("forge", "x2", subcommand="deploy", args=[SPEC, "--skip-guardrail"]),
                call("bash", "x3", command="cat .env"),
            ),
            reply("blocked"),
        )
    )
    run_id = await _run(app_client, "deploy-operator", lab.id)
    await app_client.app.state.runner.wait(run_id)
    results = {
        e["data"]["id"]: e["data"]
        for e in (await app_client.get(f"/api/runs/{run_id}/events")).json()
        if e["type"] == "tool_result"
    }
    assert "only act on" in results["x1"]["content"]
    assert "--skip-guardrail" in results["x2"]["content"]
    assert "deny rule" in results["x3"]["content"]
    assert (await app_client.get(f"/api/runs/{run_id}/approvals")).json() == []  # nobody was paged for these
    assert (await _lab(app_client, lab.id))["state"] == "ready"


async def test_deploy_refused_without_toolchain(app_client, llms, monkeypatch):
    monkeypatch.setattr(deploy_operator.shutil, "which", lambda b: None)
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(ScriptedLLM())
    r = await app_client.post("/api/runs", json={"agent": "deploy-operator", "lab_id": str(lab.id)})
    assert r.status_code == 422 and "missing on PATH" in r.json()["detail"] and "terraform" in r.json()["detail"]
    assert (await _lab(app_client, lab.id))["state"] == "approved"


async def test_teardown_that_never_ran_returns_lab_where_it_was(app_client, llms, repo_root, toolchain):
    await _render(repo_root)
    lab = await seed_lab(app_client.app, LAB, "deployed")
    llms.items.append(ScriptedLLM(reply("I'd rather not.")))
    run_id = await _run(app_client, "deploy-operator-teardown", lab.id)
    await app_client.app.state.runner.wait(run_id)
    assert (await _lab(app_client, lab.id))["state"] == "deployed"


# --------------------------------------------------------------------------- lab-designer


def _spec_text(repo_root, name):
    return (repo_root / SPEC).read_text().replace(f"name: {LAB}", f"name: {name}")


async def test_designer_writes_spec_and_forge_checks_it(app_client, llms, repo_root):
    lab = (
        await app_client.post("/api/labs", json={"name": "new-lab", "description": "DC + workstation, WinRM vulns"})
    ).json()
    assert lab["state"] == "draft"
    llms.items.append(
        ScriptedLLM(
            reply(
                "",
                call("write_file", "w0", path="specs/other-lab.yml", content="lab: {name: other-lab}"),
                call("forge", "f0", subcommand="lab-spec", args=["specs/new-lab.yml"]),
            ),
            reply("", call("write_file", "w1", path="specs/new-lab.yml", content=_spec_text(repo_root, "new-lab"))),
            reply("", call("forge", "f1", subcommand="lab-spec", args=["specs/new-lab.yml", "--check-only"])),
            reply("Spec written."),
        )
    )
    run_id = await _run(app_client, "lab-designer", lab["id"], instructions="theme avengers, small")
    await app_client.app.state.runner.wait(run_id)

    events = (await app_client.get(f"/api/runs/{run_id}/events")).json()
    results = {e["data"]["id"]: e["data"] for e in events if e["type"] == "tool_result"}
    assert results["w0"]["is_error"] and "outside the allowed paths" in results["w0"]["content"]
    assert results["f0"]["is_error"] and "--check-only" in results["f0"]["content"]
    assert not results["f1"]["is_error"], results["f1"]["content"]
    assert (
        "DC + workstation, WinRM vulns" in events[0]["data"]["task"] and "theme avengers" in events[0]["data"]["task"]
    )
    assert not (repo_root / "specs" / "other-lab.yml").exists()
    assert not (repo_root / "generated" / "new-lab" / "lab-manifest.json").exists()  # check-only never writes

    detail = await _lab(app_client, lab["id"])
    assert detail["state"] == "designed" and detail["spec_path"] == "specs/new-lab.yml" and detail["cloud"] == "azure"
    assert "check-only PASS" in detail["transitions"][-1]["reason"]
    # and the normal deterministic path continues from here
    assert (await app_client.post(f"/api/labs/{lab['id']}/compile")).json()["lab"]["state"] == "ready"


async def test_designer_that_writes_nothing_leaves_draft(app_client, llms):
    lab = (await app_client.post("/api/labs", json={"name": "empty-lab"})).json()
    llms.items.append(ScriptedLLM(reply("I designed a great lab (but wrote nothing).")))
    run_id = await _run(app_client, "lab-designer", lab["id"])
    await app_client.app.state.runner.wait(run_id)
    detail = await _lab(app_client, lab["id"])
    assert detail["state"] == "draft" and "no valid spec" in detail["transitions"][-1]["reason"]


async def test_redesign_invalidates_approval(app_client, llms, repo_root):
    lab = await seed_lab(app_client.app, LAB, "approved")
    llms.items.append(
        ScriptedLLM(
            reply(
                "",
                call(
                    "edit_file", "e1", path=SPEC, old_string="budget_alert_usd: 30", new_string="budget_alert_usd: 25"
                ),
            ),
            reply("tightened budget"),
        )
    )
    run_id = await _run(app_client, "lab-designer", lab.id)
    await app_client.app.state.runner.wait(run_id)
    detail = await _lab(app_client, lab.id)
    states = [t["to_state"] for t in detail["transitions"]]
    assert states[-2:] == ["designing", "designed"] and detail["state"] == "designed"
    assert "budget_alert_usd: 25" in (repo_root / SPEC).read_text()


# --------------------------------------------------------------------------- catalog-author


async def test_catalog_author_runs_without_a_lab(app_client, llms):
    llms.items.append(ScriptedLLM())  # the runner builds the tenant's LLM before the precondition check
    assert (await app_client.post("/api/runs", json={"agent": "catalog-author"})).status_code == 422  # needs a request
    llms.items.append(
        ScriptedLLM(
            reply(
                "",
                call("catalog_check", "c1", action="validate_file", path="catalog/vulnerabilities/asreproast.yml"),
                call("write_file", "w1", path="specs/sneaky.yml", content="x"),
            ),
            reply("asreproast entry is valid"),
        )
    )
    run_id = await _run(app_client, "catalog-author", instructions="check the AS-REP roasting entry")
    await app_client.app.state.runner.wait(run_id)
    run = (await app_client.get(f"/api/runs/{run_id}")).json()
    assert run["status"] == "completed" and run["lab_id"] is None
    results = {
        e["data"]["id"]: e["data"]
        for e in (await app_client.get(f"/api/runs/{run_id}/events")).json()
        if e["type"] == "tool_result"
    }
    assert results["c1"]["content"].rstrip().endswith("OK")
    assert results["w1"]["is_error"]  # catalog-author can't write specs/


async def test_registry_exposes_all_agents(app_client):
    names = [a["name"] for a in (await app_client.get("/api/agents")).json()]
    assert names == [
        "lab-designer",
        "deploy-operator",
        "purple-validator",
        "deploy-operator-teardown",
        "catalog-author",
    ]


def test_designer_task_points_at_schema_and_known_good_examples(repo_root):
    from agents.lab_designer import LabDesignerAgent

    (repo_root / "specs" / "aaa-broken.yml").write_text("lab: {name: aaa-broken}\n")  # a half-written user spec
    agent = LabDesignerAgent(None, repo_root=repo_root)  # type: ignore[arg-type]
    task = agent.task("new-lab", "small AD", existing=False)
    assert "specs/schema/lab-spec.schema.json" in task
    assert "`specs/winrm-validate-lab.yml`" in task and "aaa-broken" not in task
    assert "winrm-validate-lab.yml" not in agent.task("winrm-validate-lab", "x", existing=True).split("shape")[1][:120]
