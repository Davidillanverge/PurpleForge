"""Token accounting: per run (live), per lab (with per-agent breakdown) and tenant-wide."""

from __future__ import annotations

import uuid

import pytest
from _appkit import ALICE, seed_lab
from _fakes import ScriptedLLM, call, reply

from db import repository as repo
from db.session import transaction
from db.states import LabState, RunState


async def _run_with_tokens(app, tenant, *, lab_id, agent, tin, tout):
    async with transaction(app.state.sessionmaker) as s:
        run = await repo.create_run(s, tenant, agent=agent, task="t", lab_id=lab_id)
        run.input_tokens, run.output_tokens, run.status = tin, tout, RunState.COMPLETED
    return run


async def test_usage_aggregates_by_lab_agent_and_tenant(client):
    app = client.app
    a = await seed_lab(app, "lab-a", LabState.DEPLOYED, spec="specs/winrm-validate-lab.yml")
    b = await seed_lab(app, "lab-b", LabState.DESIGNED, spec="specs/bare-lab.yml")
    await _run_with_tokens(app, "default", lab_id=a.id, agent="lab-designer", tin=1000, tout=200)
    await _run_with_tokens(app, "default", lab_id=a.id, agent="purple-validator", tin=5000, tout=800)
    await _run_with_tokens(app, "default", lab_id=b.id, agent="lab-designer", tin=300, tout=50)
    await _run_with_tokens(app, "default", lab_id=None, agent="catalog-author", tin=700, tout=100)
    await _run_with_tokens(app, "other-tenant", lab_id=None, agent="catalog-author", tin=9_999, tout=9_999)

    report = (await client.get("/api/usage")).json()
    assert report["total"] == {"input_tokens": 7000, "output_tokens": 1150, "total_tokens": 8150, "runs": 4}
    assert report["by_lab"]["lab-a"]["total_tokens"] == 7000 and report["by_lab"]["lab-b"]["runs"] == 1
    assert report["without_lab"]["total_tokens"] == 800  # catalog-author
    assert report["by_agent"]["lab-designer"]["total_tokens"] == 1550

    detail = (await client.get(f"/api/labs/{a.id}")).json()
    assert detail["usage"] == {"input_tokens": 6000, "output_tokens": 1000, "total_tokens": 7000, "runs": 2}
    assert detail["usage_by_agent"]["purple-validator"]["total_tokens"] == 5800
    listed = {lab["name"]: lab["usage"]["total_tokens"] for lab in (await client.get("/api/labs")).json()}
    assert listed == {"lab-a": 7000, "lab-b": 350}


async def test_deleted_lab_tokens_still_count(client):
    app = client.app
    lab = (await client.post("/api/labs", json={"name": "gone-lab"})).json()
    await _run_with_tokens(app, "default", lab_id=uuid.UUID(lab["id"]), agent="lab-designer", tin=40, tout=2)
    assert (await client.delete(f"/api/labs/{lab['id']}")).status_code == 204
    report = (await client.get("/api/usage")).json()
    assert report["total"]["total_tokens"] == 42 and report["without_lab"]["total_tokens"] == 42


async def test_run_tokens_update_live_and_show_in_the_ui(client, llms):
    llms.items.append(ScriptedLLM(reply("", call("gated", action="deploy"), tokens=100), reply("done", tokens=7)))
    run_id = (await client.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]

    async def tokens_now():
        return (await client.get(f"/api/runs/{run_id}")).json()["input_tokens"]

    # while it waits for approval, the first turn's tokens are already on the run row
    import asyncio

    for _ in range(200):
        if await tokens_now() == 100:
            break
        await asyncio.sleep(0.01)
    assert await tokens_now() == 100
    approval = (await client.get("/api/approvals")).json()[0]
    await client.post(f"/api/approvals/{approval['id']}/decision", json={"approved": True})
    await client.app.state.runner.wait(uuid.UUID(run_id))
    run = (await client.get(f"/api/runs/{run_id}")).json()
    assert (run["input_tokens"], run["output_tokens"]) == (107, 107)

    page = (await client.get(f"/runs/{run_id}", headers={**ALICE})).text
    assert "Σ 214 tok" in page
    nav = (await client.get("/ui/partials/nav-tokens")).text
    assert "Σ 214 tok" in nav


@pytest.mark.parametrize(
    ("n", "shown"), [(0, "0"), (999, "999"), (1234, "1.2k"), (45_678, "46k"), (2_345_678, "2.35M")]
)
def test_token_formatting(n, shown):
    from ui.templating import tok

    assert tok(n) == shown
