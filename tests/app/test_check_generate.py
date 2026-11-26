"""Lab check (forge lab-spec --check-only) and generate (forge generate) — deterministic, no cloud,
no FSM movement, refused while an agent owns the lab."""

from __future__ import annotations

from _appkit import seed_lab

from db.states import LabState


async def test_check_is_read_only(client, repo_root):
    lab = (await client.post("/api/labs", json={"name": "winrm-validate-lab"})).json()
    r = await client.post(f"/api/labs/{lab['id']}/check")
    body = r.json()
    assert r.status_code == 200 and body["ok"], body
    assert body["steps"][0]["command"].startswith("forge lab-spec specs/winrm-validate-lab.yml --check-only")
    assert body["lab"]["state"] == "designed"  # no state change
    assert not (repo_root / "generated").exists()  # nothing written


async def test_check_reports_spec_errors(client):
    lab = (await client.post("/api/labs", json={"name": "bare-lab"})).json()  # not a full spec
    body = (await client.post(f"/api/labs/{lab['id']}/check")).json()
    assert not body["ok"] and "FAIL" in body["steps"][0]["output"]


async def test_generate_renders_scripts_without_moving_the_lab(client, repo_root):
    lab = (await client.post("/api/labs", json={"name": "winrm-validate-lab"})).json()
    body = (await client.post(f"/api/labs/{lab['id']}/generate")).json()
    assert body["ok"], body["steps"][0]["output"][-800:]
    assert body["out_dir"] == "generated/winrm-validate-lab/"
    assert "deploy.sh" in body["files"] and "lab-manifest.json" in body["files"]
    assert any(f.startswith("terraform/") for f in body["files"]) and any(
        f.startswith("ansible/") for f in body["files"]
    )
    assert (repo_root / "generated" / "winrm-validate-lab" / "deploy.sh").is_file()
    assert body["lab"]["state"] == "designed"  # generating is not a guardrail PASS nor an approval
    # deterministic: regenerating yields the same file set
    again = (await client.post(f"/api/labs/{lab['id']}/generate")).json()
    assert again["files"] == body["files"]


async def test_refused_while_an_agent_owns_the_lab(client):
    lab = await seed_lab(client.app, "winrm-validate-lab", LabState.DEPLOYING)
    for action in ("check", "generate"):
        r = await client.post(f"/api/labs/{lab.id}/{action}")
        assert r.status_code == 409 and "agent is working" in r.json()["detail"], action


async def test_draft_without_spec_is_refused(client):
    lab = (await client.post("/api/labs", json={"name": "no-spec-lab"})).json()
    assert (await client.post(f"/api/labs/{lab['id']}/generate")).status_code == 422


async def test_ui_buttons_and_results(client):
    from test_ui import hx, login

    ui = await login(client.app)
    lab = (await client.post("/api/labs", json={"name": "winrm-validate-lab"})).json()
    page = (await ui.get(f"/labs/{lab['id']}")).text
    assert f'hx-post="/ui/labs/{lab["id"]}/check"' in page and f'hx-post="/ui/labs/{lab["id"]}/generate"' in page
    check = await ui.post(f"/ui/labs/{lab['id']}/check", headers=hx(ui))
    assert "check OK" in check.text
    gen = await ui.post(f"/ui/labs/{lab['id']}/generate", headers=hx(ui))
    assert (
        "generado en generated/winrm-validate-lab/" in gen.text and "deploy.sh" in gen.text and "secretos" in gen.text
    )
    await ui.aclose()

    busy = await seed_lab(client.app, "busy-lab", LabState.DEPLOYING, spec="specs/bare-lab.yml")
    ui = await login(client.app)
    assert "/generate" not in (await ui.get(f"/labs/{busy.id}")).text  # buttons hidden while an agent works
    await ui.aclose()
