"""No-AI lab operations from the UI/API (validate, deploy, stop, start, teardown) and the
operator's lab report page.

forge itself is replaced by a tiny fake interpreter (``python -m forge <sub> ...`` →
prints and exits with the code the test asks for), so nothing touches a cloud."""

from __future__ import annotations

import json
import stat

import pytest
from _appkit import seed_lab
from test_ui import hx, login

from api.forge_jobs import ACTIONS, ForgeJobs
from db import repository as repo
from db.session import transaction
from db.states import LabState, RunState

LAB = "winrm-validate-lab"


@pytest.fixture
def fake_forge(tmp_path, monkeypatch):
    """A stand-in for sys.executable: `<it> -m forge <sub> args...`. Exit code per
    subcommand from $PF_FAKE_FORGE_EXIT (e.g. "stop=3"); every call is logged."""
    log = tmp_path / "forge-calls.log"
    script = tmp_path / "fake-python"
    script.write_text(
        "#!/bin/sh\n"
        "shift 2\n"  # drop "-m forge"
        f'echo "$*" >> "{log}"\n'
        'printf "\\033[1;35m== %s\\033[0m\\n" "$1"\n'  # ANSI colour like the real scripts
        'echo "progress line for $1"\n'
        # like the real `forge validate --run`: write the confirmed report the outcome reads
        '[ "$1" = validate ] && [ -n "$PF_FAKE_VALIDATION" ] && '
        'printf "%s" "$PF_FAKE_VALIDATION" > generated/winrm-validate-lab/validation-report.json\n'
        'for kv in $PF_FAKE_FORGE_EXIT; do [ "${kv%%=*}" = "$1" ] && exit "${kv#*=}"; done\n'
        "exit 0\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.delenv("PF_FAKE_FORGE_EXIT", raising=False)
    monkeypatch.delenv("PF_FAKE_VALIDATION", raising=False)
    return script, log


def _report(*verdicts):
    """A validation-report.json body: one vuln per (applied, exploitable) pair."""
    vulns = [{"id": f"v{i}", "applied": a, "exploitable": e} for i, (a, e) in enumerate(verdicts)]
    return json.dumps({"lab": LAB, "vulns": vulns})


@pytest.fixture
def jobs(client, fake_forge):
    forge_jobs: ForgeJobs = client.app.state.forge_jobs
    forge_jobs.python = str(fake_forge[0])
    forge_jobs.flush_seconds = 0.05
    return forge_jobs


def _generated(repo_root, *names):
    lab_dir = repo_root / "generated" / LAB
    lab_dir.mkdir(parents=True, exist_ok=True)
    for n in names:
        (lab_dir / n).write_text("#!/bin/sh\n")
    return lab_dir


async def _to(app, lab, *states):
    async with transaction(app.state.sessionmaker) as s:
        row = await repo.get_lab(s, "default", lab.id, for_update=True)
        for st in states:
            await repo.transition_lab(s, "default", row, st, actor="system")


async def _finish(client, jobs, run_id):
    await jobs.wait(__import__("uuid").UUID(run_id))
    run = (await client.get(f"/api/runs/{run_id}")).json()
    lab = (await client.get(f"/api/labs/{run['lab_id']}")).json()
    return run, lab


async def _events(client, run_id):
    return (await client.get(f"/api/runs/{run_id}/events")).json()


async def test_validate_moves_deployed_to_validated_and_streams_output(
    client, jobs, repo_root, fake_forge, monkeypatch
):
    lab_dir = _generated(repo_root)
    (lab_dir / "lab-manifest.json").write_text(json.dumps({"vulnerabilities_planned": [{"id": "v0"}] * 2}))
    monkeypatch.setenv("PF_FAKE_VALIDATION", _report(("YES", "YES"), ("YES", "YES")))
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    r = await client.post(f"/api/labs/{lab.id}/forge/validate")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["source"] == "forge" and body["agent"] == "forge-validate"
    run, lab_out = await _finish(client, jobs, body["id"])
    assert run["status"] == "completed" and run["input_tokens"] == 0
    assert lab_out["state"] == "validated"
    assert fake_forge[1].read_text().split("\n")[0] == f"validate specs/{LAB}.yml --run"
    events = await _events(client, body["id"])
    types = [e["type"] for e in events]
    assert "tool_output" in types and "approval_resolved" not in types  # read-only: no infra approval
    out = "".join(e["data"]["content"] for e in events if e["type"] == "tool_output")
    assert "progress line for validate" in out and "\x1b[" not in out  # live output, ANSI stripped


async def test_stop_then_start_records_the_click_as_the_approval(client, jobs, repo_root):
    _generated(repo_root, "lab-manifest.json", "stop.sh", "start.sh")
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    await _to(client.app, lab, LabState.VALIDATING, LabState.VALIDATED)

    stop = (await client.post(f"/api/labs/{lab.id}/forge/stop")).json()
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] in ("stopping", "stopped")
    run, lab_out = await _finish(client, jobs, stop["id"])
    assert run["status"] == "completed" and lab_out["state"] == "stopped"
    resolved = [e for e in await _events(client, stop["id"]) if e["type"] == "approval_resolved"]
    assert resolved and resolved[0]["data"]["approved"] and resolved[0]["data"]["by"] == "user:alice"

    start = (await client.post(f"/api/labs/{lab.id}/forge/start")).json()
    run, lab_out = await _finish(client, jobs, start["id"])
    assert run["status"] == "completed" and lab_out["state"] == "deployed"  # validation isn't inherited


async def test_failed_stop_leaves_the_lab_deployed(client, jobs, repo_root, monkeypatch):
    _generated(repo_root, "stop.sh")
    monkeypatch.setenv("PF_FAKE_FORGE_EXIT", "stop=3")
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    stop = (await client.post(f"/api/labs/{lab.id}/forge/stop")).json()
    run, lab_out = await _finish(client, jobs, stop["id"])
    assert run["status"] == "failed" and "exited 3" in run["error"]
    assert lab_out["state"] == "deployed"


async def test_deploy_generates_first_and_stops_on_a_failed_generate(client, jobs, monkeypatch, fake_forge):
    monkeypatch.setenv("PF_FAKE_FORGE_EXIT", "generate=1")
    lab = await seed_lab(client.app, LAB, LabState.APPROVED)
    dep = (await client.post(f"/api/labs/{lab.id}/forge/deploy")).json()
    run, lab_out = await _finish(client, jobs, dep["id"])
    assert run["status"] == "failed"
    assert lab_out["state"] == "ready"  # never touched infra → re-approve, not FAILED
    assert [ln.split()[0] for ln in fake_forge[1].read_text().splitlines()] == ["generate"]


async def test_deploy_ok(client, jobs, fake_forge):
    lab = await seed_lab(client.app, LAB, LabState.APPROVED)
    dep = (await client.post(f"/api/labs/{lab.id}/forge/deploy")).json()
    run, lab_out = await _finish(client, jobs, dep["id"])
    assert run["status"] == "completed" and lab_out["state"] == "deployed"
    assert [ln.split()[0] for ln in fake_forge[1].read_text().splitlines()] == ["generate", "deploy"]


async def test_teardown_needs_the_lab_name_in_the_ui(client, jobs, fake_forge):
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    await _to(client.app, lab, LabState.STOPPED)
    ui = await login(client.app)
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "/forge/teardown" in page and "/forge/start" in page and "/forge/stop" not in page
    wrong = await ui.post(f"/ui/labs/{lab.id}/forge/teardown", data={"confirm_name": "nope"}, headers=hx(ui))
    assert "escribe el nombre del lab" in wrong.text
    ok = await ui.post(f"/ui/labs/{lab.id}/forge/teardown", data={"confirm_name": LAB}, headers=hx(ui))
    run_id = ok.headers["HX-Redirect"].rsplit("/", 1)[1]
    await ui.aclose()
    run, lab_out = await _finish(client, jobs, run_id)
    assert run["status"] == "completed" and lab_out["state"] == "destroyed"
    assert fake_forge[1].read_text().strip() == f"teardown specs/{LAB}.yml --force"


async def test_refusals(client, jobs, repo_root):
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    r = await client.post(f"/api/labs/{lab.id}/forge/start")  # not stopped
    assert r.status_code == 409 and "needs: stopped" in r.json()["detail"]
    r = await client.post(f"/api/labs/{lab.id}/forge/stop")  # stop.sh not generated
    assert r.status_code == 409 and "generate the lab first" in r.json()["detail"]
    assert (await client.post(f"/api/labs/{lab.id}/forge/nuke")).status_code == 409
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] == "deployed"  # unchanged


async def test_orphaned_forge_run_rolls_the_lab_back(client, jobs):
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    async with transaction(client.app.state.sessionmaker) as s:
        run = await repo.create_run(s, "default", agent="forge-stop", task="t", lab_id=lab.id, source="forge")
        run.status = RunState.RUNNING
        row = await repo.get_lab(s, "default", lab.id, for_update=True)
        await repo.transition_lab(s, "default", row, LabState.STOPPING, actor="system")
    counts = await jobs.recover_orphans()
    assert any(counts.values())
    assert (await client.get(f"/api/labs/{lab.id}")).json()["state"] == "deployed"
    assert (await client.get(f"/api/runs/{run.id}")).json()["status"] == "failed"


def test_every_running_state_has_an_orphan_target():
    for a in ACTIONS.values():
        assert a.running_state not in a.allowed_states
        assert a.orphan_state in (LabState.FAILED, *a.allowed_states)


# --------------------------------------------------------------------------- report page


async def test_report_page_renders_forge_reports_safely(client, repo_root):
    lab_dir = _generated(repo_root)
    (lab_dir / "lab-report.md").write_text(
        "# Lab report — x\n\n## Machines\n\n| Name | IP |\n|---|---|\n| dc01 | `10.0.1.10` |\n\n"
        "## Population\n\n<script>alert(1)</script>\n\n[users](#appendix-a)\n\n## Appendix A\n\nalice\n"
    )
    (lab_dir / "terraform-outputs.json").write_text(
        json.dumps(
            {
                "bastion_public_ip": {"value": "203.0.113.7", "sensitive": False},
                "bastion_ssh_private_key_path": {"value": "./ssh_keys/bastion.pem", "sensitive": False},
                "secret": {"value": "do-not-show", "sensitive": True},
            }
        )
    )
    (lab_dir / "connectivity.json").write_text(
        json.dumps(
            {
                "checked_at": 1795725608,
                "wireguard_handshake": True,
                "nodes": {
                    "dc01": {
                        "role": "dc",
                        "ip": "10.0.1.10",
                        "probes": [{"proto": "winrm-https", "port": 5986, "required": True, "reachable": True}],
                    }
                },
            }
        )
    )
    (lab_dir / "terraform" / "aws" / "ssh_keys").mkdir(parents=True)
    (lab_dir / "terraform" / "aws" / "ssh_keys" / "pf-lab.conf").write_text("[Interface]\n")
    (lab_dir / "validation-report.md").write_text("# Validation\n\n## Summary\n\nok\n")
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)

    ui = await login(client.app)
    assert f'href="/labs/{lab.id}/report"' in (await ui.get(f"/labs/{lab.id}")).text
    r = await ui.get(f"/labs/{lab.id}/report")
    await ui.aclose()
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    page = r.text
    assert "<table>" in page and "<code>10.0.1.10</code>" in page  # markdown tables rendered
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page  # raw HTML escaped
    assert 'id="appendix-a"' in page and 'href="#appendix-a"' in page  # in-report anchors work
    assert 'id="val-summary"' in page  # second doc's anchors don't collide
    assert "203.0.113.7" in page and "do-not-show" not in page
    assert "sudo wg-quick up generated/winrm-validate-lab/terraform/aws/ssh_keys/pf-lab.conf" in page
    assert "ssh_keys/bastion.pem" in page and "winrm-https/5986" in page


async def test_report_page_without_a_generated_lab(client):
    lab = await seed_lab(client.app, LAB, LabState.DESIGNED)
    ui = await login(client.app)
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "/report" not in page
    r = await ui.get(f"/labs/{lab.id}/report")
    await ui.aclose()
    assert r.status_code == 200 and "generar scripts" in r.text


async def test_a_destroyed_lab_can_be_redeployed_through_the_gate_again(client, jobs):
    """destroyed → (↻ preparar redespliegue = compile) → ready → fresh human approval → deploy."""
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    await _to(client.app, lab, LabState.DESTROYING, LabState.DESTROYED)
    ui = await login(client.app)
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "preparar redespliegue" in page and f'hx-post="/ui/labs/{lab.id}/compile"' in page
    await ui.aclose()
    # no shortcut: deploying straight from destroyed is refused
    assert (await client.post(f"/api/labs/{lab.id}/forge/deploy")).status_code == 409

    body = (await client.post(f"/api/labs/{lab.id}/compile")).json()
    assert body["ok"] and body["lab"]["state"] == "ready", body["steps"][-1]["output"][-500:]
    r = await client.post(f"/api/labs/{lab.id}/transitions", json={"to": "approved", "reason": "redeploy"})
    assert r.status_code == 200
    dep = (await client.post(f"/api/labs/{lab.id}/forge/deploy")).json()
    run, lab_out = await _finish(client, jobs, dep["id"])
    assert run["status"] == "completed" and lab_out["state"] == "deployed"


async def test_validated_needs_every_vuln_confirmed(client, jobs, repo_root, monkeypatch):
    """forge validate exiting 0 isn't enough: one unconfirmed vuln keeps the lab deployed,
    with the summary on the lab card."""
    lab_dir = _generated(repo_root)
    (lab_dir / "lab-manifest.json").write_text(json.dumps({"vulnerabilities_planned": [{"id": "v0"}] * 3}))
    monkeypatch.setenv("PF_FAKE_VALIDATION", _report(("YES", "YES"), ("YES", "REQUIRES-HUMAN"), ("NO", "NO")))
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    body = (await client.post(f"/api/labs/{lab.id}/forge/validate")).json()
    run, lab_out = await _finish(client, jobs, body["id"])
    assert run["status"] == "completed"  # forge ran fine — the result just isn't a pass
    assert lab_out["state"] == "deployed"
    reason = lab_out["transitions"][-1]["reason"]
    assert "aplicadas 2/3" in reason and "explotables 1/3" in reason
    ui = await login(client.app)
    page = (await ui.get(f"/labs/{lab.id}")).text
    await ui.aclose()
    assert "no confirmó todas las vulns" in page and "última validación" in page
    assert "requieren comprobación manual" in page and "v1" in page and "no confirmadas (NO)" in page


async def test_stale_report_doesnt_validate(client, jobs, repo_root):
    lab_dir = _generated(repo_root)
    (lab_dir / "lab-manifest.json").write_text(json.dumps({"vulnerabilities_planned": [{"id": "v0"}]}))
    (lab_dir / "validation-report.json").write_text(_report(("YES", "YES")))
    import os

    os.utime(lab_dir / "validation-report.json", (1, 1))  # written long before this run
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    body = (await client.post(f"/api/labs/{lab.id}/forge/validate")).json()
    _, lab_out = await _finish(client, jobs, body["id"])
    assert lab_out["state"] == "deployed" and "no validation report" in lab_out["transitions"][-1]["reason"]


async def test_a_lab_without_vulns_validates(client, jobs, repo_root):
    lab_dir = _generated(repo_root)
    (lab_dir / "lab-manifest.json").write_text(json.dumps({"vulnerabilities_planned": []}))
    lab = await seed_lab(client.app, LAB, LabState.DEPLOYED)
    body = (await client.post(f"/api/labs/{lab.id}/forge/validate")).json()
    _, lab_out = await _finish(client, jobs, body["id"])
    assert lab_out["state"] == "validated"
