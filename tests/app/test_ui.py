"""Server-rendered UI: login/session, CSRF, security headers, escaping, and the
main flows driven exactly as htmx would (HX-Request + X-CSRF-Token)."""

from __future__ import annotations

import re
import uuid

import httpx
import pytest
from _appkit import seed_lab, wait_for
from _fakes import ScriptedLLM, call, reply

from db.states import LabState

HX = {"HX-Request": "true"}


async def login(app, token="tok-alice-0123456789abcdefghij") -> httpx.AsyncClient:
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    r = await c.post("/login", data={"token": token, "next": "/"})
    assert r.status_code == 303, r.text
    return c


def hx(c: httpx.AsyncClient) -> dict[str, str]:
    """Headers htmx sends from our pages: HX-Request + the CSRF echo."""
    return {**HX, "X-CSRF-Token": c.cookies.get("pf_csrf")}


@pytest.fixture
async def ui(client):
    c = await login(client.app)
    c.app = client.app
    c.api = client  # bearer-authenticated JSON client, same app
    yield c
    await c.aclose()


# --------------------------------------------------------------------------- session + security


async def test_login_flow_and_cookies(client):
    app = client.app
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    r = await anon.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = await anon.get("/labs/" + str(uuid.uuid4()))
    assert r.headers["location"].startswith("/login?next=/labs/")
    assert 'name="token"' in (await anon.get("/login")).text

    bad = await anon.post("/login", data={"token": "nope"})
    assert bad.status_code == 401 and "token inválido" in bad.text

    ok = await anon.post("/login", data={"token": "tok-alice-0123456789abcdefghij", "next": "//evil.example/x"})
    assert ok.status_code == 303 and ok.headers["location"] == "/"  # no open redirect
    cookies = ok.headers.get_list("set-cookie")
    for name in ("pf_token", "pf_csrf"):
        line = next(c for c in cookies if c.startswith(name + "="))
        assert "HttpOnly" in line and "SameSite=strict" in line
    await anon.aclose()


async def test_htmx_request_without_session_gets_hx_redirect(client):
    anon = httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app), base_url="http://t")
    r = await anon.post("/ui/labs", data={"name": "x-lab"}, headers=HX)
    assert r.headers["HX-Redirect"] == "/login"  # never ?next=/ui/<action>
    r = await anon.get("/ui/partials/labs", headers={**HX, "HX-Current-URL": "http://t/approvals"})
    assert r.headers["HX-Redirect"] == "/login?next=/approvals"
    await anon.aclose()


async def test_csrf_required_for_cookie_sessions(ui):
    # cookie session, no CSRF echo → refused (as a toast for htmx)
    r = await ui.post("/ui/labs", data={"name": "csrf-lab"}, headers=HX)
    assert r.headers["HX-Retarget"] == "#flash" and "CSRF" in r.text
    # same for the JSON API when authenticated by cookie
    r = await ui.post("/api/labs", json={"name": "csrf-lab"})
    assert r.status_code == 403
    assert (await ui.api.get("/api/labs")).json() == []
    # with the echo it goes through
    r = await ui.post("/ui/labs", data={"name": "csrf-lab"}, headers=hx(ui))
    assert r.headers["HX-Redirect"].startswith("/labs/")


async def test_security_headers_and_vendored_assets(ui):
    r = await ui.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert not re.search(r"<script(?![^>]*\bsrc=)", r.text), "inline <script> would violate the CSP"
    assert 'style="' not in r.text
    for path in ("/static/js/htmx-2.0.11.min.js", "/static/js/htmx-ext-sse-2.2.4.min.js", "/static/css/app.css"):
        assert (await ui.get(path)).status_code == 200, path


# --------------------------------------------------------------------------- dashboard + lab


async def test_dashboard_escapes_untrusted_text(ui):
    await ui.post("/ui/labs", data={"name": "xss-lab", "description": "<script>alert(1)</script>"}, headers=hx(ui))
    page = (await ui.get("/")).text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page and "<script>alert(1)" not in page
    assert "xss-lab" in (await ui.get("/ui/partials/labs")).text
    assert "specs/winrm-validate-lab.yml" in page  # spec picker lists specs/


async def test_invalid_lab_name_is_a_toast(ui):
    r = await ui.post("/ui/labs", data={"name": "Bad Name"}, headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash" and "lowercase" in r.text


async def test_compile_and_human_approval_flow(ui):
    r = await ui.post("/ui/labs", data={"name": "winrm-validate-lab"}, headers=hx(ui))
    lab_url = r.headers["HX-Redirect"]
    lab_id = lab_url.rsplit("/", 1)[1]
    page = (await ui.get(lab_url)).text
    assert "designed" in page and "forge lab-spec + guardrail" in page

    r = await ui.post(f"/ui/labs/{lab_id}/compile", headers=hx(ui))
    assert "compilación + guardrail OK" in r.text and "PASS" in r.text
    assert 'id="lab-panel" hx-swap-oob="true"' in r.text and "puerta humana" in r.text
    assert "$0.2/h" in r.text and "vpn-only" in r.text  # manifest summary for the approver

    # approving requires the explicit authorized-use confirmation (#6)
    r = await ui.post(f"/ui/labs/{lab_id}/approve", data={"reason": "TCK-1"}, headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash" and "#6" in r.text
    r = await ui.post(f"/ui/labs/{lab_id}/approve", data={"authorized": "yes", "reason": "TCK-1"}, headers=hx(ui))
    assert "approved" in r.text and "authorized-use confirmed (#6) — TCK-1" in r.text
    lab = (await ui.api.get(f"/api/labs/{lab_id}")).json()
    assert lab["state"] == "approved" and lab["transitions"][-1]["actor"] == "user:alice"


async def test_fsm_violation_shows_toast(ui):
    r = await ui.post("/ui/labs", data={"name": "draft-lab"}, headers=hx(ui))
    lab_id = r.headers["HX-Redirect"].rsplit("/", 1)[1]
    r = await ui.post(f"/ui/labs/{lab_id}/approve", data={"authorized": "yes"}, headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash" and "draft → approved" in r.text


async def test_delete_refused_with_live_infra(ui):
    lab = await seed_lab(ui.app, "live-lab", LabState.DEPLOYED)
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "puede haber infraestructura viva" in page and "/delete" not in page
    r = await ui.post(f"/ui/labs/{lab.id}/delete", headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash" and "destroy it" in r.text


async def test_unknown_lab_renders_error_page(ui):
    r = await ui.get(f"/labs/{uuid.uuid4()}", headers={"Accept": "text/html"})
    assert r.status_code == 404 and "error 404" in r.text


# --------------------------------------------------------------------------- console + approvals


async def _pending(api):
    return (await api.get("/api/approvals")).json()


async def test_console_approval_and_replay(ui, llms):
    llms.items.append(
        ScriptedLLM(
            reply("<b>bold?</b> checking", call("gated", action="deploy")),
            reply("all done"),
        )
    )
    run_id = (await ui.api.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]

    async def has_pending():
        return bool(await _pending(ui.api))

    await wait_for(has_pending)
    page = (await ui.get(f"/runs/{run_id}")).text
    assert "● live" in page and 'sse-connect="/ui/runs/' in page
    assert "APROBACIÓN REQUERIDA" in page and "deploy touches live infra" in page
    assert "&lt;b&gt;bold?&lt;/b&gt;" in page  # agent text is escaped, never HTML

    # versioned poller: unchanged pending set → 204 (DOM untouched, typed comment survives)
    version = re.search(r"/approvals\?v=([0-9a-f]+)", page).group(1)
    r = await ui.get(f"/ui/partials/runs/{run_id}/approvals?v={version}", headers=hx(ui))
    assert r.status_code == 204

    approval_id = (await _pending(ui.api))[0]["id"]
    r = await ui.post(
        f"/ui/approvals/{approval_id}/decision", data={"approved": "true", "comment": "lgtm"}, headers=hx(ui)
    )
    assert "approved" in r.text and "user:alice" in r.text and "lgtm" in r.text
    assert "border-green-600/80 text-green-300" in r.text  # approval green, not the lab-state violet
    await ui.app.state.runner.wait(uuid.UUID(run_id))

    page = (await ui.get(f"/runs/{run_id}")).text
    assert "○ replay" in page and "run completado" in page and "all done" in page and "sse-connect" not in page
    assert "✔ aprobado" in page

    # the HTML SSE stream of a finished run: one fragment per event, OOB header, then `end`
    stream = (await ui.get(f"/ui/runs/{run_id}/console-stream")).text
    assert stream.count("\nid: ") + stream.startswith("id: ") >= 6
    assert 'id="run-header" hx-swap-oob="true"' in stream and stream.rstrip().endswith("event: end\ndata: end")


async def test_global_approvals_page(ui, llms):
    llms.items.append(ScriptedLLM(reply("", call("gated", action="destroy")), reply("ok")))
    run_id = (await ui.api.post("/api/runs", json={"agent": "gated-agent"})).json()["id"]

    async def has_pending():
        return bool(await _pending(ui.api))

    await wait_for(has_pending)
    page = (await ui.get("/approvals")).text
    assert "approvals --pending" in page and "destroy touches live infra" in page
    assert ">1<" in (await ui.get("/ui/partials/nav-approvals")).text.replace(" ", "")

    approval_id = (await _pending(ui.api))[0]["id"]
    r = await ui.post(f"/ui/approvals/{approval_id}/decision", data={"approved": "false"}, headers=hx(ui))
    assert "denied" in r.text
    r = await ui.post(f"/ui/approvals/{approval_id}/decision", data={"approved": "true"}, headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash" and "already denied" in r.text
    await ui.app.state.runner.wait(uuid.UUID(run_id))
    assert "nada pendiente" in (await ui.get("/approvals")).text


async def test_launch_validator_from_lab_page(ui, llms, repo_root):
    d = repo_root / "generated" / "winrm-validate-lab"
    d.mkdir(parents=True)
    (d / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')
    lab = await seed_lab(ui.app, "winrm-validate-lab", LabState.DEPLOYED)
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "lanzar purple-validator" in page

    llms.items.append(ScriptedLLM(reply("validated")))
    r = await ui.post(
        f"/ui/labs/{lab.id}/runs", data={"agent": "purple-validator", "instructions": "solo AS-REP"}, headers=hx(ui)
    )
    run_id = r.headers["HX-Redirect"].rsplit("/", 1)[1]
    await ui.app.state.runner.wait(uuid.UUID(run_id))
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "validated" in page and "agent:purple-validator" in page


# --------------------------------------------------------------------------- providers


async def test_providers_page_never_shows_keys(ui):
    page = (await ui.get("/settings/providers")).text
    assert "desde el entorno" in page and "● en uso" in page  # env providers listed when the tenant has none

    form = {
        "name": "claude",
        "kind": "anthropic",
        "model": "sonnet",
        "priority": "10",
        "api_key": "sk-ant-SECRET",
        "enabled": "yes",
    }
    r = await ui.post("/ui/providers", data=form, headers=hx(ui))
    assert r.headers["HX-Redirect"] == "/settings/providers"
    page = (await ui.get("/settings/providers")).text
    assert "✓ cifrada" in page and "sk-ant-SECRET" not in page

    local = {
        "name": "local",
        "kind": "ollama",
        "model": "qwen3:8b",
        "base_url": "http://127.0.0.1:9",
        "timeout_seconds": "1",
        "enabled": "yes",
    }
    await ui.post("/ui/providers", data=local, headers=hx(ui))
    r = await ui.post("/ui/providers/local/test", headers=hx(ui))
    assert "✗ local" in r.text

    r = await ui.post("/ui/providers", data={**form, "api_key": "", "clear_api_key": "yes"}, headers=hx(ui))
    assert "✓ cifrada" not in (await ui.get("/settings/providers")).text
    r = await ui.post("/ui/providers", data={**form, "name": "Bad Name"}, headers=hx(ui))
    assert r.headers["HX-Retarget"] == "#flash"
    await ui.post("/ui/providers/local/delete", headers=hx(ui))
    assert 'id="test-local"' not in (await ui.get("/settings/providers")).text


async def test_incomplete_manifest_is_flagged_not_rendered_as_values(ui, repo_root):
    lab = await seed_lab(ui.app, "winrm-validate-lab", LabState.DEPLOYED)
    d = repo_root / "generated" / "winrm-validate-lab"
    d.mkdir(parents=True, exist_ok=True)
    (d / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')
    page = (await ui.get(f"/labs/{lab.id}")).text
    assert "no es un manifest completo" in page and "None / None" not in page


async def test_env_providers_are_listed_and_testable(ui, monkeypatch):
    monkeypatch.setenv("PF_LLM_PROVIDERS", "gemini,ollama")
    monkeypatch.setenv("GEMINI_API_KEY", "k-test")
    monkeypatch.setenv("PF_LLM_GEMINI_MODEL", "gemini-3.1-flash-lite")
    monkeypatch.setenv("PF_LLM_OLLAMA_BASE_URL", "http://127.0.0.1:9")
    page = (await ui.get("/settings/providers")).text
    assert "gemini-3.1-flash-lite" in page and "✓ en .env" in page and "k-test" not in page
    r = await ui.post("/ui/providers/env/ollama/test", headers=hx(ui))
    assert "✗ ollama (.env)" in r.text  # unreachable endpoint → a clear error, not a crash
    r = await ui.post("/ui/providers/env/anthropic/test", headers=hx(ui))
    assert "not in PF_LLM_PROVIDERS" in r.text
