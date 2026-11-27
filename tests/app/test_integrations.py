"""Deploy-time integrations configured from the UI (api.integrations): storage (secrets
encrypted, never echoed), the env overlay every deploy path gets (UI > .env), the UI
page/forms and the connection checks."""

from __future__ import annotations

import json
import os
import stat

import httpx
import pytest
from _appkit import seed_lab
from test_forge_jobs import LAB, _finish, _generated
from test_ui import hx, login

from agents.toolsets import build_toolset
from api import integrations
from db import repository as repo
from db.crypto import SecretCipher
from db.session import transaction
from db.states import LabState

KEY = "s" * 40
CIPHER = SecretCipher(KEY)
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@pytest.fixture
async def ui(client):
    c = await login(client.app)
    yield c
    await c.aclose()


async def _save(app, name, **kw):
    async with transaction(app.state.sessionmaker) as s:
        return await integrations.save(
            s,
            "default",
            name,
            enabled=kw.pop("enabled", True),
            values=kw.pop("values", {}),
            secrets=kw.pop("secrets", {}),
            clear_secrets=kw.pop("clear", ()),
            cipher=CIPHER,
        )


async def _overlay(app):
    return await integrations.load_tenant_env(app.state.sessionmaker, "default", CIPHER)


# --------------------------------------------------------------------------- storage + overlay


async def test_secrets_are_encrypted_kept_on_empty_and_clearable(client):
    app = client.app
    await _save(
        app,
        "aws",
        values={"AWS_REGION": "eu-west-1"},
        secrets={"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": SECRET},
    )
    async with transaction(app.state.sessionmaker) as s:
        cfg = await repo.get_integration_config(s, "default", "aws")
    assert cfg.values == {"AWS_REGION": "eu-west-1"}
    assert SECRET not in json.dumps(cfg.secrets_encrypted)  # only Fernet tokens at rest

    # a re-save with empty secrets keeps them; values are replaced as a whole
    await _save(app, "aws", values={"AWS_REGION": "us-east-1"}, secrets={"AWS_SECRET_ACCESS_KEY": ""})
    env = await _overlay(app)
    assert env["AWS_SECRET_ACCESS_KEY"] == SECRET and env["AWS_REGION"] == "us-east-1"
    assert env["AWS_PROFILE"] is None  # explicit keys: the profile gotcha is neutralised
    assert env["AWS_DEFAULT_REGION"] == "us-east-1"

    await _save(app, "aws", values={}, clear=["AWS_SECRET_ACCESS_KEY"])
    assert "AWS_SECRET_ACCESS_KEY" not in await _overlay(app)


async def test_disabled_integration_contributes_nothing_and_apply_unsets(client):
    await _save(client.app, "elastic", values={"PF_FLEET_URL": "https://fleet:8220", "PF_FLEET_INSECURE": "true"})
    overlay = await _overlay(client.app)
    assert overlay["PF_FLEET_URL"] == "https://fleet:8220" and overlay["PF_FLEET_INSECURE"] == "true"
    env = integrations.apply({"PF_FLEET_URL": "from-dotenv", "AWS_PROFILE": "x", "KEEP": "1"}, overlay)
    assert env["PF_FLEET_URL"] == "https://fleet:8220" and env["KEEP"] == "1"
    assert integrations.apply({"AWS_PROFILE": "x"}, {"AWS_PROFILE": None}) == {}

    await _save(client.app, "elastic", enabled=False, values={"PF_FLEET_URL": "https://fleet:8220"})
    assert await _overlay(client.app) == {}


async def test_mde_script_is_materialized_privately(client):
    script = '@echo off\nreg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection" /v OnboardingInfo\n'
    await _save(client.app, "mde", secrets={"MDE_WIN_ONBOARDING_SCRIPT": script})
    overlay = await _overlay(client.app)
    assert "MDE_WIN_ONBOARDING_SCRIPT" not in overlay  # the content never goes into the env
    path = overlay["MDE_WIN_ONBOARDING_PATH"]
    assert open(path, encoding="utf-8").read() == script
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    assert (await integrations.check_mde(overlay)).ok


@pytest.mark.parametrize(
    ("name", "values", "secrets", "error"),
    [
        ("nope", {}, {}, "unknown integration"),
        ("aws", {"PF_FLEET_URL": "x"}, {}, "no es un campo"),
        ("aws", {"AWS_REGION": "eu-west-1\nrm -rf /"}, {}, "saltos de línea"),
        ("aws", {"AWS_SECRET_ACCESS_KEY": "x"}, {}, "es un secreto"),
        ("aws", {}, {"AWS_REGION": "x"}, "no es un secreto"),
    ],
)
async def test_save_rejects_bad_input(client, name, values, secrets, error):
    with pytest.raises(integrations.IntegrationInputError, match=error):
        await _save(client.app, name, values=values, secrets=secrets)


async def test_save_secret_without_cipher_is_refused(client):
    async with transaction(client.app.state.sessionmaker) as s:
        with pytest.raises(integrations.IntegrationInputError, match="PF_SECRET_KEY"):
            await integrations.save(
                s, "default", "caldera", enabled=True, values={}, secrets={"PF_CALDERA_API_KEY": "k"}, cipher=None
            )


# --------------------------------------------------------------------------- deploy paths get the overlay


async def test_ui_forge_deploy_child_gets_the_integrations(client, tmp_path, monkeypatch):
    """The no-AI deploy button: forge's env = .env + the tenant's integrations on top."""
    log = tmp_path / "env.log"
    script = tmp_path / "fake-python"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$3 key=$AWS_ACCESS_KEY_ID secret=$AWS_SECRET_ACCESS_KEY profile=${{AWS_PROFILE-unset}} '
        f'fleet=$PF_FLEET_URL" >> "{log}"\n'
        "exit 0\n"
    )
    script.chmod(0o755)
    jobs = client.app.state.forge_jobs
    jobs.python, jobs.flush_seconds = str(script), 0.05
    monkeypatch.setenv("AWS_PROFILE", "stale-profile")  # from .env
    monkeypatch.setenv("PF_FLEET_URL", "https://from-dotenv:8220")
    await _save(client.app, "aws", secrets={"AWS_ACCESS_KEY_ID": "AKIAUI", "AWS_SECRET_ACCESS_KEY": SECRET})

    _generated(client.app.state.forge_jobs.repo_root, "lab-manifest.json", "deploy.sh")
    lab = await seed_lab(client.app, LAB, LabState.APPROVED)
    dep = (await client.post(f"/api/labs/{lab.id}/forge/deploy")).json()
    run, _ = await _finish(client, jobs, dep["id"])
    assert run["status"] == "completed", run
    lines = log.read_text().splitlines()
    assert lines == [
        f"generate key=AKIAUI secret={SECRET} profile=unset fleet=https://from-dotenv:8220",
        f"deploy key=AKIAUI secret={SECRET} profile=unset fleet=https://from-dotenv:8220",
    ]


def test_deploy_toolset_and_mcp_child_use_the_overlay(repo_root, monkeypatch):
    environ = integrations.apply(os.environ, {"PROXMOX_VE_API_TOKEN": "u@pve!t=1"})
    tools = build_toolset("deploy-operator", repo_root, spec_path="specs/winrm-validate-lab.yml", environ=environ)
    by_name = {t.name: t for t in tools}
    assert by_name["forge"].env["PROXMOX_VE_API_TOKEN"] == "u@pve!t=1"
    assert by_name["bash"].env["PROXMOX_VE_API_TOKEN"] == "u@pve!t=1"

    # what api.cli_brain hands an MCP tools child: JSON in one var, popped on read
    monkeypatch.setenv(integrations.OVERLAY_ENV, json.dumps({"A": "1", "AWS_PROFILE": None}))
    assert integrations.pop_overlay_from_environ() == {"A": "1", "AWS_PROFILE": None}
    assert integrations.OVERLAY_ENV not in os.environ


async def test_runner_loads_the_overlay_only_for_deploy_agents(client):
    from api.registry import DEPLOYER, VALIDATOR

    assert DEPLOYER.deploy_env and not VALIDATOR.deploy_env


# --------------------------------------------------------------------------- JSON API + UI


async def test_api_never_returns_secrets(client):
    r = await client.put(
        "/api/integrations/proxmox",
        json={
            "values": {"PROXMOX_VE_ENDPOINT": "https://pve:8006/", "PROXMOX_VE_INSECURE": "true"},
            "secrets": {"PROXMOX_VE_API_TOKEN": "root@pam!pf=SECRET-UUID"},
        },
    )
    assert r.status_code == 200, r.text
    assert "SECRET-UUID" not in r.text
    fields = {f["env"]: f for f in r.json()["fields"]}
    assert fields["PROXMOX_VE_API_TOKEN"]["source"] == "ui" and "value" not in fields["PROXMOX_VE_API_TOKEN"]
    assert fields["PROXMOX_VE_ENDPOINT"]["value"] == "https://pve:8006/"
    listed = (await client.get("/api/integrations")).text
    assert "SECRET-UUID" not in listed and '"name":"caldera"' in listed.replace(" ", "")
    bad = await client.put("/api/integrations/proxmox", json={"values": {"NOPE": "x"}})
    assert bad.status_code == 422
    assert (await client.delete("/api/integrations/proxmox")).status_code == 204
    assert (await client.delete("/api/integrations/proxmox")).status_code == 404


async def test_ui_page_save_upload_and_delete(ui, monkeypatch):
    monkeypatch.setenv("PF_CALDERA_SERVER", "http://10.11.0.2:8888")
    page = (await ui.get("/settings/integrations")).text
    for label in ("AWS", "Azure", "Proxmox VE", "Elastic (Fleet)", "Microsoft Defender for Endpoint", "MITRE Caldera"):
        assert label in page
    assert 'href="/settings/integrations"' in page
    assert "http://10.11.0.2:8888" in page  # .env value shown as the placeholder/source

    r = await ui.post(
        "/ui/integrations/azure",
        data={
            "v:ARM_TENANT_ID": "t-1",
            "v:ARM_SUBSCRIPTION_ID": "sub-1",
            "v:ARM_CLIENT_ID": "app-1",
            "s:ARM_CLIENT_SECRET": "AZ-SECRET-VALUE",
            "enabled": "yes",
        },
        headers=hx(ui),
    )
    assert r.headers["HX-Redirect"].startswith("/settings/integrations")
    page = (await ui.get("/settings/integrations")).text
    assert "AZ-SECRET-VALUE" not in page and "✓ cifrado" in page and 'value="sub-1"' in page

    script = b'@echo off\nreg add ... /v OnboardingInfo /t REG_SZ /d "{}"\n'
    r = await ui.post(
        "/ui/integrations/mde",
        data={"enabled": "yes"},
        files={"s:MDE_WIN_ONBOARDING_SCRIPT": ("WindowsDefenderATPOnboardingScript.cmd", script)},
        headers=hx(ui),
    )
    assert "HX-Redirect" in r.headers, r.text
    r = await ui.post("/ui/integrations/mde/test", headers=hx(ui))
    assert "✓" in r.text and "onboarding válido" in r.text

    r = await ui.post("/ui/integrations/aws", data={"v:AWS_REGION": "eu\nwest"}, headers=hx(ui))
    assert "saltos de línea" in r.text and r.headers.get("HX-Retarget") == "#flash"

    await ui.post("/ui/integrations/azure/delete", headers=hx(ui))
    assert 'value="sub-1"' not in (await ui.get("/settings/integrations")).text


# --------------------------------------------------------------------------- connection checks


def _mock_http(monkeypatch, handler):
    async def fake(method, url, *, verify=True, **kw):
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as c:
            return await c.request(method, url, **kw)

    monkeypatch.setattr(integrations, "_http", fake)


async def test_check_proxmox_sends_the_token_and_reads_the_version(monkeypatch):
    seen = {}

    def handler(req):
        seen["auth"] = req.headers["Authorization"]
        return httpx.Response(200, json={"data": {"version": "9.1.2"}})

    _mock_http(monkeypatch, handler)
    res = await integrations.check_proxmox(
        {"PROXMOX_VE_ENDPOINT": "https://pve:8006/", "PROXMOX_VE_API_TOKEN": "u!t=1"}
    )
    assert res.ok and "9.1.2" in res.message and seen["auth"] == "PVEAPIToken=u!t=1"
    _mock_http(monkeypatch, lambda req: httpx.Response(401))
    res = await integrations.check_proxmox({"PROXMOX_VE_ENDPOINT": "https://pve:8006", "PROXMOX_VE_API_TOKEN": "x"})
    assert not res.ok and "401" in res.message
    assert "falta" in (await integrations.check_proxmox({})).message


async def test_check_elastic_and_caldera(monkeypatch):
    _mock_http(monkeypatch, lambda req: httpx.Response(200, json={"name": "fleet-server", "status": "HEALTHY"}))
    env = {"PF_FLEET_URL": "https://fleet:8220", "PF_FLEET_ENROLLMENT_TOKEN": "t"}
    assert (await integrations.check_elastic(env)).ok

    def caldera(req):
        assert req.url.path == "/api/v2/health" and req.headers["KEY"] == "k"
        return httpx.Response(200, json={"version": "5.3.0"})

    _mock_http(monkeypatch, caldera)
    res = await integrations.check_caldera({"PF_CALDERA_SERVER": "http://c:8888", "PF_CALDERA_API_KEY": "k"})
    assert res.ok and "5.3.0" in res.message


async def test_general_overrides_have_nothing_to_test(client):
    async with transaction(client.app.state.sessionmaker) as s:
        res = await integrations.run_test(s, "default", "general", CIPHER)
    assert res.ok


def test_bool_checkbox_reflects_dotenv_until_saved():
    rows = {r.integration.name: r for r in integrations.status([], {"PF_FLEET_INSECURE": "true"})}
    insecure = next(f for f in rows["elastic"].fields if f.field.env == "PF_FLEET_INSECURE")
    assert insecure.value == "true" and insecure.source == "env"
