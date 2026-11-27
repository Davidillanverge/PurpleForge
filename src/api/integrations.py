"""Deploy-time integrations configurable from the UI (AWS, Azure, Proxmox, Elastic,
Cloudflare, Defender for Endpoint, Caldera...).

Each field IS the env var the generated scripts already read (deploy.sh & co., see the
runbooks) — nothing in forge changes: the service only decides what env the deploy
child gets. Precedence, per field: value saved in the UI (tenant DB) > ``.env`` /
process environment > unset. A disabled integration contributes nothing (pure ``.env``).

Secrets are Fernet-encrypted at rest (db.crypto, PF_SECRET_KEY) and never returned by
the API; they only reach the env of the deploy paths (``scrub_env(allow_cloud=True)``).
CLAUDE.md invariant #2: telemetry/BAS credentials are deploy-time and NOT derived from
the seed — this is just a nicer place to type them than ``.env``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db import repository as repo
from db.crypto import SecretCipher
from db.models import IntegrationConfig
from db.session import transaction

log = logging.getLogger(__name__)

CHECK_TIMEOUT = 15.0
#: an onboarding .cmd is a few KB; refuse anything absurd
MAX_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    message: str


@dataclass(frozen=True)
class Field:
    env: str
    label: str
    secret: bool = False
    #: text | bool | textarea (multi-line secret, e.g. an SSH key) | file (uploaded, materialized to a path)
    kind: str = "text"
    placeholder: str = ""
    help: str = ""
    #: kind=file: the env var that receives the materialized file's path
    path_env: str | None = None
    file_name: str = ""


CheckFn = Callable[[Mapping[str, str]], Awaitable[CheckResult]]


@dataclass(frozen=True)
class Integration:
    name: str
    label: str
    group: str  # infra | detect | bas | general
    description: str
    fields: tuple[Field, ...]
    runbook: str = ""
    test: CheckFn | None = field(default=None, compare=False)

    def get_field(self, env: str) -> Field | None:
        return next((f for f in self.fields if f.env == env), None)

    @property
    def env_names(self) -> tuple[str, ...]:
        return tuple(f.path_env or f.env for f in self.fields)


# --------------------------------------------------------------------------- connection tests


def _req(env: Mapping[str, str], *names: str) -> str | None:
    missing = [n for n in names if not env.get(n)]
    return f"falta {', '.join(missing)}" if missing else None


def _true(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


async def _http(method: str, url: str, *, verify: bool = True, **kw: Any) -> httpx.Response:
    async with httpx.AsyncClient(timeout=CHECK_TIMEOUT, verify=verify, follow_redirects=False) as c:
        return await c.request(method, url, **kw)


def _neterr(exc: Exception) -> CheckResult:
    return CheckResult(False, f"sin conexión: {type(exc).__name__}: {exc}"[:400])


async def check_aws(env: Mapping[str, str]) -> CheckResult:
    if not (env.get("AWS_ACCESS_KEY_ID") or env.get("AWS_PROFILE")):
        return CheckResult(False, "falta AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (o AWS_PROFILE)")
    aws = shutil.which("aws")
    if aws is None:
        return CheckResult(False, "el AWS CLI no está en el PATH de este host (deploy.sh también lo necesita)")
    child = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")} | {
        k: v for k, v in env.items() if k.startswith("AWS_") and v
    }
    proc = await asyncio.create_subprocess_exec(
        aws, "sts", "get-caller-identity", "--output", "text", "--query", "Arn",
        env=child, stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )  # fmt: skip
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), CHECK_TIMEOUT)
    except TimeoutError:
        proc.kill()
        return CheckResult(False, "aws sts get-caller-identity: timeout")
    text = out.decode(errors="replace").strip()
    return CheckResult(proc.returncode == 0, (f"identidad: {text}" if proc.returncode == 0 else text)[:400])


async def check_azure(env: Mapping[str, str]) -> CheckResult:
    if not env.get("ARM_CLIENT_ID"):
        return CheckResult(
            False, "sin service principal: deploy.sh usará el login de `az` del host (no comprobable desde aquí)"
        )
    if err := _req(env, "ARM_TENANT_ID", "ARM_CLIENT_SECRET", "ARM_SUBSCRIPTION_ID"):
        return CheckResult(False, err)
    try:
        tok = await _http(
            "POST",
            f"https://login.microsoftonline.com/{env['ARM_TENANT_ID']}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": env["ARM_CLIENT_ID"],
                "client_secret": env["ARM_CLIENT_SECRET"],
                "scope": "https://management.azure.com/.default",
            },
        )
        if tok.status_code != 200:
            detail = tok.json().get("error_description", tok.text) if tok.content else tok.reason_phrase
            return CheckResult(False, f"login del service principal rechazado: {str(detail).splitlines()[0]}"[:400])
        sub = await _http(
            "GET",
            f"https://management.azure.com/subscriptions/{env['ARM_SUBSCRIPTION_ID']}?api-version=2022-12-01",
            headers={"Authorization": f"Bearer {tok.json()['access_token']}"},
        )
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return _neterr(exc)
    if sub.status_code != 200:
        return CheckResult(False, f"login OK, pero la suscripción no es accesible (HTTP {sub.status_code})")
    return CheckResult(True, f"suscripción: {sub.json().get('displayName', env['ARM_SUBSCRIPTION_ID'])}")


async def check_proxmox(env: Mapping[str, str]) -> CheckResult:
    if err := _req(env, "PROXMOX_VE_ENDPOINT", "PROXMOX_VE_API_TOKEN"):
        return CheckResult(False, err)
    url = env["PROXMOX_VE_ENDPOINT"].rstrip("/") + "/api2/json/version"
    try:
        r = await _http(
            "GET",
            url,
            verify=not _true(env.get("PROXMOX_VE_INSECURE")),
            headers={"Authorization": f"PVEAPIToken={env['PROXMOX_VE_API_TOKEN']}"},
        )
    except httpx.HTTPError as exc:
        hint = " (¿cert self-signed? marca 'insecure')" if "CERTIFICATE" in str(exc).upper() else ""
        return CheckResult(False, _neterr(exc).message + hint)
    if r.status_code == 401:
        return CheckResult(False, "token rechazado (HTTP 401): formato user@realm!tokenid=uuid")
    if r.status_code != 200:
        return CheckResult(False, f"HTTP {r.status_code} de {url}")
    return CheckResult(True, f"Proxmox VE {r.json().get('data', {}).get('version', '?')}")


async def check_elastic(env: Mapping[str, str]) -> CheckResult:
    if err := _req(env, "PF_FLEET_URL", "PF_FLEET_ENROLLMENT_TOKEN"):
        return CheckResult(False, err)
    url = env["PF_FLEET_URL"].rstrip("/") + "/api/status"
    try:
        r = await _http("GET", url, verify=not _true(env.get("PF_FLEET_INSECURE")))
    except httpx.HTTPError as exc:
        return _neterr(exc)
    try:
        status = r.json().get("status", "?")
    except ValueError:
        status = "?"
    ok = r.status_code == 200 and str(status).upper() == "HEALTHY"
    return CheckResult(ok, f"Fleet Server: HTTP {r.status_code}, status {status} (el token se valida al enrolar)")


async def check_cloudflare(env: Mapping[str, str]) -> CheckResult:
    if err := _req(env, "PF_CLOUDFLARE_TEAM", "PF_CLOUDFLARE_ENROLL_CLIENT_ID", "PF_CLOUDFLARE_ENROLL_CLIENT_SECRET"):
        return CheckResult(False, err)
    team = env["PF_CLOUDFLARE_TEAM"].strip().removesuffix(".cloudflareaccess.com")
    try:
        r = await _http("GET", f"https://{team}.cloudflareaccess.com/cdn-cgi/access/certs")
    except httpx.HTTPError as exc:
        return _neterr(exc)
    if r.status_code != 200:
        return CheckResult(False, f"team '{team}' no encontrado (HTTP {r.status_code})")
    return CheckResult(True, f"team '{team}' existe (el service token se valida al enrolar WARP)")


async def check_mde(env: Mapping[str, str]) -> CheckResult:
    path = env.get("MDE_WIN_ONBOARDING_PATH")
    if not path:
        return CheckResult(False, "falta el script de onboarding (súbelo o define MDE_WIN_ONBOARDING_PATH)")
    p = Path(path)
    if not p.is_file():
        return CheckResult(False, f"{path} no es un fichero legible")
    text = p.read_text(encoding="utf-8", errors="replace")
    if "OnboardingInfo" not in text and "Advanced Threat Protection" not in text:
        return CheckResult(False, "no parece un script de onboarding de Defender (no contiene OnboardingInfo)")
    return CheckResult(True, f"script de onboarding válido ({len(text)} bytes)")


async def check_caldera(env: Mapping[str, str]) -> CheckResult:
    if err := _req(env, "PF_CALDERA_SERVER"):
        return CheckResult(False, err)
    base = env["PF_CALDERA_SERVER"].rstrip("/")
    try:
        if env.get("PF_CALDERA_API_KEY"):
            r = await _http("GET", f"{base}/api/v2/health", headers={"KEY": env["PF_CALDERA_API_KEY"]})
            if r.status_code == 200:
                return CheckResult(True, f"Caldera {r.json().get('version', '?')} (API key válida)")
            return CheckResult(False, f"/api/v2/health: HTTP {r.status_code} (¿API key?)")
        r = await _http("GET", base + "/")
    except (httpx.HTTPError, ValueError) as exc:
        return _neterr(exc)
    note = " — ojo: los hosts del lab lo alcanzan por el túnel, no por esta URL" if "127.0.0.1" in base else ""
    return CheckResult(r.status_code < 500, f"servidor responde (HTTP {r.status_code}){note}")


# --------------------------------------------------------------------------- catalog

INTEGRATIONS: tuple[Integration, ...] = (
    Integration(
        "aws",
        "AWS",
        "infra",
        "Terraform apply + backend S3/DynamoDB. Claves explícitas o un perfil del CLI de este host.",
        (
            Field("AWS_ACCESS_KEY_ID", "access key id", secret=True, placeholder="AKIA…"),
            Field("AWS_SECRET_ACCESS_KEY", "secret access key", secret=True),
            Field("AWS_SESSION_TOKEN", "session token", secret=True, help="solo con credenciales temporales (STS/SSO)"),
            Field("AWS_REGION", "región", placeholder="eu-west-1"),
            Field("AWS_PROFILE", "perfil", placeholder="(alternativa a las claves)", help="ignorado si hay claves"),
        ),
        runbook="AWS-DEPLOY-RUNBOOK.md",
        test=check_aws,
    ),
    Integration(
        "azure",
        "Azure",
        "infra",
        "Service principal para Terraform (sin `az login`). Vacío = el login de `az` del host.",
        (
            Field("ARM_TENANT_ID", "tenant id", placeholder="00000000-…"),
            Field("ARM_SUBSCRIPTION_ID", "subscription id", placeholder="00000000-…"),
            Field("ARM_CLIENT_ID", "client (app) id", placeholder="00000000-…"),
            Field("ARM_CLIENT_SECRET", "client secret", secret=True),
            Field("PF_TFSTATE_RG", "RG del estado TF", placeholder="(default del harness)"),
        ),
        runbook="AZURE-DEPLOY-RUNBOOK.md",
        test=check_azure,
    ),
    Integration(
        "proxmox",
        "Proxmox VE",
        "infra",
        "API token del provider bpg/proxmox + SSH al nodo (subida de snippets cloud-init).",
        (
            Field("PROXMOX_VE_ENDPOINT", "endpoint", placeholder="https://pve.example:8006/"),
            Field("PROXMOX_VE_API_TOKEN", "API token", secret=True, placeholder="user@pve!tokenid=uuid"),
            Field("PROXMOX_VE_INSECURE", "cert self-signed (insecure)", kind="bool"),
            Field("PROXMOX_VE_SSH_USERNAME", "usuario SSH", placeholder="root"),
            Field(
                "PROXMOX_VE_SSH_PRIVATE_KEY",
                "clave privada SSH",
                secret=True,
                kind="textarea",
                help="vacío = ssh-agent del host",
            ),
        ),
        runbook="PROXMOX-DEPLOY-RUNBOOK.md",
        test=check_proxmox,
    ),
    Integration(
        "elastic",
        "Elastic (Fleet)",
        "detect",
        "telemetry.edr/siem: elastic — enrolamiento de Elastic Agent vía Fleet.",
        (
            Field("PF_FLEET_URL", "Fleet Server URL", placeholder="https://fleet.example:8220"),
            Field("PF_FLEET_ENROLLMENT_TOKEN", "enrollment token", secret=True),
            Field("PF_ELASTIC_AGENT_VERSION", "versión del agente", placeholder="9.5.4"),
            Field("PF_FLEET_INSECURE", "CA self-signed (insecure)", kind="bool"),
        ),
        runbook="TELEMETRY-DEPLOY-RUNBOOK.md",
        test=check_elastic,
    ),
    Integration(
        "cloudflare",
        "Cloudflare WARP",
        "detect",
        "telemetry: cloudflare — enrolamiento de WARP con service token de Zero Trust.",
        (
            Field("PF_CLOUDFLARE_TEAM", "team", placeholder="mi-team (de mi-team.cloudflareaccess.com)"),
            Field("PF_CLOUDFLARE_ENROLL_CLIENT_ID", "client id", placeholder="….access"),
            Field("PF_CLOUDFLARE_ENROLL_CLIENT_SECRET", "client secret", secret=True),
        ),
        runbook="TELEMETRY-DEPLOY-RUNBOOK.md",
        test=check_cloudflare,
    ),
    Integration(
        "mde",
        "Microsoft Defender for Endpoint",
        "detect",
        "telemetry.edr: microsoft-defender — script de onboarding local de Windows de TU tenant "
        "(Settings › Endpoints › Onboarding › Windows Server › Local Script). Une los hosts a tu organización real.",
        (
            Field(
                "MDE_WIN_ONBOARDING_SCRIPT",
                "script de onboarding (.cmd)",
                secret=True,
                kind="file",
                path_env="MDE_WIN_ONBOARDING_PATH",
                file_name="WindowsDefenderATPOnboardingScript.cmd",
            ),
        ),
        runbook="TELEMETRY-DEPLOY-RUNBOOK.md",
        test=check_mde,
    ),
    Integration(
        "caldera",
        "MITRE Caldera",
        "bas",
        "bas: — servidor Caldera para el beacon sandcat (cloud, o la IP del túnel WireGuard si es Kali local).",
        (
            Field("PF_CALDERA_SERVER", "servidor", placeholder="http://10.11.0.2:8888"),
            Field("PF_CALDERA_GROUP", "grupo", placeholder="red"),
            Field("PF_CALDERA_API_KEY", "API key", secret=True, help="solo si la descarga está autenticada"),
        ),
        runbook="BAS-DEPLOY-RUNBOOK.md",
        test=check_caldera,
    ),
    Integration(
        "general",
        "Overrides de despliegue",
        "general",
        "Sobrescriben región/tamaño del spec sin editarlo (invariante: el spec sigue siendo la fuente).",
        (
            Field("PF_REGION", "región", placeholder="(la del spec)"),
            Field("PF_VM_SIZE", "SKU / tipo de VM", placeholder="(auto-sizing: el más barato)"),
        ),
    ),
)

BY_NAME: dict[str, Integration] = {i.name: i for i in INTEGRATIONS}
GROUP_LABELS = {"infra": "infraestructura", "detect": "DETECT (telemetría)", "bas": "BAS", "general": "general"}


def get(name: str) -> Integration:
    try:
        return BY_NAME[name]
    except KeyError:
        raise KeyError(f"unknown integration {name!r} (one of: {', '.join(BY_NAME)})") from None


# --------------------------------------------------------------------------- input validation


class IntegrationInputError(ValueError):
    pass


def check_value(f: Field, value: str) -> str:
    """Single-line fields must stay single-line: they end up in shell env / .pf-proxmox-env."""
    value = value.strip() if f.kind != "textarea" else value.strip("\r\n ") + ("\n" if value.strip() else "")
    if f.kind in ("text", "bool") and ("\n" in value or "\r" in value or "\x00" in value):
        raise IntegrationInputError(f"{f.label}: no puede contener saltos de línea")
    if "\x00" in value:
        raise IntegrationInputError(f"{f.label}: contiene bytes nulos")
    return value


# --------------------------------------------------------------------------- env resolution


def _files_dir(tenant: str) -> Path:
    """Private dir for materialized uploads (outside the repo: agents' file tools can't see it)."""
    d = Path(tempfile.gettempdir()) / f"pf-integrations-{os.getuid()}" / tenant
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d.parent, 0o700)
    os.chmod(d, 0o700)
    return d


def _materialize(tenant: str, f: Field, content: str) -> str:
    path = _files_dir(tenant) / (f.file_name or f.env.lower())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    os.chmod(path, 0o600)
    return str(path)


def config_env(
    integ: Integration, cfg: IntegrationConfig, cipher: SecretCipher | None, tenant: str
) -> dict[str, str | None]:
    """One enabled integration's env overlay. ``None`` = unset that variable."""
    out: dict[str, str | None] = {}
    values = cfg.values or {}
    secrets = cfg.secrets_encrypted or {}
    for f in integ.fields:
        if f.kind == "bool":
            out[f.env] = "true" if _true(values.get(f.env)) else "false"
            continue
        if f.secret:
            token = secrets.get(f.env)
            if not token:
                continue
            if cipher is None:
                log.warning("integration %s: %s stored but PF_SECRET_KEY is not set — skipped", integ.name, f.env)
                continue
            try:
                plain = cipher.decrypt(token)
            except ValueError:
                log.warning("integration %s: cannot decrypt %s (PF_SECRET_KEY changed?) — skipped", integ.name, f.env)
                continue
            if f.kind == "file":
                out[f.path_env or f.env] = _materialize(tenant, f, plain)
            else:
                out[f.env] = plain
        elif values.get(f.env):
            out[f.env] = str(values[f.env])
    # the AWS_PROFILE gotcha (.env.example): explicit keys + a profile = the CLI picks the profile
    if integ.name == "aws" and out.get("AWS_ACCESS_KEY_ID"):
        out["AWS_PROFILE"] = None
        out.setdefault("AWS_DEFAULT_REGION", out.get("AWS_REGION"))
        if out["AWS_DEFAULT_REGION"] is None:
            del out["AWS_DEFAULT_REGION"]
    return out


async def tenant_env(session: AsyncSession, tenant: str, cipher: SecretCipher | None) -> dict[str, str | None]:
    """The env overlay of every enabled integration of a tenant (see ``apply``)."""
    out: dict[str, str | None] = {}
    for cfg in await repo.list_integration_configs(session, tenant, enabled_only=True):
        integ = BY_NAME.get(cfg.name)
        if integ is not None:
            out.update(config_env(integ, cfg, cipher, tenant))
    return out


async def load_tenant_env(
    sessionmaker: async_sessionmaker[AsyncSession], tenant: str, cipher: SecretCipher | None
) -> dict[str, str | None]:
    async with transaction(sessionmaker) as s:
        return await tenant_env(s, tenant, cipher)


#: carries the overlay (JSON) from the API to an MCP tools server it spawns (api.cli_brain)
OVERLAY_ENV = "PF_DEPLOY_ENV_OVERLAY"


def pop_overlay_from_environ() -> dict[str, str | None]:
    """In an MCP tools child: take the overlay out of os.environ (so it isn't passed further as-is)."""
    import json

    raw = os.environ.pop(OVERLAY_ENV, "")
    if not raw:
        return {}
    data = json.loads(raw)
    return {str(k): (None if v is None else str(v)) for k, v in data.items()}


def apply(environ: Mapping[str, str], overlay: Mapping[str, str | None]) -> dict[str, str]:
    """``environ`` with the UI-configured integrations on top (UI wins over .env)."""
    env = dict(environ)
    for key, value in overlay.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


# --------------------------------------------------------------------------- UI status


@dataclass
class FieldStatus:
    field: Field
    #: "ui" (saved here) | "env" (.env / process env) | None (unset)
    source: str | None
    #: shown for non-secret fields only
    value: str = ""


@dataclass
class IntegrationStatus:
    integration: Integration
    config: IntegrationConfig | None
    fields: list[FieldStatus]

    @property
    def enabled(self) -> bool:
        return self.config is not None and self.config.enabled

    @property
    def configured(self) -> bool:
        return any(f.source for f in self.fields if f.field.kind != "bool")


def status(configs: Sequence[IntegrationConfig], environ: Mapping[str, str] | None = None) -> list[IntegrationStatus]:
    environ = os.environ if environ is None else environ
    by_name = {c.name: c for c in configs}
    rows: list[IntegrationStatus] = []
    for integ in INTEGRATIONS:
        cfg = by_name.get(integ.name)
        active = cfg is not None and cfg.enabled
        fields = []
        for f in integ.fields:
            env_name = f.path_env or f.env
            if (
                active
                and cfg is not None
                and (
                    (f.secret and f.env in (cfg.secrets_encrypted or {}))
                    or (not f.secret and f.env in (cfg.values or {}))
                )
            ):
                source, value = "ui", "" if f.secret else str(cfg.values[f.env])
            elif environ.get(env_name):
                source, value = "env", "" if f.secret else environ[env_name]
            else:
                source, value = None, ""
            if f.kind == "file" and source == "env":
                value = environ[env_name]  # a path, not the secret itself
            if f.kind == "bool":  # the checkbox shows the effective value (so saving doesn't flip .env)
                raw = (cfg.values or {}).get(f.env) if active and cfg is not None else environ.get(env_name)
                value = "true" if _true(raw) else ""
            fields.append(FieldStatus(f, source, value))
        rows.append(IntegrationStatus(integ, cfg, fields))
    return rows


async def run_test(session: AsyncSession, tenant: str, name: str, cipher: SecretCipher | None) -> CheckResult:
    """Test with the EFFECTIVE values (what a deploy would get: UI over .env)."""
    integ = get(name)
    if integ.test is None:
        return CheckResult(True, "nada que probar: son overrides de despliegue")
    cfg = await repo.get_integration_config(session, tenant, name)
    overlay = config_env(integ, cfg, cipher, tenant) if cfg is not None and cfg.enabled else {}
    env = apply(os.environ, overlay)
    try:
        return await integ.test(env)
    except Exception as exc:  # noqa: BLE001 - a test button never 500s
        log.exception("integration test %s crashed", name)
        return CheckResult(False, f"{type(exc).__name__}: {exc}"[:400])


# --------------------------------------------------------------------------- save (shared by API + UI)


async def save(
    session: AsyncSession,
    tenant: str,
    name: str,
    *,
    enabled: bool,
    values: Mapping[str, str],
    secrets: Mapping[str, str],
    clear_secrets: Sequence[str] = (),
    cipher: SecretCipher | None,
) -> IntegrationConfig:
    """``values``: every non-secret field (missing/empty = unset → falls back to .env).
    ``secrets``: only the ones being replaced (empty = keep the stored one)."""
    try:
        integ = get(name)
    except KeyError as exc:
        raise IntegrationInputError(str(exc)) from None
    known = {f.env: f for f in integ.fields}
    for env in [*values, *secrets, *clear_secrets]:
        if env not in known:
            raise IntegrationInputError(f"{env}: no es un campo de {integ.label}")
    clean_values: dict[str, str] = {}
    for env, raw in values.items():
        f = known[env]
        if f.secret:
            raise IntegrationInputError(f"{env} es un secreto: va en 'secrets'")
        v = check_value(f, raw or "")
        if f.kind == "bool":
            v = "true" if _true(v) else ""
        if v:
            clean_values[env] = v
    clean_secrets: dict[str, str] = {}
    for env, raw in secrets.items():
        f = known[env]
        if not f.secret:
            raise IntegrationInputError(f"{env} no es un secreto: va en 'values'")
        if not raw:
            continue
        if f.kind == "file" and len(raw.encode("utf-8")) > MAX_FILE_BYTES:
            raise IntegrationInputError(f"{f.label}: el fichero supera {MAX_FILE_BYTES // 1024} KB")
        clean_secrets[env] = check_value(f, raw) if f.kind != "file" else raw
    if clean_secrets and cipher is None:
        raise IntegrationInputError("configura PF_SECRET_KEY en el servidor antes de guardar secretos")
    return await repo.upsert_integration_config(
        session,
        tenant,
        name=name,
        enabled=enabled,
        values=clean_values,
        set_secrets=clean_secrets,
        clear_secrets=clear_secrets,
        cipher=cipher,
    )
