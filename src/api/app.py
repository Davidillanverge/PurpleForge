"""FastAPI application factory.

uvicorn api.app:create_app --factory --app-dir src
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Request, Response, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from agents import background
from api.broker import Broker, EventBroker, RedisEventBroker
from api.forge_jobs import ForgeActionError, ForgeJobs
from api.registry import AgentPreconditionError, AgentSpec, default_registry
from api.routes import approvals, health, labs, providers, runs, usage
from api.runner import AgentRunner, LabBusy, LLMFactory, UnknownAgent
from api.settings import AppSettings, load_env_file
from db import repository as repo
from db.crypto import SecretCipher
from db.migrate import upgrade_head
from db.session import create_engine, create_sessionmaker
from db.settings import DatabaseSettings
from db.states import InvalidTransition

log = logging.getLogger(__name__)


SERVICE_LOGGERS = ("api", "agents", "db", "llm", "ui")


def configure_logging(level: str) -> None:
    """Timestamped, levelled logs for the service's own packages (idempotent; leaves
    uvicorn's loggers and any handler the host app already installed alone)."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    for name in SERVICE_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(level.upper())
        if not logger.handlers:
            logger.addHandler(handler)
            logger.propagate = False


async def wait_for_database(engine: AsyncEngine, timeout: float) -> None:
    """Containers start in parallel: retry until the DB accepts connections."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            if loop.time() >= deadline:
                raise RuntimeError(f"database not reachable after {timeout:.0f}s: {exc}") from exc
            log.info("waiting for the database: %s", exc)
            await asyncio.sleep(1.0)


async def build_broker(settings: AppSettings) -> Broker:
    if not settings.redis_url:
        workers = os.environ.get("UVICORN_WORKERS", "1")
        if workers.isdigit() and int(workers) > 1:
            # each worker would have its own in-memory broker: approvals/SSE/cancels
            # landing on the wrong worker would silently go nowhere.
            raise RuntimeError(f"UVICORN_WORKERS={workers} needs PF_REDIS_URL (in-memory broker is single-process)")
        return EventBroker()
    import redis.asyncio as aioredis

    client = aioredis.from_url(settings.redis_url)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.db_wait_seconds
    while True:
        try:
            await client.ping()
            return RedisEventBroker(client)
        except Exception as exc:  # noqa: BLE001
            if loop.time() >= deadline:
                raise RuntimeError(f"redis not reachable at PF_REDIS_URL: {exc}") from exc
            log.info("waiting for redis: %s", exc)
            await asyncio.sleep(1.0)


def _repo_env_file() -> Path:
    from forge.core import REPO_ROOT  # lazy, like api.settings: forge resolves the repo root

    return Path(REPO_ROOT) / ".env"


def create_app(
    settings: AppSettings | None = None,
    db_settings: DatabaseSettings | None = None,
    *,
    registry: dict[str, AgentSpec] | None = None,
    llm_factory: LLMFactory | None = None,
) -> FastAPI:
    # Production path only (tests inject settings and must not pick up the dev .env):
    # export .env into os.environ so agent subprocesses (forge deploy) see the
    # deploy-time vars too, the same .env pydantic-settings reads (cwd) plus the repo's.
    env_files = load_env_file(Path(".env"), _repo_env_file()) if settings is None else []
    settings = settings or AppSettings()
    db_settings = db_settings or DatabaseSettings()
    configure_logging(settings.log_level)
    for env_file in env_files:
        log.info("exported %s into the process environment (already-set variables kept)", env_file)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings=db_settings)
        await wait_for_database(engine, settings.db_wait_seconds)
        if settings.auto_migrate:
            await upgrade_head(engine)  # advisory-locked on Postgres: safe with N workers
        sessionmaker = create_sessionmaker(engine)
        # long forge operations of agent runs become detached jobs writing to this DB
        background.configure(engine.url.render_as_string(hide_password=False))
        secret = db_settings.secret_key.get_secret_value() if db_settings.secret_key else None
        cipher = SecretCipher(secret) if secret else None
        broker = await build_broker(settings)
        runner = AgentRunner(
            sessionmaker, broker, settings, registry or default_registry(), cipher=cipher, llm_factory=llm_factory
        )
        app.state.settings = settings
        app.state.engine = engine
        app.state.sessionmaker = sessionmaker
        app.state.cipher = cipher
        app.state.broker = broker
        app.state.runner = runner
        forge_jobs = ForgeJobs(sessionmaker, settings.repo_root, worker_id=runner.worker_id)
        app.state.forge_jobs = forge_jobs
        if not settings.auth_disabled and not settings.api_tokens:
            log.warning("no PF_API_TOKENS configured: every API request will be rejected (401)")
        if settings.auth_disabled:
            log.warning("PF_AUTH_DISABLED=true: every request is user 'dev' — local development only")
        await runner.recover_orphans()
        alive = await broker.alive_workers()  # clustered: leave other workers' forge runs alone
        await forge_jobs.recover_orphans(alive_workers=None if alive is None else {*alive, runner.worker_id})
        await runner.start_background()
        log.info("PurpleForge worker %s ready (broker: %s)", runner.worker_id, type(broker).__name__)
        try:
            yield
        finally:
            await forge_jobs.shutdown()
            await runner.shutdown()
            await broker.aclose()
            await engine.dispose()

    app = FastAPI(title="PurpleForge", version="0.1.0", lifespan=lifespan)
    for module in (health, labs, runs, approvals, providers, usage):
        app.include_router(module.router)
    from ui.routes import router as ui_router
    from ui.templating import STATIC_DIR

    app.include_router(ui_router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(SecurityHeadersMiddleware)
    _install_error_handlers(app)
    return app


#: Everything is served from 'self' (htmx/Tailwind vendored, no inline scripts or
#: styles), so the policy can be strict. API JSON responses get it too — harmless.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response


def _is_ui_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true" and not request.url.path.startswith("/api/")


def _error_response(request: Request, code: int, detail: str) -> Response:
    """JSON for the API; a toast for htmx UI requests; a plain error page for UI page loads."""
    if _is_ui_htmx(request):
        from ui.routes import flash_response

        return flash_response(detail, code=code)
    if not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", ""):
        from ui.routes import templates

        return templates.TemplateResponse(
            request,
            "error.html",
            {"code": code, "detail": detail, "principal": None, "csrf_token": ""},
            status_code=code,
        )
    return JSONResponse({"detail": detail}, status_code=code)


def _install_error_handlers(app: FastAPI) -> None:
    from api import services
    from ui.routes import LoginRequired

    def handler(code: int) -> Any:
        async def _h(request: Request, exc: Exception) -> Response:
            return _error_response(request, code, str(exc))

        return _h

    for exc_type, code in (
        (repo.NotFound, status.HTTP_404_NOT_FOUND),
        (UnknownAgent, status.HTTP_404_NOT_FOUND),
        (InvalidTransition, status.HTTP_409_CONFLICT),
        (LabBusy, status.HTTP_409_CONFLICT),
        (ForgeActionError, status.HTTP_409_CONFLICT),
        (repo.ApprovalAlreadyDecided, status.HTTP_409_CONFLICT),
        (repo.LabHasInfrastructure, status.HTTP_409_CONFLICT),
        (services.LabExists, status.HTTP_409_CONFLICT),
        (services.LabNotEditable, status.HTTP_409_CONFLICT),
        (repo.ActorNotAllowed, status.HTTP_403_FORBIDDEN),
        (services.ManualTransitionForbidden, status.HTTP_403_FORBIDDEN),
        (AgentPreconditionError, status.HTTP_422_UNPROCESSABLE_CONTENT),
        (services.SpecError, status.HTTP_422_UNPROCESSABLE_CONTENT),
    ):
        app.add_exception_handler(exc_type, handler(code))

    async def integrity(request: Request, exc: Exception) -> Response:
        return _error_response(request, status.HTTP_409_CONFLICT, "conflicts with an existing record")

    async def http_exc(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)
        if _is_ui_htmx(request) or (
            not request.url.path.startswith("/api/") and "text/html" in request.headers.get("accept", "")
        ):
            return _error_response(request, exc.status_code, str(exc.detail))
        return await http_exception_handler(request, exc)

    async def login_required(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, LoginRequired)
        target = "/login" + (f"?next={quote(exc.next_url)}" if exc.next_url not in ("", "/") else "")
        if request.headers.get("hx-request") == "true":
            return Response(status_code=200, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=303)

    app.add_exception_handler(IntegrityError, integrity)
    app.add_exception_handler(StarletteHTTPException, http_exc)
    app.add_exception_handler(LoginRequired, login_required)
