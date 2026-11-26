"""Server-rendered UI (Jinja2 + HTMX). Pages at /, fragments and actions under /ui/.

Every rule lives in api.services / api.runner / db.repository — the UI only
renders and calls them, so it can never be laxer than the JSON API. Mutations
are htmx POSTs carrying the CSRF header (see api.auth).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import ValidationError

from api import services
from api.auth import CSRF_COOKIE, Principal, authenticate, end_session, start_session, user_for_token
from api.deps import RunnerDep, SessionDep, SettingsDep
from api.sse import StreamEnd, format_sse, iter_run_events
from db import repository as repo
from db.states import LabState, ProviderKind
from ui.templating import build_templates

router = APIRouter(include_in_schema=False)
templates = build_templates()


class LoginRequired(Exception):
    def __init__(self, next_url: str = "/") -> None:
        self.next_url = next_url


def ui_principal(request: Request, settings: SettingsDep) -> Principal:
    try:
        return authenticate(request, settings)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            raise LoginRequired(_return_to(request)) from exc
        raise


UIPrincipal = Annotated[Principal, Depends(ui_principal)]


# --------------------------------------------------------------------------- helpers


def render(
    request: Request,
    name: str,
    principal: Principal | None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    **ctx: Any,
) -> HTMLResponse:
    ctx.update(principal=principal, csrf_token=request.cookies.get(CSRF_COOKIE, ""))
    return templates.TemplateResponse(request, name, ctx, status_code=status_code, headers=headers)


def fragment(name: str, **ctx: Any) -> str:
    return templates.get_template(name).render(**ctx)


def hx_redirect(url: str) -> Response:
    return Response(status_code=200, headers={"HX-Redirect": url})


def flash_response(message: str, *, level: str = "error", code: int | None = None) -> HTMLResponse:
    """For htmx requests: show a toast in #flash instead of swapping the target."""
    return HTMLResponse(
        fragment("partials/flash.html", message=message, level=level, code=code),
        headers={"HX-Retarget": "#flash", "HX-Reswap": "innerHTML"},
    )


def _version(ids: list[uuid.UUID]) -> str:
    return hashlib.sha256(",".join(sorted(map(str, ids))).encode()).hexdigest()[:16]


def _return_to(request: Request) -> str:
    """Where to land after login: the page itself, never a /ui/ action or fragment
    (those are POSTs/partials — landing on one after login would 405 or show a shard)."""
    path = request.url.path
    if path.startswith("/ui/"):
        current = request.headers.get("hx-current-url", "")
        path = urlsplit(current).path if current else "/"
    return _safe_next(path) if not path.startswith("/ui/") else "/"


def _safe_next(value: str | None) -> str:
    # only same-site absolute paths (no //host or scheme) — no open redirect
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


async def _lab_ctx(request: Request, session: Any, principal: Principal, lab_id: uuid.UUID) -> dict[str, Any]:
    lab = await repo.get_lab(session, principal.tenant, lab_id)
    settings = request.app.state.settings
    return {
        "lab": lab,
        "transitions": await repo.list_transitions(session, principal.tenant, lab_id),
        "runs": await repo.list_runs(session, principal.tenant, lab_id=lab_id),
        "agents": list(request.app.state.runner.registry.values()),
        "manifest": services.load_manifest_summary(settings.repo_root, lab.name) if lab.spec_path else None,
        "lab_usage": await repo.usage_total(session, principal.tenant, lab_id=lab_id),
        "lab_usage_by_agent": await repo.usage_by_agent(session, principal.tenant, lab_id=lab_id),
    }


# --------------------------------------------------------------------------- auth


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, settings: SettingsDep, next: str = "/"):
    if settings.auth_disabled:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", None, next=_safe_next(next), error=None)


@router.post("/login", response_class=HTMLResponse)
async def login(
    request: Request, settings: SettingsDep, token: Annotated[str, Form()], next: Annotated[str, Form()] = "/"
):
    if user_for_token(token, settings) is None:
        return render(request, "login.html", None, status_code=401, next=_safe_next(next), error="token inválido")
    response = RedirectResponse(_safe_next(next), status_code=303)
    start_session(response, token, secure=request.url.scheme == "https")
    return response


@router.post("/logout")
async def logout(principal: UIPrincipal) -> Response:
    response = hx_redirect("/login")
    end_session(response)
    return response


# --------------------------------------------------------------------------- dashboard + labs


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: SessionDep, principal: UIPrincipal, settings: SettingsDep):
    specs_dir = settings.repo_root / "specs"
    specs = sorted(f"specs/{p.name}" for p in specs_dir.glob("*.yml")) if specs_dir.is_dir() else []
    return render(
        request,
        "dashboard.html",
        principal,
        nav_active="labs",
        labs=await repo.list_labs(session, principal.tenant),
        pending_count=len(await repo.list_pending_approvals(session, principal.tenant)),
        active_runs=await repo.count_active_runs(session, principal.tenant),
        specs=specs,
        lab_free_agents=[a for a in request.app.state.runner.registry.values() if not a.requires_lab],
        usage_total=await repo.usage_total(session, principal.tenant),
        usage_by_lab=await repo.usage_by_lab(session, principal.tenant),
    )


@router.get("/ui/partials/labs", response_class=HTMLResponse)
async def lab_rows(request: Request, session: SessionDep, principal: UIPrincipal):
    return render(
        request,
        "partials/lab_rows.html",
        principal,
        labs=await repo.list_labs(session, principal.tenant),
        usage_by_lab=await repo.usage_by_lab(session, principal.tenant),
    )


@router.post("/ui/labs")
async def create_lab(
    session: SessionDep,
    principal: UIPrincipal,
    settings: SettingsDep,
    name: Annotated[str, Form()],
    spec_path: Annotated[str, Form()] = "",
    description: Annotated[str, Form()] = "",
) -> Response:
    from api.schemas import LabCreate  # same name validation as the API

    try:
        body = LabCreate(name=name.strip(), description=description.strip(), spec_path=spec_path.strip() or None)
    except ValidationError as exc:
        return flash_response("; ".join(e["msg"].removeprefix("Value error, ") for e in exc.errors()))
    lab = await services.create_lab(
        session, principal, settings, name=body.name, description=body.description, spec_path=body.spec_path
    )
    return hx_redirect(f"/labs/{lab.id}")


@router.get("/labs/{lab_id}", response_class=HTMLResponse)
async def lab_detail(lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal):
    return render(
        request, "lab_detail.html", principal, nav_active="labs", **await _lab_ctx(request, session, principal, lab_id)
    )


@router.get("/ui/partials/labs/{lab_id}/panel", response_class=HTMLResponse)
async def lab_panel(lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal):
    return render(
        request, "partials/panel_fragment.html", principal, **await _lab_ctx(request, session, principal, lab_id)
    )


@router.post("/ui/labs/{lab_id}/compile", response_class=HTMLResponse)
async def compile_lab(
    lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal, settings: SettingsDep
):
    _, outcome = await services.compile_lab(session, principal, settings, lab_id)
    await session.flush()
    return render(
        request,
        "partials/compile_result.html",
        principal,
        outcome=outcome,
        **await _lab_ctx(request, session, principal, lab_id),
    )


@router.post("/ui/labs/{lab_id}/check", response_class=HTMLResponse)
async def check_lab(
    lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal, settings: SettingsDep
):
    _, outcome = await services.check_lab(session, principal, settings, lab_id)
    return render(
        request,
        "partials/forge_result.html",
        principal,
        outcome=outcome,
        title_ok="✓ check OK — el spec es válido (no se ha escrito nada)",
        title_fail="✗ check: el spec tiene errores",
    )


@router.post("/ui/labs/{lab_id}/generate", response_class=HTMLResponse)
async def generate_lab(
    lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal, settings: SettingsDep
):
    _, outcome = await services.generate_lab(session, principal, settings, lab_id)
    return render(
        request,
        "partials/forge_result.html",
        principal,
        outcome=outcome,
        title_ok=f"✓ generado en {outcome.out_dir} ({len(outcome.files)} ficheros)",
        title_fail="✗ forge generate falló",
    )


@router.post("/ui/labs/{lab_id}/approve", response_class=HTMLResponse)
async def approve_lab(
    lab_id: uuid.UUID,
    request: Request,
    session: SessionDep,
    principal: UIPrincipal,
    authorized: Annotated[str, Form()] = "",
    reason: Annotated[str, Form()] = "",
):
    if authorized != "yes":
        return flash_response("marca la confirmación de uso autorizado (invariante #6) para aprobar")
    note = "authorized-use confirmed (#6)" + (f" — {reason.strip()}" if reason.strip() else "")
    await services.user_transition(session, principal, lab_id, LabState.APPROVED, reason=note)
    return render(
        request, "partials/panel_fragment.html", principal, **await _lab_ctx(request, session, principal, lab_id)
    )


@router.post("/ui/labs/{lab_id}/redesign", response_class=HTMLResponse)
async def redesign_lab(lab_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal):
    await services.user_transition(session, principal, lab_id, LabState.DESIGNED, reason="sent back to designed")
    return render(
        request, "partials/panel_fragment.html", principal, **await _lab_ctx(request, session, principal, lab_id)
    )


@router.post("/ui/labs/{lab_id}/delete")
async def delete_lab(lab_id: uuid.UUID, session: SessionDep, principal: UIPrincipal) -> Response:
    await services.delete_lab(session, principal, lab_id)
    return hx_redirect("/")


@router.post("/ui/labs/{lab_id}/runs")
async def start_run(
    lab_id: uuid.UUID,
    runner: RunnerDep,
    principal: UIPrincipal,
    agent: Annotated[str, Form()],
    instructions: Annotated[str, Form()] = "",
) -> Response:
    run = await runner.start(principal, agent, lab_id=lab_id, instructions=instructions.strip()[:10_000])
    return hx_redirect(f"/runs/{run.id}")


@router.post("/ui/runs")
async def start_lab_free_run(
    runner: RunnerDep,
    principal: UIPrincipal,
    agent: Annotated[str, Form()],
    instructions: Annotated[str, Form()] = "",
) -> Response:
    """Agents that work outside any lab lifecycle (catalog-author)."""
    run = await runner.start(principal, agent, lab_id=None, instructions=instructions.strip()[:10_000])
    return hx_redirect(f"/runs/{run.id}")


# --------------------------------------------------------------------------- runs / console


@router.get("/runs/{run_id}", response_class=HTMLResponse)
async def run_console(
    run_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal, runner: RunnerDep
):
    run = await repo.get_run(session, principal.tenant, run_id)
    events = await repo.list_events(session, principal.tenant, run_id, limit=100_000)
    approvals = await repo.list_run_approvals(session, principal.tenant, run_id)
    pending = [a.id for a in approvals if a.status.value == "pending"]
    return render(
        request,
        "run_console.html",
        principal,
        nav_active="labs",
        run=run,
        lab=await repo.get_lab(session, principal.tenant, run.lab_id) if run.lab_id else None,
        events=events,
        last_seq=events[-1].seq if events else 0,
        active=not run.status.is_terminal,
        approvals=approvals,
        version=_version(pending),
        lab_names={},
    )


@router.get("/ui/partials/runs/{run_id}/approvals", response_class=HTMLResponse)
async def run_approvals(run_id: uuid.UUID, request: Request, session: SessionDep, principal: UIPrincipal, v: str = ""):
    run = await repo.get_run(session, principal.tenant, run_id)
    approvals = await repo.list_run_approvals(session, principal.tenant, run_id)
    pending = [a.id for a in approvals if a.status.value == "pending"]
    version = _version(pending)
    if run.status.is_terminal and not pending:
        return HTMLResponse("")  # run over: drop the poller
    if v == version:
        return Response(status_code=status.HTTP_204_NO_CONTENT)  # unchanged: htmx keeps the DOM as is
    return render(
        request, "partials/run_approvals.html", principal, run=run, approvals=approvals, version=version, lab_names={}
    )


@router.post("/ui/runs/{run_id}/cancel", response_class=HTMLResponse)
async def cancel_run(run_id: uuid.UUID, request: Request, principal: UIPrincipal, runner: RunnerDep):
    async with request.app.state.sessionmaker() as s:
        current = await repo.get_run(s, principal.tenant, run_id)
    if current.source == "mcp":
        return flash_response(
            "MCP runs are driven by Claude Code: deny the pending approval to stop one before it touches infrastructure"
        )
    if not await runner.cancel(run_id, tenant=principal.tenant):
        return flash_response("el run ya no está activo")
    async with request.app.state.sessionmaker() as s:
        run = await repo.get_run(s, principal.tenant, run_id)
    return render(request, "partials/run_header.html", principal, run=run, active=False)


@router.get("/ui/runs/{run_id}/console-stream")
async def console_stream(
    run_id: uuid.UUID,
    request: Request,
    principal: UIPrincipal,
    runner: RunnerDep,
    settings: SettingsDep,
    after: int = 0,
):
    """SSE of server-rendered HTML: one console line per event (+ the run header
    out-of-band), then ``event: end`` so htmx closes the EventSource."""
    last_event_id = request.headers.get("last-event-id", "")
    if last_event_id.isdigit():
        after = max(after, int(last_event_id))
    sessionmaker = request.app.state.sessionmaker
    async with sessionmaker() as s:
        await repo.get_run(s, principal.tenant, run_id)

    async def frames() -> AsyncIterator[str]:
        async for item in iter_run_events(
            sessionmaker=sessionmaker,
            broker=request.app.state.broker,
            tenant_id=principal.tenant,
            run_id=run_id,
            after_seq=after,
            heartbeat=settings.sse_heartbeat_seconds,
        ):
            if item is None:
                yield ": keep-alive\n\n"
                continue
            async with sessionmaker() as s:
                run = await repo.get_run(s, principal.tenant, run_id)
            header = (
                '<div id="run-header" hx-swap-oob="true">'
                # the task may still be finalizing after the terminal event: trust the status too
                + fragment("partials/run_header.html", run=run, active=not run.status.is_terminal)
                + "</div>"
            )
            if isinstance(item, StreamEnd):
                tail = '<div id="console-tail" hx-swap-oob="true" class="border-t border-term-line px-4 py-2 text-xs text-term-dim">run terminado</div>'
                yield format_sse(data=header + tail)
                yield format_sse(event="end", data="end")
                return
            yield format_sse(id_=item.seq, data=fragment("partials/event.html", ev=item) + header)

    return StreamingResponse(
        frames(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --------------------------------------------------------------------------- approvals


async def _approvals_ctx(session: Any, principal: Principal) -> dict[str, Any]:
    pending = await repo.list_pending_approvals(session, principal.tenant)
    return {"pending": pending, "version": _version([a.id for a in pending])}


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request, session: SessionDep, principal: UIPrincipal, settings: SettingsDep):
    ctx = await _approvals_ctx(session, principal)
    recent = await repo.list_recent_approvals(session, principal.tenant)
    names = await repo.lab_names(session, principal.tenant, [a.lab_id for a in [*ctx["pending"], *recent]])
    return render(
        request,
        "approvals.html",
        principal,
        nav_active="approvals",
        recent=recent,
        lab_names=names,
        timeout_minutes=int(settings.approval_timeout_seconds // 60),
        **ctx,
    )


@router.get("/ui/partials/approvals", response_class=HTMLResponse)
async def pending_approvals(request: Request, session: SessionDep, principal: UIPrincipal, v: str = ""):
    ctx = await _approvals_ctx(session, principal)
    if v == ctx["version"]:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    names = await repo.lab_names(session, principal.tenant, [a.lab_id for a in ctx["pending"]])
    return render(request, "partials/pending_approvals.html", principal, lab_names=names, **ctx)


@router.get("/ui/partials/nav-tokens", response_class=HTMLResponse)
async def nav_tokens(request: Request, session: SessionDep, principal: UIPrincipal):
    return render(request, "partials/nav_tokens.html", principal, u=await repo.usage_total(session, principal.tenant))


@router.get("/ui/partials/nav-approvals", response_class=HTMLResponse)
async def nav_approvals(request: Request, session: SessionDep, principal: UIPrincipal):
    count = len(await repo.list_pending_approvals(session, principal.tenant))
    return render(request, "partials/nav_approvals.html", principal, count=count)


@router.post("/ui/approvals/{approval_id}/decision", response_class=HTMLResponse)
async def decide(
    approval_id: uuid.UUID,
    request: Request,
    principal: UIPrincipal,
    runner: RunnerDep,
    approved: Annotated[str, Form()],
    comment: Annotated[str, Form()] = "",
):
    if approved not in ("true", "false"):
        return flash_response("decisión inválida")
    approval = await runner.decide(principal, approval_id, approved=approved == "true", comment=comment.strip() or None)
    return render(request, "partials/approval_card.html", principal, a=approval, lab_names={})


# --------------------------------------------------------------------------- providers


@router.get("/settings/providers", response_class=HTMLResponse)
async def providers_page(request: Request, session: SessionDep, principal: UIPrincipal):
    env_rows, env_error = services.env_providers()
    return render(
        request,
        "providers.html",
        principal,
        nav_active="providers",
        providers=await repo.list_provider_configs(session, principal.tenant),
        kinds=[k.value for k in ProviderKind],
        cipher_ready=request.app.state.cipher is not None,
        env_rows=env_rows,
        env_error=env_error,
    )


@router.post("/ui/providers")
async def save_provider(
    request: Request,
    session: SessionDep,
    principal: UIPrincipal,
    name: Annotated[str, Form()],
    kind: Annotated[ProviderKind, Form()],
    model: Annotated[str, Form()],
    priority: Annotated[int, Form()] = 100,
    base_url: Annotated[str, Form()] = "",
    timeout_seconds: Annotated[str, Form()] = "",
    api_key: Annotated[str, Form()] = "",
    clear_api_key: Annotated[str, Form()] = "",
    enabled: Annotated[str, Form()] = "",
) -> Response:
    from api.routes.providers import PROVIDER_NAME

    if not PROVIDER_NAME.match(name):
        return flash_response("nombre de proveedor inválido ([a-z][a-z0-9_-]*)")
    cipher = request.app.state.cipher
    kwargs: dict[str, Any] = {}
    if clear_api_key == "yes":
        kwargs["api_key"] = None
    elif api_key:
        if cipher is None:
            return flash_response("configura PF_SECRET_KEY en el servidor antes de guardar una API key")
        kwargs["api_key"] = api_key
    try:
        timeout = float(timeout_seconds) if timeout_seconds.strip() else None
    except ValueError:
        return flash_response("timeout inválido")
    await repo.upsert_provider_config(
        session,
        principal.tenant,
        name=name,
        kind=kind,
        model=model.strip(),
        enabled=enabled == "yes",
        priority=priority,
        base_url=base_url.strip() or None,
        timeout_seconds=timeout,
        cipher=cipher,
        **kwargs,
    )
    return hx_redirect("/settings/providers")


@router.post("/ui/providers/env/{name}/test", response_class=HTMLResponse)
async def test_env_provider(name: str, request: Request, principal: UIPrincipal):
    result = await services.test_env_provider(name)
    return render(request, "partials/provider_test.html", principal, result=result)


@router.post("/ui/providers/{name}/delete")
async def delete_provider(name: str, session: SessionDep, principal: UIPrincipal) -> Response:
    if not await repo.delete_provider_config(session, principal.tenant, name):
        return flash_response(f"proveedor {name!r} no encontrado")
    return hx_redirect("/settings/providers")


@router.post("/ui/providers/{name}/test", response_class=HTMLResponse)
async def test_provider(name: str, request: Request, session: SessionDep, principal: UIPrincipal):
    result = await services.test_provider(session, principal, name, request.app.state.cipher)
    return render(request, "partials/provider_test.html", principal, result=result)
