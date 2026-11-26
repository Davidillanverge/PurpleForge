"""Bearer-token auth → Principal (user + tenant), plus CSRF for cookie sessions.

Tokens come from PF_API_TOKENS. They're accepted from the
``Authorization: Bearer`` header (API clients) or the ``pf_token`` cookie (the
browser UI). The principal's ``actor`` ("user:<id>") is what the FSM and the
approval gate check — only humans can approve.

Cookie sessions are CSRF-protected twice: the cookies are ``SameSite=Strict``,
and every unsafe request authenticated by cookie must echo the ``pf_csrf``
cookie in an ``X-CSRF-Token`` header (double submit; the UI sets it on every
htmx request). Bearer-token requests carry no ambient credential, so no CSRF.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass

from fastapi import HTTPException, Request, Response, status

from api.settings import AppSettings

COOKIE_NAME = "pf_token"
CSRF_COOKIE = "pf_csrf"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Principal:
    user: str
    tenant: str

    @property
    def actor(self) -> str:
        return f"user:{self.user}"


def _bearer(request: Request) -> str | None:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


def user_for_token(token: str, settings: AppSettings) -> str | None:
    for known, user in settings.api_tokens.items():  # constant-time compare against every token
        if hmac.compare_digest(known.encode(), token.encode()):
            return user
    return None


def _check_csrf(request: Request) -> None:
    if request.method in SAFE_METHODS:
        return
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get(CSRF_HEADER, "")
    if not cookie or not hmac.compare_digest(cookie.encode(), header.encode()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")


def authenticate(request: Request, settings: AppSettings) -> Principal:
    if settings.auth_disabled:
        return Principal(user="dev", tenant=settings.default_tenant)
    token = _bearer(request)
    via_cookie = False
    if token is None:
        token = request.cookies.get(COOKIE_NAME)
        via_cookie = token is not None
    user = user_for_token(token, settings) if token else None
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "missing or invalid API token", headers={"WWW-Authenticate": "Bearer"}
        )
    if via_cookie:
        _check_csrf(request)
    return Principal(user=user, tenant=settings.default_tenant)


def start_session(response: Response, token: str, *, secure: bool) -> str:
    """Set the session + CSRF cookies after a successful login; returns the CSRF token."""
    csrf = secrets.token_urlsafe(32)
    common = {"httponly": True, "samesite": "strict", "secure": secure, "path": "/"}
    response.set_cookie(COOKIE_NAME, token, max_age=12 * 3600, **common)  # type: ignore[arg-type]
    response.set_cookie(CSRF_COOKIE, csrf, max_age=12 * 3600, **common)  # type: ignore[arg-type]
    return csrf


def end_session(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
