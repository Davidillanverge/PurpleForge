"""Per-tenant LLM provider configuration. API keys are write-only."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request, Response, status

from api import services
from api.deps import PrincipalDep, SessionDep
from api.schemas import ProviderIn, ProviderOut, ProviderTestResult
from db import repository as repo

router = APIRouter(prefix="/api/providers", tags=["providers"])

PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


@router.get("", response_model=list[ProviderOut])
async def list_providers(session: SessionDep, principal: PrincipalDep):
    return await repo.list_provider_configs(session, principal.tenant)


@router.put("/{name}", response_model=ProviderOut)
async def put_provider(name: str, body: ProviderIn, request: Request, session: SessionDep, principal: PrincipalDep):
    if not PROVIDER_NAME.match(name):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid provider name")
    kwargs = {}
    if "api_key" in body.model_fields_set:
        kwargs["api_key"] = body.api_key or None
        if body.api_key and request.app.state.cipher is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "set PF_SECRET_KEY on the server before storing an API key"
            )
    return await repo.upsert_provider_config(
        session,
        principal.tenant,
        name=name,
        kind=body.kind,
        model=body.model,
        enabled=body.enabled,
        priority=body.priority,
        base_url=body.base_url,
        timeout_seconds=body.timeout_seconds,
        options=body.options,
        cipher=request.app.state.cipher,
        **kwargs,
    )


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(name: str, session: SessionDep, principal: PrincipalDep) -> Response:
    if not await repo.delete_provider_config(session, principal.tenant, name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"provider {name!r} not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{name}/test", response_model=ProviderTestResult)
async def test_provider(name: str, request: Request, session: SessionDep, principal: PrincipalDep):
    """One tiny completion against this provider alone (no pool, no failover)."""
    outcome = await services.test_provider(session, principal, name, request.app.state.cipher)
    return ProviderTestResult(**outcome.model_dump())
