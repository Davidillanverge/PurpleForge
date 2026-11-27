"""Per-tenant deploy-time integrations (api.integrations). Secrets are write-only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from api import integrations
from api.deps import PrincipalDep, SessionDep
from db import repository as repo

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


class IntegrationIn(BaseModel):
    enabled: bool = True
    #: every non-secret field; missing/empty = unset (falls back to .env)
    values: dict[str, str] = Field(default_factory=dict)
    #: only the secrets being replaced; never echoed back
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list)


def _out(row: integrations.IntegrationStatus) -> dict[str, Any]:
    i = row.integration
    return {
        "name": i.name,
        "label": i.label,
        "group": i.group,
        "description": i.description,
        "enabled": row.enabled,
        "saved": row.config is not None,
        "fields": [
            {
                "env": f.field.path_env or f.field.env,
                "field": f.field.env,
                "label": f.field.label,
                "secret": f.field.secret,
                "kind": f.field.kind,
                "source": f.source,
                **({} if f.field.secret and f.field.kind != "file" else {"value": f.value}),
            }
            for f in row.fields
        ],
    }


@router.get("")
async def list_integrations(session: SessionDep, principal: PrincipalDep) -> list[dict[str, Any]]:
    return [_out(r) for r in integrations.status(await repo.list_integration_configs(session, principal.tenant))]


@router.put("/{name}")
async def put_integration(
    name: str, body: IntegrationIn, request: Request, session: SessionDep, principal: PrincipalDep
) -> dict[str, Any]:
    try:
        await integrations.save(
            session,
            principal.tenant,
            name,
            enabled=body.enabled,
            values=body.values,
            secrets=body.secrets,
            clear_secrets=body.clear_secrets,
            cipher=request.app.state.cipher,
        )
    except integrations.IntegrationInputError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    rows = integrations.status(await repo.list_integration_configs(session, principal.tenant))
    return _out(next(r for r in rows if r.integration.name == name))


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(name: str, session: SessionDep, principal: PrincipalDep) -> Response:
    if not await repo.delete_integration_config(session, principal.tenant, name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"integration {name!r} not configured")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{name}/test")
async def test_integration(name: str, request: Request, session: SessionDep, principal: PrincipalDep):
    if name not in integrations.BY_NAME:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown integration {name!r}")
    result = await integrations.run_test(session, principal.tenant, name, request.app.state.cipher)
    return {"ok": result.ok, "message": result.message}
