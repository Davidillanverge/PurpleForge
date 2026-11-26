"""Labs: CRUD, FSM transitions, deterministic compile + guardrail (rules in api.services)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from api import services
from api.deps import PrincipalDep, SessionDep, SettingsDep
from api.schemas import (
    CompileResult,
    GenerateResult,
    LabCreate,
    LabDetail,
    LabOut,
    LabTransitionOut,
    LabTransitionRequest,
    LabUpdate,
    RunOut,
    UsageOut,
)
from db import repository as repo
from db.states import LabState

router = APIRouter(prefix="/api/labs", tags=["labs"])


@router.get("", response_model=list[LabOut])
async def list_labs(session: SessionDep, principal: PrincipalDep, state: list[LabState] | None = None):
    labs = await repo.list_labs(session, principal.tenant, states=state)
    usage = await repo.usage_by_lab(session, principal.tenant)
    out = []
    for lab in labs:
        item = LabOut.model_validate(lab)
        if lab.id in usage:
            item.usage = UsageOut.of(usage[lab.id])
        out.append(item)
    return out


@router.post("", response_model=LabDetail, status_code=status.HTTP_201_CREATED)
async def create_lab(body: LabCreate, session: SessionDep, principal: PrincipalDep, settings: SettingsDep):
    lab = await services.create_lab(
        session, principal, settings, name=body.name, description=body.description, spec_path=body.spec_path
    )
    return await _detail(session, principal.tenant, lab.id)


@router.get("/{lab_id}", response_model=LabDetail)
async def get_lab(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep):
    return await _detail(session, principal.tenant, lab_id)


@router.patch("/{lab_id}", response_model=LabDetail)
async def update_lab(
    lab_id: uuid.UUID, body: LabUpdate, session: SessionDep, principal: PrincipalDep, settings: SettingsDep
):
    lab = await services.update_lab(
        session, principal, settings, lab_id, description=body.description, spec_path=body.spec_path
    )
    return await _detail(session, principal.tenant, lab.id)


@router.delete("/{lab_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_lab(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep) -> Response:
    await services.delete_lab(session, principal, lab_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{lab_id}/transitions", response_model=LabDetail)
async def transition(lab_id: uuid.UUID, body: LabTransitionRequest, session: SessionDep, principal: PrincipalDep):
    """Human-driven transitions only: approve a READY lab (the deploy gate) or back to DESIGNED."""
    lab = await services.user_transition(session, principal, lab_id, body.to, reason=body.reason)
    return await _detail(session, principal.tenant, lab.id)


@router.post("/{lab_id}/compile", response_model=CompileResult)
async def compile_lab(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep, settings: SettingsDep):
    """``forge lab-spec`` + ``forge guardrail``: DESIGNED → COMPILED → READY (see services.compile_lab)."""
    lab, outcome = await services.compile_lab(session, principal, settings, lab_id)
    return CompileResult(lab=LabOut.model_validate(lab), steps=outcome.steps, ok=outcome.ok)


@router.post("/{lab_id}/check", response_model=CompileResult)
async def check_lab(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep, settings: SettingsDep):
    """``forge lab-spec --check-only``: validate without writing anything or moving the lab."""
    lab, outcome = await services.check_lab(session, principal, settings, lab_id)
    return CompileResult(lab=LabOut.model_validate(lab), steps=outcome.steps, ok=outcome.ok)


@router.post("/{lab_id}/generate", response_model=GenerateResult)
async def generate_lab(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep, settings: SettingsDep):
    """``forge generate``: render Terraform + Ansible + lifecycle scripts into generated/<lab>/.
    Cloud-free and deterministic; the lab's state is unchanged."""
    lab, outcome = await services.generate_lab(session, principal, settings, lab_id)
    return GenerateResult(
        lab=LabOut.model_validate(lab), steps=outcome.steps, ok=outcome.ok, out_dir=outcome.out_dir, files=outcome.files
    )


@router.get("/{lab_id}/transitions", response_model=list[LabTransitionOut])
async def list_transitions(lab_id: uuid.UUID, session: SessionDep, principal: PrincipalDep):
    await repo.get_lab(session, principal.tenant, lab_id)
    return await repo.list_transitions(session, principal.tenant, lab_id)


async def _detail(session, tenant: str, lab_id: uuid.UUID) -> LabDetail:
    lab = await repo.get_lab(session, tenant, lab_id)
    transitions = await repo.list_transitions(session, tenant, lab_id)
    runs = await repo.list_runs(session, tenant, lab_id=lab_id)
    out = LabDetail.model_validate({**LabOut.model_validate(lab).model_dump(), "transitions": [], "runs": []})
    out.transitions = [LabTransitionOut.model_validate(t) for t in transitions]
    out.runs = [RunOut.model_validate(r) for r in runs]
    out.usage = UsageOut.of(await repo.usage_total(session, tenant, lab_id=lab_id))
    out.usage_by_agent = {
        a: UsageOut.of(u) for a, u in (await repo.usage_by_agent(session, tenant, lab_id=lab_id)).items()
    }
    return out
