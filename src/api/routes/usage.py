"""Token usage: tenant total, per agent and per lab."""

from __future__ import annotations

from fastapi import APIRouter

from api.deps import PrincipalDep, SessionDep
from api.schemas import UsageOut, UsageReport
from db import repository as repo

router = APIRouter(prefix="/api/usage", tags=["usage"])


@router.get("", response_model=UsageReport)
async def usage(session: SessionDep, principal: PrincipalDep) -> UsageReport:
    total = await repo.usage_total(session, principal.tenant)
    by_lab = await repo.usage_by_lab(session, principal.tenant)
    names = await repo.lab_names(session, principal.tenant, by_lab)
    labs_in = sum(u.input_tokens for u in by_lab.values())
    labs_out = sum(u.output_tokens for u in by_lab.values())
    labs_runs = sum(u.runs for u in by_lab.values())
    return UsageReport(
        total=UsageOut.of(total),
        by_agent={a: UsageOut.of(u) for a, u in (await repo.usage_by_agent(session, principal.tenant)).items()},
        # a deleted lab's runs keep their tokens (lab_id → NULL), so they count under "without_lab"
        by_lab={names.get(lab_id, str(lab_id)): UsageOut.of(u) for lab_id, u in by_lab.items()},
        without_lab=UsageOut.of(
            repo.Usage(total.input_tokens - labs_in, total.output_tokens - labs_out, total.runs - labs_runs)
        ),
    )
