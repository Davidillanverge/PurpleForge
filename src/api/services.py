"""Lab use-cases shared by the JSON API and the HTML UI.

One implementation of each rule, so the UI can never be laxer than the API.
Functions raise domain exceptions; api.app maps them to HTTP (JSON for /api,
a flash message for htmx UI requests).
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import Principal
from api.forge_ops import ForgeStep, SpecError, compile_and_guardrail, resolve_spec
from api.settings import AppSettings
from db import repository as repo
from db.crypto import SecretCipher
from db.models import Lab
from db.states import LabState
from llm.provider import Message, ProviderError

__all__ = ["SpecError"]

#: States a human may request directly. Everything else is driven by forge
#: results or agent runs — nobody can hand-mark a lab READY without a guardrail
#: PASS, or DEPLOYED without a deploy.
USER_TRANSITIONS = frozenset({LabState.DESIGNED, LabState.APPROVED})
EDITABLE_STATES = frozenset(
    {LabState.DRAFT, LabState.DESIGNED, LabState.COMPILED, LabState.READY, LabState.APPROVED, LabState.DESTROYED}
)
COMPILABLE_STATES = frozenset({LabState.DESIGNED, LabState.COMPILED, LabState.READY, LabState.APPROVED})


class LabExists(RuntimeError):
    pass


class LabNotEditable(RuntimeError):
    pass


class ManualTransitionForbidden(PermissionError):
    pass


class CompileOutcome(BaseModel):
    steps: list[ForgeStep]
    ok: bool


async def create_lab(
    session: AsyncSession,
    principal: Principal,
    settings: AppSettings,
    *,
    name: str,
    description: str = "",
    spec_path: str | None = None,
) -> Lab:
    if await repo.get_lab_by_name(session, principal.tenant, name):
        raise LabExists(f"lab {name!r} already exists")
    default = f"specs/{name}.yml"
    if not spec_path and (settings.repo_root / default).is_file():
        spec_path = default
    data = None
    if spec_path:
        _, data = resolve_spec(settings.repo_root, spec_path, name)
    lab = await repo.create_lab(
        session,
        principal.tenant,
        name=name,
        description=description,
        spec_path=spec_path or None,
        cloud=(data or {}).get("lab", {}).get("provider"),
        actor=principal.actor,
    )
    if data is not None:
        await repo.transition_lab(
            session, principal.tenant, lab, LabState.DESIGNED, actor=principal.actor, reason=f"spec {spec_path}"
        )
    return lab


async def update_lab(
    session: AsyncSession,
    principal: Principal,
    settings: AppSettings,
    lab_id: uuid.UUID,
    *,
    description: str | None = None,
    spec_path: str | None = None,
) -> Lab:
    lab = await repo.get_lab(session, principal.tenant, lab_id, for_update=True)
    if description is not None:
        lab.description = description
    if spec_path is not None and spec_path != lab.spec_path:
        if lab.state not in EDITABLE_STATES:
            raise LabNotEditable(f"can't change the spec of a lab that is {lab.state.value}")
        _, data = resolve_spec(settings.repo_root, spec_path, lab.name)
        lab.spec_path = spec_path
        lab.cloud = data.get("lab", {}).get("provider")
        # a new spec invalidates compile / guardrail / approval
        await repo.transition_lab(
            session,
            principal.tenant,
            lab,
            LabState.DESIGNED,
            actor=principal.actor,
            reason=f"spec changed to {spec_path}",
        )
    await session.flush()
    return lab


async def user_transition(
    session: AsyncSession, principal: Principal, lab_id: uuid.UUID, target: LabState, *, reason: str = ""
) -> Lab:
    """Approve a READY lab for deploy (the human gate) or send a lab back to DESIGNED."""
    if target not in USER_TRANSITIONS:
        allowed = ", ".join(sorted(s.value for s in USER_TRANSITIONS))
        raise ManualTransitionForbidden(
            f"{target.value} is set by forge/agents, not by hand (manual targets: {allowed})"
        )
    lab = await repo.get_lab(session, principal.tenant, lab_id, for_update=True)
    await repo.transition_lab(session, principal.tenant, lab, target, actor=principal.actor, reason=reason)
    return lab


async def delete_lab(session: AsyncSession, principal: Principal, lab_id: uuid.UUID) -> None:
    lab = await repo.get_lab(session, principal.tenant, lab_id, for_update=True)
    await repo.delete_lab(session, principal.tenant, lab)


async def compile_lab(
    session: AsyncSession, principal: Principal, settings: AppSettings, lab_id: uuid.UUID
) -> tuple[Lab, CompileOutcome]:
    """``forge lab-spec`` + ``forge guardrail``: DESIGNED → COMPILED → READY.

    Re-compiling a COMPILED/READY/APPROVED lab first drops it back to DESIGNED,
    so an approval never survives a recompile. A failing step leaves the lab at
    the last state it legitimately reached; forge's output is returned.
    The lab row stays locked while forge runs, serialising concurrent compiles.
    """
    lab = await repo.get_lab(session, principal.tenant, lab_id, for_update=True)
    if lab.state not in COMPILABLE_STATES:
        raise LabNotEditable(f"can't compile a lab that is {lab.state.value}")
    if not lab.spec_path:
        raise SpecError("lab has no spec_path")
    spec, _ = resolve_spec(settings.repo_root, lab.spec_path, lab.name)

    if lab.state is not LabState.DESIGNED:
        await repo.transition_lab(
            session, principal.tenant, lab, LabState.DESIGNED, actor=principal.actor, reason="recompile requested"
        )
    steps = await compile_and_guardrail(settings.repo_root, spec, lab.name, timeout=settings.forge_timeout_seconds)
    if steps[0].ok:
        await repo.transition_lab(
            session, principal.tenant, lab, LabState.COMPILED, actor="system", reason="forge lab-spec OK"
        )
        if len(steps) > 1 and steps[1].ok:
            await repo.transition_lab(
                session,
                principal.tenant,
                lab,
                LabState.READY,
                actor="system",
                reason="forge guardrail PASS — awaiting human approval",
            )
    return lab, CompileOutcome(steps=steps, ok=all(s.ok for s in steps))


class ProviderTestOutcome(BaseModel):
    ok: bool
    provider: str
    model: str | None = None
    latency_ms: int | None = None
    error: str | None = None


async def test_provider(
    session: AsyncSession, principal: Principal, name: str, cipher: SecretCipher | None
) -> ProviderTestOutcome:
    """One tiny completion against this provider alone (no pool, no failover)."""
    cfg = await repo.get_provider_config(session, principal.tenant, name)
    try:
        provider = repo.provider_from_config(cfg, cipher)
    except ValueError as exc:
        return ProviderTestOutcome(ok=False, provider=name, error=str(exc))
    started = time.monotonic()
    try:
        resp = await provider.complete([Message.user("Reply with the single word: pong")], max_tokens=16)
        return ProviderTestOutcome(
            ok=True, provider=name, model=resp.model, latency_ms=int((time.monotonic() - started) * 1000)
        )
    except ProviderError as exc:
        return ProviderTestOutcome(ok=False, provider=name, error=str(exc))
    finally:
        await provider.aclose()


def load_manifest_summary(repo_root: Path, lab_name: str) -> dict[str, Any] | None:
    """What a human needs to see before approving a deploy: cost, isolation,
    machines, vulns, reconciliation — straight from forge's lab-manifest.json."""
    path = repo_root / "generated" / lab_name / "lab-manifest.json"
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    lab = m.get("lab") or {}
    recon = m.get("reconciliation") or {}
    if not isinstance(m, dict) or not lab or not m.get("cost_estimate"):
        # not a forge lab-spec manifest (or a partial one): don't show made-up values
        return {
            "incomplete": True,
            "path": str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path),
        }
    return {
        "incomplete": False,
        "provider": lab.get("provider"),
        "region": lab.get("region"),
        "isolation": lab.get("isolation"),
        "auto_shutdown": lab.get("auto_shutdown"),
        "cost": m.get("cost_estimate") or {},
        "machines": [x for x in m.get("machines") or [] if isinstance(x, dict)],
        "vulns": [v if isinstance(v, str) else str(v.get("id")) for v in m.get("vulnerabilities") or []],
        "reconciliation": {
            "on_conflict": recon.get("on_conflict"),
            "excluded_controls": recon.get("excluded_controls") or [],
            "warnings": recon.get("warnings") or [],
        },
    }
