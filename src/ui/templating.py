"""Jinja2 environment for the UI: filters and the state → colour mapping.

Autoescape is on for every template: agent output and tool results are
untrusted text and are only ever rendered as escaped text (never as HTML or
markdown).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates

from db.states import INFRA_STATES, ApprovalStatus, LabState, RunState

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Tailwind scans this file (@source), so these class strings end up in app.css.
LAB_STATE_CLASSES: dict[str, str] = {
    LabState.DRAFT: "border-zinc-600 text-zinc-400",
    LabState.DESIGNING: "border-sky-500/80 text-sky-200 animate-pulse",
    LabState.DESIGNED: "border-sky-600/70 text-sky-300",
    LabState.COMPILED: "border-cyan-600/70 text-cyan-300",
    LabState.READY: "border-amber-500/80 text-amber-300",
    LabState.APPROVED: "border-violet-500/80 text-violet-300",
    LabState.DEPLOYING: "border-orange-500/80 text-orange-300 animate-pulse",
    LabState.DEPLOYED: "border-green-600/80 text-green-300",
    LabState.VALIDATING: "border-cyan-500/80 text-cyan-200 animate-pulse",
    LabState.VALIDATED: "border-emerald-500/80 text-emerald-300",
    LabState.STOPPED: "border-zinc-500 text-zinc-300",
    LabState.DESTROYING: "border-red-500/80 text-red-300 animate-pulse",
    LabState.DESTROYED: "border-zinc-700 text-zinc-500",
    LabState.FAILED: "border-red-600 text-red-300",
}
RUN_STATE_CLASSES: dict[str, str] = {
    RunState.QUEUED: "border-zinc-600 text-zinc-400",
    RunState.RUNNING: "border-cyan-500/80 text-cyan-200 animate-pulse",
    RunState.WAITING_APPROVAL: "border-amber-500/80 text-amber-300 animate-pulse",
    RunState.COMPLETED: "border-green-600/80 text-green-300",
    RunState.BUDGET_EXCEEDED: "border-orange-500/80 text-orange-300",
    RunState.REFUSED: "border-orange-500/80 text-orange-300",
    RunState.FAILED: "border-red-600 text-red-300",
    RunState.CANCELLED: "border-zinc-500 text-zinc-400",
}
APPROVAL_CLASSES: dict[str, str] = {
    ApprovalStatus.PENDING: "border-amber-500/80 text-amber-300",
    ApprovalStatus.APPROVED: "border-green-600/80 text-green-300",
    ApprovalStatus.DENIED: "border-red-600 text-red-300",
    ApprovalStatus.EXPIRED: "border-zinc-500 text-zinc-400",
}


def _key(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def state_class(value: Any) -> str:
    k = _key(value)
    for table in (LAB_STATE_CLASSES, RUN_STATE_CLASSES, APPROVAL_CLASSES):
        for state, cls in table.items():
            if _key(state) == k:
                return cls
    return "border-zinc-600 text-zinc-400"


def approval_class(value: Any) -> str:
    """Separate from state_class: "approved" is also a lab state (violet), but an
    approved *decision* must read as green."""
    k = _key(value)
    return next((cls for st, cls in APPROVAL_CLASSES.items() if _key(st) == k), "border-zinc-600 text-zinc-400")


def fmt_dt(value: datetime | str | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        raw = value
        try:
            value = datetime.fromisoformat(raw)
        except ValueError:
            return raw
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def ago(value: datetime | None) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    secs = int((datetime.now(timezone.utc) - value).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return f"{max(secs, 0)}s ago"


def tok(value: int | None) -> str:
    """1234 → '1.2k', 2_345_678 → '2.35M' (exact count goes in a title attribute)."""
    n = int(value or 0)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 10_000:
        return f"{n / 1000:.0f}k"
    if n >= 1_000:
        return f"{n / 1000:.1f}k"
    return str(n)


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str, sort_keys=True)


def duration(start: datetime | None, end: datetime | None) -> str:
    if start is None:
        return "—"
    end = end or datetime.now(timezone.utc)
    secs = int((end - start).total_seconds())
    return f"{secs // 60}m{secs % 60:02d}s" if secs >= 60 else f"{secs}s"


def build_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    env = templates.env
    env.filters.update(
        state_class=state_class,
        approval_class=approval_class,
        tok=tok,
        dt=fmt_dt,
        ago=ago,
        pretty_json=pretty_json,
        duration=duration,
    )
    env.globals.update(INFRA_STATES=INFRA_STATES, LabState=LabState, RunState=RunState)
    env.trim_blocks = True
    env.lstrip_blocks = True
    return templates
