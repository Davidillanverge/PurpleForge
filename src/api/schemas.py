"""Request/response models. API keys are write-only: never serialized back."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.forge_ops import ForgeStep
from db.states import ApprovalStatus, LabState, ProviderKind, RunState

# Same shape as the spec schema's lab.name: it becomes generated/<name>/ and cloud resource names.
LAB_NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- labs


class LabCreate(BaseModel):
    name: str
    description: str = ""
    spec_path: str | None = Field(default=None, description="specs/<name>.yml; defaults to that if it exists")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not LAB_NAME.match(v):
            raise ValueError("lab name must be lowercase letters, digits and '-', starting with a letter (2-63)")
        return v


class LabUpdate(BaseModel):
    description: str | None = None
    spec_path: str | None = None


class LabTransitionRequest(BaseModel):
    to: LabState
    reason: str = ""


class LabTransitionOut(_ORM):
    id: int
    from_state: LabState | None
    to_state: LabState
    actor: str
    reason: str
    run_id: uuid.UUID | None
    at: datetime


class UsageOut(BaseModel):
    """Tokens consumed by agent runs (thinking tokens count as output)."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    runs: int = 0

    @classmethod
    def of(cls, u: Any) -> UsageOut:
        return cls(input_tokens=u.input_tokens, output_tokens=u.output_tokens, total_tokens=u.total_tokens, runs=u.runs)


class LabOut(_ORM):
    id: uuid.UUID
    name: str
    description: str
    spec_path: str | None
    cloud: str | None
    state: LabState
    state_changed_at: datetime
    last_error: str | None
    created_at: datetime
    updated_at: datetime
    #: tokens of every agent run on this lab
    usage: UsageOut = UsageOut()


class LabDetail(LabOut):
    transitions: list[LabTransitionOut] = []
    runs: list[RunOut] = []
    usage_by_agent: dict[str, UsageOut] = {}


class UsageReport(BaseModel):
    total: UsageOut
    by_agent: dict[str, UsageOut]
    by_lab: dict[str, UsageOut]  # lab name → usage
    without_lab: UsageOut  # e.g. catalog-author runs


class CompileResult(BaseModel):
    lab: LabOut
    steps: list[ForgeStep]
    ok: bool


class GenerateResult(CompileResult):
    out_dir: str | None = None
    files: list[str] = []


# --------------------------------------------------------------------------- runs


class RunCreate(BaseModel):
    agent: str
    lab_id: uuid.UUID | None = None
    instructions: str = Field(default="", max_length=10_000)


class RunOut(_ORM):
    id: uuid.UUID
    lab_id: uuid.UUID | None
    agent: str
    status: RunState
    task: str
    output: str
    error: str | None
    provider: str | None
    model: str | None
    turns: int
    input_tokens: int
    output_tokens: int
    created_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    active: bool = False


class EventOut(_ORM):
    seq: int
    type: str
    data: dict[str, Any]
    ts: datetime


class AgentInfo(BaseModel):
    name: str
    description: str
    requires_lab: bool
    allowed_states: list[LabState]


# --------------------------------------------------------------------------- approvals


class ApprovalOut(_ORM):
    id: uuid.UUID
    run_id: uuid.UUID
    lab_id: uuid.UUID | None
    tool_call_id: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    status: ApprovalStatus
    decided_by: str | None
    comment: str | None
    requested_at: datetime
    decided_at: datetime | None


class ApprovalDecisionIn(BaseModel):
    approved: bool
    comment: str | None = Field(default=None, max_length=2_000)


# --------------------------------------------------------------------------- providers


class ProviderIn(BaseModel):
    kind: ProviderKind
    model: str
    enabled: bool = True
    priority: int = 100
    base_url: str | None = None
    timeout_seconds: float | None = Field(default=None, gt=0)
    options: dict[str, Any] = Field(default_factory=dict)
    #: omitted → keep the stored key; null/"" → clear it; string → replace it
    api_key: str | None = None


class ProviderOut(_ORM):
    id: uuid.UUID
    name: str
    kind: ProviderKind
    model: str
    enabled: bool
    priority: int
    base_url: str | None
    timeout_seconds: float | None
    options: dict[str, Any]
    has_api_key: bool
    created_at: datetime
    updated_at: datetime


class ProviderTestResult(BaseModel):
    ok: bool
    provider: str
    model: str | None = None
    latency_ms: int | None = None
    error: str | None = None


LabDetail.model_rebuild()
