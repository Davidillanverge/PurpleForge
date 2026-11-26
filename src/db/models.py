"""ORM models. Every table carries ``tenant_id`` (see db.base.TenantMixin)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, BigIntPK, TenantMixin, TimestampMixin, utcnow
from db.states import ApprovalStatus, LabState, ProviderKind, RunState


def _enum(cls: type[Enum], length: int = 32) -> SAEnum:
    # VARCHAR, not a native PG enum: new states don't need ALTER TYPE.
    return SAEnum(
        cls, native_enum=False, length=length, values_callable=lambda e: [m.value for m in e], validate_strings=True
    )


class Lab(TenantMixin, TimestampMixin, Base):
    __tablename__ = "labs"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    #: specs/<name>.yml, relative to the repo root (specs/ stays the source of truth)
    spec_path: Mapped[str | None] = mapped_column(String(512))
    #: azure | aws | proxmox, once known from the spec
    cloud: Mapped[str | None] = mapped_column(String(16))
    state: Mapped[LabState] = mapped_column(_enum(LabState), default=LabState.DRAFT, index=True)
    state_changed_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_error: Mapped[str | None] = mapped_column(Text)

    transitions: Mapped[list[LabTransition]] = relationship(
        back_populates="lab", cascade="all, delete-orphan", order_by="LabTransition.id"
    )
    runs: Mapped[list[AgentRun]] = relationship(back_populates="lab", order_by="AgentRun.created_at")


class LabTransition(TenantMixin, Base):
    """Append-only state history — the lab detail timeline."""

    __tablename__ = "lab_transitions"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    lab_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("labs.id", ondelete="CASCADE"), index=True)
    from_state: Mapped[LabState | None] = mapped_column(_enum(LabState))
    to_state: Mapped[LabState] = mapped_column(_enum(LabState))
    actor: Mapped[str] = mapped_column(String(128))  # "user:<id>", "agent:<name>", "system"
    reason: Mapped[str] = mapped_column(Text, default="")
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_runs.id", ondelete="SET NULL"))
    at: Mapped[datetime] = mapped_column(default=utcnow)

    lab: Mapped[Lab] = relationship(back_populates="transitions")


class AgentRun(TenantMixin, Base):
    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    lab_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("labs.id", ondelete="SET NULL"), index=True)
    agent: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[RunState] = mapped_column(_enum(RunState), default=RunState.QUEUED, index=True)
    task: Mapped[str] = mapped_column(Text)
    output: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    turns: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(128))
    #: API worker process that executes this run (runs live in-process); orphan
    #: recovery only fails runs whose worker is no longer alive.
    worker_id: Mapped[str | None] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()

    lab: Mapped[Lab | None] = relationship(back_populates="runs")
    events: Mapped[list[AgentEvent]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="AgentEvent.seq"
    )
    approvals: Mapped[list[Approval]] = relationship(back_populates="run", cascade="all, delete-orphan")


class AgentEvent(TenantMixin, Base):
    """Persisted copy of agents.events.AgentEvent (SSE replay + audit)."""

    __tablename__ = "agent_events"
    __table_args__ = (UniqueConstraint("run_id", "seq"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(32), index=True)
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    ts: Mapped[datetime] = mapped_column(default=utcnow)

    run: Mapped[AgentRun] = relationship(back_populates="events")


class Approval(TenantMixin, Base):
    """A human decision on one gated tool call (deploy-operator's gate)."""

    __tablename__ = "approvals"
    __table_args__ = (
        UniqueConstraint("run_id", "tool_call_id"),
        Index("ix_approvals_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"), index=True)
    lab_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("labs.id", ondelete="SET NULL"))
    tool_call_id: Mapped[str] = mapped_column(String(128))
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[ApprovalStatus] = mapped_column(_enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    decided_by: Mapped[str | None] = mapped_column(String(128))
    comment: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column()

    run: Mapped[AgentRun] = relationship(back_populates="approvals")


class ProviderConfig(TenantMixin, TimestampMixin, Base):
    """Per-tenant LLM provider settings; overrides the PF_LLM_* env defaults."""

    __tablename__ = "provider_configs"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64))  # pool name, unique per tenant
    kind: Mapped[ProviderKind] = mapped_column(_enum(ProviderKind, 16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)  # lower = tried first
    model: Mapped[str] = mapped_column(String(128))
    base_url: Mapped[str | None] = mapped_column(String(512))
    timeout_seconds: Mapped[float | None] = mapped_column(Float)
    #: Fernet token (db.crypto); never the plaintext key
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    options: Mapped[dict[str, Any]] = mapped_column(default=dict)

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key_encrypted)
