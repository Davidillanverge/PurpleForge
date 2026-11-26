"""Declarative base, portable column types and the tenant mixin.

Postgres (asyncpg) is the target; SQLite (aiosqlite) must also work so the test
suite runs without a database server. Hence: generic ``Uuid``, JSON that
becomes JSONB on Postgres, non-native enums (plain VARCHAR — adding a state is
not a migration), and a tz-aware datetime that survives SQLite's naive storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Integer, MetaData, String, TypeDecorator, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

#: Tenant used while the product is single-tenant. Every row still carries it,
#: so going SaaS is a data migration, not a schema one.
DEFAULT_TENANT = "default"

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JSONType = JSON().with_variant(JSONB(), "postgresql")
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")  # SQLite autoincrements INTEGER PKs only


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator[datetime]):
    """Always stores/returns aware UTC datetimes (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime not allowed; use timezone-aware UTC")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: dict[Any, Any] = {
        datetime: UTCDateTime(),
        dict[str, Any]: JSONType,
        uuid.UUID: Uuid(),
    }


class TenantMixin:
    # No default on purpose: every write must name its tenant explicitly, so a
    # forgotten scope fails loudly (NOT NULL) instead of landing in "default".
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
