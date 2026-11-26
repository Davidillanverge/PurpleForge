"""Alembic environment (async). URL: ``sqlalchemy.url`` if set on the Config
(tests do this), else PF_DATABASE_URL via DatabaseSettings."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from typing import Any, Literal

import sqlalchemy as sa
from alembic import context
from alembic.autogenerate.api import AutogenContext
from sqlalchemy.engine import Connection

from db.base import Base, UTCDateTime
from db.models import AgentEvent, AgentRun, Approval, Lab, LabTransition, ProviderConfig  # noqa: F401
from db.session import create_engine
from db.settings import DatabaseSettings

config = context.config
if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or DatabaseSettings().database_url


def _render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    """Render app column types as plain SQLAlchemy, so migrations never import
    app code (a later refactor of db.base must not break old revisions)."""
    if type_ != "type":
        return False
    if isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    if isinstance(obj, sa.JSON) and "postgresql" in getattr(obj, "_variant_mapping", {}):
        autogen_context.imports.add("from sqlalchemy.dialects import postgresql")
        return 'sa.JSON().with_variant(postgresql.JSONB(), "postgresql")'
    return False


def _configure(connection: Connection | None = None, **kw: Any) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_item=_render_item,
        render_as_batch=True,  # SQLite ALTER support; harmless on Postgres
        **kw,
    )


def run_migrations_offline() -> None:
    _configure(url=_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(_do_run)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    existing = config.attributes.get("connection")
    if existing is not None:  # called from inside a running loop (app startup / tests)
        _do_run(existing)
    else:
        asyncio.run(run_migrations_online())
