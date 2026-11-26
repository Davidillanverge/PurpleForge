"""Migrations match the models and round-trip."""

from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from db.base import Base
from db.migrate import downgrade, upgrade_head


async def test_migrations_match_models(engine):
    def diff(conn):
        mc = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(mc, Base.metadata)

    async with engine.connect() as conn:
        assert await conn.run_sync(diff) == []


async def test_every_table_has_tenant_id(engine):
    def tables(conn):
        insp = inspect(conn)
        return {t: [c["name"] for c in insp.get_columns(t)] for t in insp.get_table_names() if t != "alembic_version"}

    async with engine.connect() as conn:
        cols = await conn.run_sync(tables)
    assert set(cols) == {"labs", "lab_transitions", "agent_runs", "agent_events", "approvals", "provider_configs"}
    for table, names in cols.items():
        assert "tenant_id" in names, table


async def test_downgrade_and_reupgrade(engine):
    await downgrade(engine, "base")

    def names(conn):
        return set(inspect(conn).get_table_names()) - {"alembic_version"}

    async with engine.connect() as conn:
        assert await conn.run_sync(names) == set()
    await upgrade_head(engine)
    async with engine.connect() as conn:
        assert "labs" in await conn.run_sync(names)
