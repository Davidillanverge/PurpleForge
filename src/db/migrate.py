"""Programmatic Alembic (app startup auto-migrate, tests)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["configure_logger"] = False  # don't clobber the app's logging
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    return cfg


#: Arbitrary constant: the advisory-lock key every PurpleForge worker migrates under.
MIGRATION_LOCK_KEY = 0x5046_4D49_4752  # "PFMIGR"


async def upgrade_head(engine: AsyncEngine) -> None:
    """``alembic upgrade head`` on an existing async engine (safe inside a running loop).

    On Postgres it runs under a transaction-scoped advisory lock, so N workers
    (or replicas) starting at once with PF_AUTO_MIGRATE=true migrate exactly once:
    the first takes the lock and upgrades, the rest wait and then find nothing to do.
    """

    def _run(connection: Connection) -> None:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")

    async with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": MIGRATION_LOCK_KEY})
        await conn.run_sync(_run)


async def downgrade(engine: AsyncEngine, revision: str = "base") -> None:
    def _run(connection: Connection) -> None:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, revision)

    async with engine.begin() as conn:
        await conn.run_sync(_run)
