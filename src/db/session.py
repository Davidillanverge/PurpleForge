"""Async engine / session factory (SQLAlchemy 2.0 + asyncpg)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from db.settings import DatabaseSettings


def create_engine(url: str | None = None, *, settings: DatabaseSettings | None = None, **kwargs: Any) -> AsyncEngine:
    settings = settings or DatabaseSettings()
    url = url or settings.database_url
    if url.startswith("sqlite"):
        engine = create_async_engine(url, echo=settings.database_echo, **kwargs)

        @event.listens_for(engine.sync_engine, "connect")
        def _fk_on(dbapi_conn: Any, _record: Any) -> None:  # SQLite ignores FKs unless asked
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    return create_async_engine(
        url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_pre_ping=True,
        **kwargs,
    )


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False: objects stay readable after commit (async can't lazy-reload).
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def transaction(sessionmaker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    """One session, committed on success, rolled back on error."""
    async with sessionmaker() as session, session.begin():
        yield session
