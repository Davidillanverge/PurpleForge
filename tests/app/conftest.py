"""DB fixtures: a fresh migrated database per test.

SQLite by default (no server). Set PF_TEST_DATABASE_URL to a throwaway Postgres
(postgresql+asyncpg://...) to run the same tests against the real target.
"""

from __future__ import annotations

import os

import pytest

from db.migrate import downgrade, upgrade_head
from db.session import create_engine, create_sessionmaker


@pytest.fixture
async def engine(tmp_path):
    url = os.environ.get("PF_TEST_DATABASE_URL") or f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    eng = create_engine(url)
    await upgrade_head(eng)  # the real migrations, not create_all
    try:
        yield eng
    finally:
        if url.startswith("postgresql"):
            await downgrade(eng, "base")
        await eng.dispose()


@pytest.fixture
def sessionmaker(engine):
    return create_sessionmaker(engine)


@pytest.fixture
async def session(sessionmaker):
    async with sessionmaker() as s:
        yield s


# App-level fixtures (tmp repo, scripted LLMs, app factory, authed client).
from _appkit import client, llms, make_app, repo_root  # noqa: E402,F401
