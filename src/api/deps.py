"""FastAPI dependencies: settings, DB session, principal, runner."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import Principal, authenticate
from api.broker import EventBroker
from api.runner import AgentRunner
from api.settings import AppSettings


def get_settings(request: Request) -> AppSettings:
    return request.app.state.settings


def get_runner(request: Request) -> AgentRunner:
    return request.app.state.runner


def get_broker(request: Request) -> EventBroker:
    return request.app.state.broker


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One transaction per request: committed if the handler returns, rolled back if it raises."""
    async with request.app.state.sessionmaker() as session, session.begin():
        yield session


def get_principal(request: Request, settings: Annotated[AppSettings, Depends(get_settings)]) -> Principal:
    return authenticate(request, settings)


SettingsDep = Annotated[AppSettings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
PrincipalDep = Annotated[Principal, Depends(get_principal)]
RunnerDep = Annotated[AgentRunner, Depends(get_runner)]
BrokerDep = Annotated[EventBroker, Depends(get_broker)]
