"""LLMPool: an ordered set of providers with retry, failover and cooldown.

Policy (driven by the error class, see ``llm.provider``):

- ``TransientProviderError`` → retry the same provider with exponential backoff
  up to ``max_retries`` times, then fail over to the next one.
- ``ProviderConfigError`` → fail over immediately (retrying won't fix a bad key).
- ``InvalidRequestError`` → raise immediately (the request is our bug).

A provider that exhausted its attempts is put in cooldown, so later turns of a
long agent run go straight to the healthy provider instead of re-paying the
retries. If every provider is cooling down they are all tried anyway — a pool
never refuses to make an attempt.

The pool itself satisfies ``LLMProvider``, so the engine can't tell a single
provider from a pool.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from llm.provider import (
    AllProvidersFailed,
    LLMProvider,
    LLMResponse,
    Message,
    ProviderConfigError,
    ProviderError,
    ToolSpec,
)


@dataclass(frozen=True)
class FailoverEvent:
    """Emitted when a provider gives up and the pool moves on."""

    from_provider: str
    to_provider: str | None  # None: nothing left to try
    error: ProviderError


FailoverCallback = Callable[[FailoverEvent], Awaitable[None] | None]


class LLMPool:
    def __init__(
        self,
        providers: list[LLMProvider],
        *,
        max_retries: int = 2,
        backoff_base: float = 1.0,
        backoff_max: float = 20.0,
        cooldown_seconds: float = 60.0,
        on_failover: FailoverCallback | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not providers:
            raise ValueError("LLMPool needs at least one provider")
        names = [p.name for p in providers]
        if len(set(names)) != len(names):
            raise ValueError(f"duplicate provider names in pool: {names}")
        self.providers = list(providers)
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.cooldown_seconds = cooldown_seconds
        self.on_failover = on_failover
        self._sleep = sleep
        self._clock = clock
        self._down_until: dict[str, float] = {}

    # LLMProvider surface -------------------------------------------------------
    name = "pool"

    @property
    def model(self) -> str:
        return self.providers[0].model

    def is_cooling_down(self, provider_name: str) -> bool:
        return self._down_until.get(provider_name, 0.0) > self._clock()

    def _ordered(self) -> list[LLMProvider]:
        """Healthy providers first (in configured order), cooling-down ones last."""
        healthy = [p for p in self.providers if not self.is_cooling_down(p.name)]
        cooling = [p for p in self.providers if self.is_cooling_down(p.name)]
        return healthy + cooling

    def _backoff(self, attempt: int) -> float:
        return min(self.backoff_max, self.backoff_base * (2**attempt))

    async def _notify(self, event: FailoverEvent) -> None:
        if self.on_failover is None:
            return
        result = self.on_failover(event)
        if result is not None:
            await result

    async def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        tools: list[ToolSpec] | None = None,
        max_tokens: int = 4096,
        temperature: float | None = None,
    ) -> LLMResponse:
        errors: list[ProviderError] = []
        order = self._ordered()
        for idx, provider in enumerate(order):
            attempt = 0
            while True:
                try:
                    resp = await provider.complete(
                        messages, system=system, tools=tools, max_tokens=max_tokens, temperature=temperature
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as raw:  # noqa: BLE001
                    # A provider bug (non-ProviderError) is treated as "this provider
                    # can't serve us": fail over, never take the whole pool down.
                    exc = (
                        raw
                        if isinstance(raw, ProviderError)
                        else ProviderConfigError(f"unexpected {type(raw).__name__}: {raw}", provider=provider.name)
                    )
                    if not exc.provider:
                        exc.provider = provider.name
                    if not exc.failover:
                        raise  # only real ProviderErrors can be non-failover, so exc is raw
                    if exc.retryable and attempt < self.max_retries:
                        await self._sleep(self._backoff(attempt))
                        attempt += 1
                        continue
                    errors.append(exc)
                    self._down_until[provider.name] = self._clock() + self.cooldown_seconds
                    nxt = order[idx + 1].name if idx + 1 < len(order) else None
                    await self._notify(FailoverEvent(provider.name, nxt, exc))
                    break
                else:
                    self._down_until.pop(provider.name, None)
                    return resp
        raise AllProvidersFailed(errors)

    async def aclose(self) -> None:
        await asyncio.gather(*(p.aclose() for p in self.providers), return_exceptions=True)
