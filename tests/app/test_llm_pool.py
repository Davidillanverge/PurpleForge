"""LLMPool retry / failover / cooldown with scripted fake providers."""

from __future__ import annotations

import pytest

from llm import (
    AllProvidersFailed,
    InvalidRequestError,
    LLMPool,
    LLMProvider,
    LLMResponse,
    Message,
    ProviderConfigError,
    TransientProviderError,
)
from llm.settings import LLMSettings, build_pool


class FakeProvider:
    """Replays a script: each item is an exception to raise or a reply text."""

    def __init__(self, name: str, script: list):
        self.name = name
        self.model = f"{name}-model"
        self.script = list(script)
        self.calls = 0
        self.closed = False

    async def complete(self, messages, **kwargs):
        self.calls += 1
        item = self.script.pop(0) if self.script else "ok"
        if isinstance(item, Exception):
            raise item
        return LLMResponse(content=item, provider=self.name, model=self.model)

    async def aclose(self):
        self.closed = True


class Harness:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []
        self.events = []

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now

    def pool(self, providers, **kw):
        kw.setdefault("max_retries", 2)
        kw.setdefault("cooldown_seconds", 60.0)
        return LLMPool(providers, sleep=self.sleep, clock=self.clock, on_failover=self.events.append, **kw)


MSGS = [Message.user("hi")]


def test_fake_and_pool_satisfy_protocol():
    assert isinstance(FakeProvider("a", []), LLMProvider)
    assert isinstance(LLMPool([FakeProvider("a", [])]), LLMProvider)


async def test_primary_success_no_failover():
    h = Harness()
    a, b = FakeProvider("a", ["from a"]), FakeProvider("b", [])
    resp = await h.pool([a, b]).complete(MSGS)
    assert resp.provider == "a" and b.calls == 0 and h.events == []


async def test_transient_retries_with_backoff_then_succeeds():
    h = Harness()
    a = FakeProvider("a", [TransientProviderError("429"), TransientProviderError("503"), "finally"])
    resp = await h.pool([a], backoff_base=1.0).complete(MSGS)
    assert resp.content == "finally" and a.calls == 3
    assert h.sleeps == [1.0, 2.0]


async def test_transient_exhausted_fails_over():
    h = Harness()
    a = FakeProvider("a", [TransientProviderError("down")] * 3)
    b = FakeProvider("b", ["from b"])
    resp = await h.pool([a, b]).complete(MSGS)
    assert resp.provider == "b" and a.calls == 3
    assert [(e.from_provider, e.to_provider) for e in h.events] == [("a", "b")]
    assert h.events[0].error.provider == "a"  # pool fills in the provider name


async def test_config_error_fails_over_without_retry():
    h = Harness()
    a = FakeProvider("a", [ProviderConfigError("bad key")])
    b = FakeProvider("b", ["from b"])
    resp = await h.pool([a, b]).complete(MSGS)
    assert resp.provider == "b" and a.calls == 1 and h.sleeps == []


async def test_invalid_request_raises_immediately():
    h = Harness()
    a = FakeProvider("a", [InvalidRequestError("bad schema")])
    b = FakeProvider("b", ["never"])
    with pytest.raises(InvalidRequestError):
        await h.pool([a, b]).complete(MSGS)
    assert b.calls == 0


async def test_all_failed_collects_errors():
    h = Harness()
    a = FakeProvider("a", [ProviderConfigError("bad key")])
    b = FakeProvider("b", [TransientProviderError("x")] * 3)
    with pytest.raises(AllProvidersFailed) as info:
        await h.pool([a, b]).complete(MSGS)
    assert [e.provider for e in info.value.errors] == ["a", "b"]
    assert h.events[-1].to_provider is None


async def test_cooldown_skips_failed_provider_then_recovers():
    h = Harness()
    a = FakeProvider("a", [ProviderConfigError("blip"), "a is back"])
    b = FakeProvider("b", ["b1", "b2"])
    pool = h.pool([a, b], cooldown_seconds=60.0)

    assert (await pool.complete(MSGS)).provider == "b"
    assert pool.is_cooling_down("a")
    # Second turn: a is cooling down, so b is tried first and a isn't touched.
    assert (await pool.complete(MSGS)).provider == "b"
    assert a.calls == 1
    # After the cooldown a is preferred again.
    h.now += 61
    assert (await pool.complete(MSGS)).content == "a is back"


async def test_all_cooling_down_still_attempts():
    h = Harness()
    a = FakeProvider("a", [ProviderConfigError("x"), "recovered"])
    pool = h.pool([a], cooldown_seconds=60.0)
    with pytest.raises(AllProvidersFailed):
        await pool.complete(MSGS)
    assert (await pool.complete(MSGS)).content == "recovered"


async def test_aclose_closes_all():
    a, b = FakeProvider("a", []), FakeProvider("b", [])
    await LLMPool([a, b]).aclose()
    assert a.closed and b.closed


def test_pool_rejects_empty_and_duplicates():
    with pytest.raises(ValueError):
        LLMPool([])
    with pytest.raises(ValueError):
        LLMPool([FakeProvider("a", []), FakeProvider("a", [])])


# --------------------------------------------------------------------------- settings


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("PF_LLM_PROVIDERS", "ollama, Anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("PF_LLM_OLLAMA_MODEL", "llama3.1:8b")
    s = LLMSettings(_env_file=None)
    assert s.providers == ["ollama", "anthropic"]
    assert s.anthropic_api_key.get_secret_value() == "sk-test"
    pool = build_pool(s)
    assert [p.name for p in pool.providers] == ["ollama", "anthropic"]
    assert pool.providers[0].model == "llama3.1:8b"


def test_build_pool_skips_anthropic_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("PF_LLM_ANTHROPIC_API_KEY", raising=False)
    pool = build_pool(LLMSettings(_env_file=None))
    assert [p.name for p in pool.providers] == ["ollama"]


def test_settings_rejects_unknown_provider(monkeypatch):
    monkeypatch.setenv("PF_LLM_PROVIDERS", "anthropic,gpt")
    with pytest.raises(ValueError):
        LLMSettings(_env_file=None)


async def test_unexpected_provider_exception_still_fails_over():
    """Regression: a provider raising a non-ProviderError (e.g. the Anthropic SDK's
    TypeError when no credentials are set) must not take the whole pool down."""
    h = Harness()
    a = FakeProvider("a", [TypeError("Could not resolve authentication method")])
    b = FakeProvider("b", ["from b"])
    resp = await h.pool([a, b]).complete(MSGS)
    assert resp.provider == "b" and a.calls == 1 and h.sleeps == []
    assert isinstance(h.events[0].error, ProviderConfigError) and "TypeError" in str(h.events[0].error)


async def test_pool_honours_provider_retry_after():
    """Regression (live, Gemini free tier 15 RPM): 1-2 s backoff isn't enough for a
    per-minute quota — wait what the provider asked for, then retry the same provider."""
    h = Harness()
    a = FakeProvider("a", [TransientProviderError("429 quota", retry_after=34.0), "after the wait"])
    b = FakeProvider("b", ["never"])
    resp = await h.pool([a, b], backoff_base=1.0).complete(MSGS)
    assert resp.content == "after the wait" and h.sleeps == [34.0] and b.calls == 0


async def test_pool_fails_over_when_asked_to_wait_too_long():
    h = Harness()
    a = FakeProvider("a", [TransientProviderError("429 daily quota", retry_after=3600.0)])
    b = FakeProvider("b", ["from b"])
    resp = await h.pool([a, b], max_retry_after=120.0).complete(MSGS)
    assert resp.provider == "b" and h.sleeps == []
