"""LLM configuration (pydantic-settings) and the pool factory.

Env vars use the ``PF_LLM_`` prefix; the Anthropic key also accepts the SDK's
standard ``ANTHROPIC_API_KEY``. Phase 3 adds DB-backed ProviderConfig, which
will override these defaults per tenant.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from llm import anthropic_provider, gemini_provider, ollama_provider
from llm.anthropic_provider import AnthropicProvider
from llm.gemini_provider import GeminiProvider
from llm.ollama_provider import OllamaProvider
from llm.pool import FailoverCallback, LLMPool
from llm.provider import LLMProvider

KNOWN_PROVIDERS = ("anthropic", "gemini", "ollama")


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PF_LLM_", env_file=".env", extra="ignore")

    # Failover order, e.g. PF_LLM_PROVIDERS=ollama,anthropic for free local dev.
    providers: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["anthropic", "ollama"])

    anthropic_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("PF_LLM_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY")
    )
    anthropic_model: str = anthropic_provider.DEFAULT_MODEL
    anthropic_base_url: str | None = None
    anthropic_timeout: float = 120.0

    gemini_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("PF_LLM_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
    )
    gemini_model: str = gemini_provider.DEFAULT_MODEL
    gemini_base_url: str = gemini_provider.DEFAULT_BASE_URL
    gemini_timeout: float = 600.0

    ollama_base_url: str = ollama_provider.DEFAULT_BASE_URL
    ollama_model: str = ollama_provider.DEFAULT_MODEL
    ollama_timeout: float = 300.0
    ollama_num_ctx: int = ollama_provider.DEFAULT_NUM_CTX

    max_retries: int = 2
    backoff_base: float = 1.0
    backoff_max: float = 20.0
    cooldown_seconds: float = 60.0
    max_retry_after: float = 120.0

    @field_validator("providers", mode="before")
    @classmethod
    def _split_providers(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.split(",")
        if isinstance(value, list):
            value = [str(p).strip().lower() for p in value if str(p).strip()]
            unknown = [p for p in value if p not in KNOWN_PROVIDERS]
            if unknown:
                raise ValueError(f"unknown LLM provider(s) {unknown}; known: {list(KNOWN_PROVIDERS)}")
        return value


def build_provider(name: str, settings: LLMSettings) -> LLMProvider:
    if name == "anthropic":
        key = settings.anthropic_api_key.get_secret_value() if settings.anthropic_api_key else None
        return AnthropicProvider(
            api_key=key,
            model=settings.anthropic_model,
            base_url=settings.anthropic_base_url,
            timeout=settings.anthropic_timeout,
        )
    if name == "gemini":
        gkey = settings.gemini_api_key.get_secret_value() if settings.gemini_api_key else None
        return GeminiProvider(
            api_key=gkey,
            model=settings.gemini_model,
            base_url=settings.gemini_base_url,
            timeout=settings.gemini_timeout,
        )
    if name == "ollama":
        return OllamaProvider(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model,
            timeout=settings.ollama_timeout,
            num_ctx=settings.ollama_num_ctx,
        )
    raise ValueError(f"unknown LLM provider {name!r}")


def build_pool(settings: LLMSettings | None = None, *, on_failover: FailoverCallback | None = None) -> LLMPool:
    """Build the pool in ``settings.providers`` order. Key-based providers
    (anthropic, gemini) are skipped when their key is missing, so a key-less dev
    box falls back to Ollama only."""
    settings = settings or LLMSettings()
    keyed = {"anthropic": settings.anthropic_api_key, "gemini": settings.gemini_api_key}
    names = [n for n in settings.providers if n not in keyed or keyed[n]]
    if not names:
        raise ValueError(
            "no usable LLM provider: set ANTHROPIC_API_KEY / GEMINI_API_KEY or add 'ollama' to PF_LLM_PROVIDERS"
        )
    return LLMPool(
        [build_provider(n, settings) for n in names],
        max_retries=settings.max_retries,
        backoff_base=settings.backoff_base,
        backoff_max=settings.backoff_max,
        cooldown_seconds=settings.cooldown_seconds,
        max_retry_after=settings.max_retry_after,
        on_failover=on_failover,
    )
