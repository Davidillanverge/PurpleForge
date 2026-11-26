"""Database + secret-key configuration (pydantic-settings, ``PF_`` prefix)."""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "postgresql+asyncpg://purpleforge:purpleforge@localhost:5432/purpleforge"


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PF_", env_file=".env", extra="ignore")

    database_url: str = DEFAULT_DATABASE_URL
    database_echo: bool = False
    database_pool_size: int = 5
    database_max_overflow: int = 10
    #: Encrypts provider API keys at rest (db.crypto). Required to store a key.
    secret_key: SecretStr | None = None
