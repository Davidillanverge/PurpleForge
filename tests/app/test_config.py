"""Configuration surface: every setting is documented, and deployment files stay consistent."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from api.settings import AppSettings
from db.settings import DatabaseSettings
from llm.settings import LLMSettings

ROOT = Path(__file__).resolve().parents[2]
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")


def _env_choices(model) -> dict[str, set[str]]:
    """field -> env var names that set it (prefix+name, or its validation aliases)."""
    prefix = model.model_config.get("env_prefix", "")
    out = {}
    for name, field in model.model_fields.items():
        alias = field.validation_alias
        choices = {str(c).upper() for c in getattr(alias, "choices", [alias] if alias else [])}
        out[name] = choices or {f"{prefix}{name}".upper()}
    return out


@pytest.mark.parametrize("model", [AppSettings, DatabaseSettings, LLMSettings])
def test_every_setting_is_documented_in_env_example(model):
    documented = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", ENV_EXAMPLE, flags=re.M))
    missing = [names for names in _env_choices(model).values() if not names & documented]
    assert not missing, f"document these in .env.example: {missing}"


def test_compose_variables_are_documented():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]+)", compose))
    documented = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", ENV_EXAMPLE, flags=re.M))
    assert used - documented == set()


def test_compose_hardening():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = compose["services"]
    assert all(p.startswith("127.0.0.1:") for p in svc["app"]["ports"])  # never 0.0.0.0 by default
    assert "ports" not in svc["db"] and "ports" not in svc["redis"]
    assert compose["networks"]["backend"]["internal"] is True
    assert svc["app"]["read_only"] is True and svc["app"]["cap_drop"] == ["ALL"]
    for name in ("db", "redis"):
        assert "@sha256:" in svc[name]["image"], f"{name} image must be pinned by digest"


def test_dockerfile_pins_and_runs_non_root():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"ARG PYTHON_IMAGE=python:[\d.]+-slim@sha256:[0-9a-f]{64}", dockerfile)
    assert re.search(r"^USER pf$", dockerfile, flags=re.M)
    assert "TAILWIND_SHA256_AMD64=" in dockerfile and "TAILWIND_SHA256_ARM64=" in dockerfile


def test_api_tokens_parsing(monkeypatch):
    monkeypatch.setenv("PF_API_TOKENS", "")
    assert AppSettings(_env_file=None).api_tokens == {}
    monkeypatch.setenv("PF_API_TOKENS", '{"' + "x" * 30 + '": "david"}')
    assert AppSettings(_env_file=None).api_tokens == {"x" * 30: "david"}
    monkeypatch.setenv("PF_API_TOKENS", '{"short": "david"}')
    with pytest.raises(ValueError, match=">= 24 chars"):
        AppSettings(_env_file=None)
    monkeypatch.setenv("PF_API_TOKENS", "david:token")
    with pytest.raises(ValueError, match="must be JSON"):
        AppSettings(_env_file=None)
