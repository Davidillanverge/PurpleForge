"""Deterministic forge steps the API runs itself (no AI): compile + guardrail.

They drive the lab FSM designed → compiled → ready. Running them here — not via
an agent — keeps the gate deterministic: an LLM can't talk a lab into READY.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from agents.tools import forge_pythonpath, run_subprocess, scrub_env


class ForgeStep(BaseModel):
    command: str
    exit_code: int | None
    ok: bool
    output: str


class SpecError(ValueError):
    pass


def resolve_spec(repo_root: Path, spec_path: str, lab_name: str) -> tuple[Path, dict[str, Any]]:
    """specs/<x>.yml inside the repo, existing, whose lab.name matches the lab.
    Returns the resolved path and the parsed spec."""
    specs_dir = (repo_root / "specs").resolve()
    path = (repo_root / spec_path).resolve()
    if not path.is_relative_to(specs_dir) or path.suffix not in (".yml", ".yaml"):
        raise SpecError(f"spec_path must be a .yml under specs/, got {spec_path!r}")
    if not path.is_file():
        raise SpecError(f"spec not found: {spec_path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SpecError(f"{spec_path}: invalid YAML: {exc}") from exc
    name = (data.get("lab") or {}).get("name") if isinstance(data, dict) else None
    if name != lab_name:
        raise SpecError(f"{spec_path}: lab.name is {name!r}, expected {lab_name!r}")
    return path, data


async def run_forge(repo_root: Path, *args: str, timeout: float) -> ForgeStep:
    env = scrub_env(os.environ)
    env["PYTHONPATH"] = forge_pythonpath(env)
    res = await run_subprocess([sys.executable, "-m", "forge", *args], cwd=repo_root, env=env, timeout=timeout)
    code = res.data.get("exit_code")
    return ForgeStep(command="forge " + " ".join(args), exit_code=code, ok=code == 0, output=res.content)


async def compile_and_guardrail(repo_root: Path, spec: Path, lab_name: str, *, timeout: float) -> list[ForgeStep]:
    """``forge lab-spec`` then (only if it passed) ``forge guardrail``."""
    out_dir = str(repo_root / "generated" / lab_name)
    rel = str(spec.relative_to(repo_root.resolve()))
    steps = [await run_forge(repo_root, "lab-spec", rel, "--out-dir", out_dir, timeout=timeout)]
    if steps[0].ok:
        steps.append(await run_forge(repo_root, "guardrail", rel, "--out-dir", out_dir, timeout=timeout))
    return steps
