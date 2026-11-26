"""Shared security primitives — identical in both execution modes (standalone engine and MCP).

- ``scrub_env``: child processes never see LLM keys; cloud/deploy credentials only on request
- ``PathGuard``: path resolution confined to roots, with protected files (.env, keys, .git)
- ``run_subprocess``: no TTY/stdin, timeout kills the whole process group, output truncated
- ``forge_pythonpath``: make the real ``forge`` package importable in a child process

These keep a well-meaning model in its lane; they are NOT a sandbox against a hostile one.
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import re
import signal
from collections.abc import Iterable, Mapping
from pathlib import Path

from core.schemas import ToolResult

DEFAULT_MAX_OUTPUT_CHARS = 30_000


def truncate(text: str, limit: int = DEFAULT_MAX_OUTPUT_CHARS) -> str:
    """Keep head and tail (errors usually sit at the end of long output)."""
    if len(text) <= limit:
        return text
    head = limit // 3
    tail = limit - head
    return f"{text[:head]}\n\n[... truncated {len(text) - limit} chars ...]\n\n{text[-tail:]}"


_SECRET_NAME = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_CLOUD_PREFIXES = ("AWS_", "ARM_", "AZURE_", "GOOGLE_", "GCLOUD_", "PROXMOX_", "TF_VAR_", "MDE_")
_ALWAYS_DROP_PREFIXES = ("ANTHROPIC_", "PF_LLM_", "GEMINI_", "GOOGLE_API_KEY")


def scrub_env(environ: Mapping[str, str], *, allow_cloud: bool = False) -> dict[str, str]:
    """Child env without LLM keys and, unless ``allow_cloud``, without cloud or
    deploy-time credentials. Only the deploy-operator passes allow_cloud=True."""
    out: dict[str, str] = {}
    for key, value in environ.items():
        if key.startswith(_ALWAYS_DROP_PREFIXES):
            continue
        if not allow_cloud and (key.startswith(_CLOUD_PREFIXES) or _SECRET_NAME.search(key)):
            continue
        out[key] = value
    return out


async def run_subprocess(
    argv: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
) -> ToolResult:
    """Run without a TTY or stdin; on timeout kill the whole process group."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd),
        env=dict(env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return ToolResult(
            content=f"timed out after {timeout:.0f}s (process killed)",
            is_error=True,
            data={"exit_code": None, "timed_out": True},
        )
    text = out.decode("utf-8", errors="replace")
    code = proc.returncode
    return ToolResult(
        content=f"exit code: {code}\n{truncate(text, max_output_chars)}",
        is_error=code != 0,
        data={"exit_code": code},
    )


def forge_pythonpath(env: Mapping[str, str]) -> str:
    """PYTHONPATH that makes the installed/checked-out ``forge`` package importable
    in a child process — located from the package itself, not from a repo_root
    guess (the agent's repo_root and forge's home may differ, e.g. in tests)."""
    import importlib.util

    spec = importlib.util.find_spec("forge")
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError("the forge package is not importable (pip install -e . from the repo root)")
    scripts = str(Path(next(iter(spec.submodule_search_locations))).parent)
    return os.pathsep.join(p for p in (scripts, env.get("PYTHONPATH", "")) if p)


#: Never readable by an agent even inside its roots (deploy-time credentials).
DEFAULT_READ_DENY = (".env", ".env.*", "*.pem", "*.ppk", ".git/*", ".venv/*")
DEFAULT_READ_ALLOW = (".env.example",)


class PathGuard:
    def __init__(
        self,
        base: Path,
        roots: Iterable[Path],
        deny: Iterable[str] = (),
        allow: Iterable[str] = (),
    ) -> None:
        self.base = Path(base).resolve()
        self.roots = [Path(r).resolve() for r in roots]
        self.deny = tuple(deny)
        self.allow = tuple(allow)

    def resolve(self, raw: str) -> Path:
        path = Path(raw)
        if not path.is_absolute():
            path = self.base / path
        path = path.resolve()  # collapses ../ and follows symlinks
        if not any(path == r or path.is_relative_to(r) for r in self.roots):
            roots = ", ".join(self._rel(r) for r in self.roots)
            raise PermissionError(f"{raw}: outside the allowed paths for this agent ({roots})")
        rel = self._rel(path)
        name = path.name
        if not any(fnmatch.fnmatch(name, a) or fnmatch.fnmatch(rel, a) for a in self.allow) and any(
            fnmatch.fnmatch(name, d) or fnmatch.fnmatch(rel, d) for d in self.deny
        ):
            raise PermissionError(f"{raw}: access denied (protected file)")
        return path

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.base)) or "."
        except ValueError:
            return str(path)
