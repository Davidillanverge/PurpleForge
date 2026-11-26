"""CatalogAuthorAgent — catalog-author: reusable catalog content, outside any lab lifecycle.

Lane:
- writes only catalog/** , templates/ansible/vulns/** (inject playbooks) and a
  scratch dir for throwaway specs (generated/_catalog-scratch/, gitignored);
- no shell: schema validation, the catalog-wide contract check and
  `lab-spec --check-only` on a scratch spec are exposed as one fixed-command tool;
- web_fetch limited to reference sites (MITRE ATT&CK, GitHub, Microsoft Learn)
  so ATT&CK ids are verified, not guessed; fetched text is labelled untrusted.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, Field

from agents.base import BaseAgent
from agents.budget import BudgetLimits
from agents.engine import AgentResult
from agents.tools import (
    FileEditTool,
    FileReadTool,
    FileWriteTool,
    GlobTool,
    GrepTool,
    PathGuard,
    Tool,
    ToolResult,
    WebFetchTool,
    forge_pythonpath,
    run_subprocess,
    scrub_env,
)

REFERENCE_HOSTS = ("attack.mitre.org", "github.com", "raw.githubusercontent.com", "learn.microsoft.com")
SCRATCH = "generated/_catalog-scratch"

# Runs in a subprocess (forge's own loaders/schemas; isolates its sys.exit/print).
_CHECK_SCRIPT = r"""
import sys
from pathlib import Path
import jsonschema, yaml, forge

action, target = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")

def schema_for(p):
    if "vulnerabilities" in p.parts:
        return forge.load_vulnerability_schema()
    if "themes" in p.parts:
        return forge.load_theme_schema()
    return None

def check(p):
    p = Path(p)
    schema = schema_for(p)
    if schema is None:
        print(f"{p}: no JSON Schema for this location (only catalog/vulnerabilities, catalog/themes)")
        return True
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(data), key=str)
    for e in errors:
        print(f"{p}: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}")
    if not errors and "vulnerabilities" in p.parts:   # invariant #2: purple = attack AND defense
        missing = [k for k in ("mitigate", "neutralized_by") if not data.get(k)]
        for k in missing:
            print(f"{p}: missing {k} (invariant #2)")
        return not missing
    return not errors

if action == "validate_file":
    ok = check(target)
else:  # catalog_suite
    files = sorted(Path("catalog/vulnerabilities").glob("*.yml")) + sorted(Path("catalog/themes").glob("*.yml"))
    ok = all([check(f) for f in files])
    forge.load_vuln_catalog()  # the loader the generator uses must still accept the catalog
    print(f"checked {len(files)} catalog files")
print("OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
"""


class CatalogCheckInput(BaseModel):
    action: Literal["validate_file", "catalog_suite", "lab_spec_check"] = Field(
        description="validate_file: one catalog .yml against its JSON Schema (+ invariant #2). "
        "catalog_suite: every vuln/theme + the generator's loader. "
        f"lab_spec_check: `forge lab-spec --check-only` on a scratch spec under {SCRATCH}/."
    )
    path: str | None = Field(default=None, description="File for validate_file / lab_spec_check.")


class CatalogCheckTool(Tool):
    name = "catalog_check"
    description = "Validate catalog content with forge's own schemas and loaders (fixed commands, no shell)."
    Input: ClassVar[type[BaseModel]] = CatalogCheckInput

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = Path(repo_root)
        self.catalog_guard = PathGuard(repo_root, [repo_root / "catalog"])
        self.scratch_guard = PathGuard(repo_root, [repo_root / SCRATCH])
        env = scrub_env(os.environ)
        env["PYTHONPATH"] = forge_pythonpath(env)
        self.env = env

    async def run(self, args: BaseModel) -> ToolResult:
        assert isinstance(args, CatalogCheckInput)
        try:
            if args.action == "validate_file":
                if not args.path:
                    return ToolResult(content="validate_file needs a path", is_error=True)
                argv = [
                    sys.executable,
                    "-c",
                    _CHECK_SCRIPT,
                    "validate_file",
                    str(self.catalog_guard.resolve(args.path)),
                ]
            elif args.action == "catalog_suite":
                argv = [sys.executable, "-c", _CHECK_SCRIPT, "catalog_suite"]
            else:
                if not args.path:
                    return ToolResult(content="lab_spec_check needs a path", is_error=True)
                spec = self.scratch_guard.resolve(args.path)
                argv = [sys.executable, "-m", "forge", "lab-spec", str(spec), "--check-only"]
        except PermissionError as exc:
            return ToolResult(content=str(exc), is_error=True)
        return await run_subprocess(argv, cwd=self.repo_root, env=self.env, timeout=300)


class CatalogAuthorAgent(BaseAgent):
    definition_name = "catalog-author"
    default_limits = BudgetLimits(max_turns=50, max_total_tokens=2_000_000)

    def writable_roots(self) -> list[Path]:
        return [
            self.repo_root / "catalog",
            self.repo_root / "templates" / "ansible" / "vulns",
            self.repo_root / SCRATCH,
        ]

    def build_tools(self) -> list[Tool]:
        (self.repo_root / SCRATCH).mkdir(parents=True, exist_ok=True)
        roots = self.writable_roots()
        return [
            FileReadTool(self.repo_root),
            FileWriteTool(self.repo_root, roots=roots),
            FileEditTool(self.repo_root, roots=roots),
            GrepTool(self.repo_root),
            GlobTool(self.repo_root),
            WebFetchTool(REFERENCE_HOSTS),
            CatalogCheckTool(self.repo_root),
        ]

    def task(self, request: str) -> str:
        return (
            f"Catalog request:\n{request.strip()}\n\n"
            "Validate everything you write with `catalog_check` (validate_file per entry, then catalog_suite; "
            f"for a new vuln also lab_spec_check a scratch spec under {SCRATCH}/ that selects it). "
            "Verify ATT&CK ids with web_fetch on attack.mitre.org — never guess. "
            "Report the files you changed, the id, ATT&CK mapping, primitive source and neutralized_by."
        )

    async def run(self, request: str, *, run_id: str | None = None) -> AgentResult:
        return await self._run(self.task(request), self.build_tools(), run_id=run_id)
