"""LabDesignerAgent — lab-designer: natural-language request → specs/<lab>.yml.

Lane (enforced by its tool set, not by the prompt):
- writes/edits exactly ONE file: specs/<lab>.yml (never generated/, never another lab);
- forge: only `lab-spec <its spec> --check-only` (the --check-only flag is mandatory,
  so it can't write generated/<lab>/lab-manifest.json);
- no shell at all: it consumes free-text user input, so it gets read-only
  read_file/grep/glob instead of bash;
- no cloud credentials.
"""

from __future__ import annotations

from pathlib import Path

from agents.base import BaseAgent
from agents.budget import BudgetLimits
from agents.engine import AgentResult
from agents.tools import FileEditTool, FileReadTool, FileWriteTool, ForgeTool, GlobTool, GrepTool, Tool


class LabDesignerAgent(BaseAgent):
    definition_name = "lab-designer"
    default_limits = BudgetLimits(max_turns=50, max_total_tokens=2_000_000)

    @staticmethod
    def spec_rel(lab_name: str) -> str:
        return f"specs/{lab_name}.yml"

    def build_tools(self, lab_name: str) -> list[Tool]:
        spec_rel = self.spec_rel(lab_name)
        spec_file = self.repo_root / spec_rel
        return [
            ForgeTool(
                self.repo_root,
                allowed_subcommands={"lab-spec"},
                required_flags={"lab-spec": {"--check-only"}},
                spec_lock=spec_rel,
            ),
            FileReadTool(self.repo_root),
            FileWriteTool(self.repo_root, roots=[spec_file]),
            FileEditTool(self.repo_root, roots=[spec_file]),
            GrepTool(self.repo_root),
            GlobTool(self.repo_root),
        ]

    #: Versioned smoke-test specs (kept valid by the repo's tests) — the safest shapes to copy.
    KNOWN_GOOD_EXAMPLES = ("specs/winrm-validate-lab.yml", "specs/mssql-weak-sa-lab.yml")

    def examples(self, lab_name: str, limit: int = 2) -> list[str]:
        """Specs to copy the shape from: the versioned known-good ones (user specs under
        specs/ may be half-written or invalid); other specs only if none exist. Never the target."""
        known = [e for e in self.KNOWN_GOOD_EXAMPLES if (self.repo_root / e).is_file() and Path(e).stem != lab_name]
        if known:
            return known[:limit]  # never mix in unknown user specs when a known-good one exists
        others = [f"specs/{p.name}" for p in sorted((self.repo_root / "specs").glob("*.yml"))]
        return [e for e in others if Path(e).stem != lab_name][:limit]

    def task(self, lab_name: str, request: str, *, existing: bool) -> str:
        spec_rel = self.spec_rel(lab_name)
        verb = "Revise the existing" if existing else "Write the"
        examples = self.examples(lab_name)
        # Deterministic orientation: the schema is the contract forge validates against.
        # Without it, smaller models guess the structure and loop on schema errors.
        orientation = (
            "Before writing anything, read `specs/schema/lab-spec.schema.json` (the exact contract forge "
            "validates: required blocks, allowed keys, enums, formats)"
            + (f" and copy the shape of an existing spec: {', '.join(f'`{e}`' for e in examples)}" if examples else "")
            + ". Vulnerability ids are the file names in `catalog/vulnerabilities/`; themes are in `catalog/themes/`. "
            "When `--check-only` fails, fix EVERY reported error in one edit, re-reading the schema for the "
            "failing keys — don't resubmit the same content.\n\n"
        )
        return (
            f"{verb} spec `{spec_rel}` for the lab `{lab_name}` (lab.name MUST be exactly `{lab_name}`; "
            "it is the only file you can write).\n\n"
            f"Request:\n{request.strip() or '(no details given: design a sensible small purple-team AD lab)'}\n\n"
            + orientation
            + f"Before finishing, `forge lab-spec {spec_rel} --check-only` must pass; fix whatever it flags. "
            "Then report topology, org shape + seed, selected vulns + ordered chain + objective, and any "
            "sizing/quota caveat."
        )

    async def run(
        self, lab_name: str, request: str, *, existing: bool = False, run_id: str | None = None
    ) -> AgentResult:
        return await self._run(
            self.task(lab_name, request, existing=existing), self.build_tools(lab_name), run_id=run_id
        )
