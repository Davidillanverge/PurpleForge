"""ValidatorAgent — purple-validator: per vuln APPLIED + EXPLOITABLE, then lab-report.md.

Lane (enforced by its tool set, not by the prompt):
- forge: only read-only/validation subcommands (validate, ad-inventory, guardrail).
- bash: no cloud credentials in its env; infra-mutating commands refused.
- write_file: only inside generated/<lab>/.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from agents.base import BaseAgent
from agents.budget import BudgetLimits
from agents.engine import AgentResult
from agents.tools import BashTool, FileReadTool, FileWriteTool, ForgeTool, GlobTool, GrepTool, Tool

VALIDATOR_FORGE_SUBCOMMANDS = frozenset({"validate", "ad-inventory", "guardrail"})

#: The validator attacks a live lab over the tunnel; it never changes the infra itself.
VALIDATOR_BASH_DENY = (
    r"\bterraform\b",
    r"\bansible-playbook\b",
    r"(^|[\s;&|(])(az|aws|gcloud|pvesh|qm)\s",
    r"\bforge\s+(deploy|teardown|destroy|reset|stop|start|restart)\b",
    r"\b(deploy|teardown|rollback|reset|stop|start)\.sh\b",
    r"\bgit\s+(push|commit|reset|checkout|clean)\b",
)


class ValidatorPreconditionError(RuntimeError):
    pass


class ValidatorAgent(BaseAgent):
    definition_name = "purple-validator"
    default_limits = BudgetLimits(max_turns=60, max_total_tokens=2_000_000)

    def lab_context(self, spec: str | Path) -> tuple[Path, str, Path]:
        """(spec path, lab name, generated/<lab>/) — fails early if the lab was never generated."""
        spec_path = Path(spec)
        if not spec_path.is_absolute():
            spec_path = self.repo_root / spec_path
        spec_path = spec_path.resolve()
        if not spec_path.is_file():
            raise ValidatorPreconditionError(f"spec not found: {spec_path}")
        data = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        lab = (data.get("lab") or {}).get("name")
        if not lab:
            raise ValidatorPreconditionError(f"{spec_path}: missing lab.name")
        lab_dir = self.repo_root / "generated" / lab
        if not (lab_dir / "lab-manifest.json").is_file():
            raise ValidatorPreconditionError(
                f"{lab_dir / 'lab-manifest.json'} not found — run `forge generate` and deploy the lab first"
            )
        return spec_path, lab, lab_dir

    def build_tools(self, lab_dir: Path, spec_rel: str | None = None) -> list[Tool]:
        return [
            # spec_lock: it validates THIS lab only (no forge validate/ad-inventory on another lab)
            ForgeTool(self.repo_root, allowed_subcommands=VALIDATOR_FORGE_SUBCOMMANDS, spec_lock=spec_rel),
            BashTool(self.repo_root, deny_patterns=VALIDATOR_BASH_DENY),
            FileReadTool(self.repo_root),
            FileWriteTool(self.repo_root, roots=[lab_dir]),
            GrepTool(self.repo_root),
            GlobTool(self.repo_root),
        ]

    async def run(self, spec: str | Path, *, run_id: str | None = None, instructions: str = "") -> AgentResult:
        spec_path, lab, lab_dir = self.lab_context(spec)
        rel_spec = spec_path.relative_to(self.repo_root) if spec_path.is_relative_to(self.repo_root) else spec_path
        rel_dir = lab_dir.relative_to(self.repo_root)
        task = (
            f"Validate the deployed lab `{lab}` (spec `{rel_spec}`, artifacts in `{rel_dir}/`).\n"
            f"Follow your Part 1 (validate every injected vuln: APPLIED + EXPLOITABLE, starting with "
            f"`forge validate {rel_spec} --run`) and Part 2 (write `{rel_dir}/lab-report.md`).\n"
            "The deploy has finished and the clean snapshot was taken, so attacks are allowed now."
        )
        if instructions:
            task += f"\n\nOperator notes: {instructions}"
        return await self._run(task, self.build_tools(lab_dir, str(rel_spec)), run_id=run_id)
