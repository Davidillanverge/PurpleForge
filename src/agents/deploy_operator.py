"""DeployOperatorAgent — deploy-operator: the ONLY agent holding cloud credentials.

Two modes, each locked to ONE lab's spec:
- deploy:   forge generate (--plan) → forge deploy (guardrail gate + deploy.sh:
            infra → AD → population → hardening → vulns → EDR → clean snapshot)
- teardown: forge teardown --force (destroy to cost-zero + verify)

Human approval (rule 5) is enforced by the tools, not the prompt:
- `forge deploy` / `forge teardown` always need an explicit human OK;
- bash runs in *approval-by-default* mode: only single, provably read-only
  commands (terraform show/output, az … show/list, aws … describe/list/get, …)
  run without asking; anything else waits for a human;
- every forge call is locked to this lab's spec, `--skip-guardrail` and
  `--out-dir` are refused, so an approval can never be spent on another lab.

The deterministic work stays in forge/deploy.sh — the agent drives and reports.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from enum import Enum

import yaml

from agents.base import BaseAgent
from agents.budget import BudgetLimits
from agents.engine import AgentResult
from agents.tools import BashTool, FileReadTool, ForgeTool, GlobTool, GrepTool, Tool


class Mode(str, Enum):
    DEPLOY = "deploy"
    TEARDOWN = "teardown"


FORGE_BY_MODE = {
    Mode.DEPLOY: frozenset({"lab-spec", "generate", "guardrail", "deploy"}),
    Mode.TEARDOWN: frozenset({"teardown"}),
}

#: Single simple commands that only read state — the only ones run without a human OK.
READONLY_BASH = (
    r"^(ls|cat|head|tail|wc|stat|du|df|pwd|which|file|jq|grep)(\s|$)",
    r"^terraform(\s+-chdir=\S+)?\s+(show|output|state\s+(list|show)|validate|version|providers)(\s|$)",
    r"^az\s+account\s+show(\s|$)",
    r"^az\s+([a-z-]+\s+){1,3}(show|list)(\s|$)",
    r"^aws\s+[a-z0-9-]+\s+(describe|list|get)-[a-z0-9-]+(\s|$)",
    r"^wg\s+show(\s|$)",
    r"^ping\s+-c\s*\d+\s",
    r"^docker\s+(ps|logs|inspect)(\s|$)",
)

#: Refused outright: credential exfiltration (their output would go to the LLM
#: provider) and gate bypasses. A guardrail, not a sandbox — see agents/tools.py.
DEPLOY_BASH_DENY = (
    r"(^|[\s;&|(])(env|printenv|export|set)(\s|$)",
    r"\.env\b",
    r"\.aws/|\.azure/|\.kube/",
    r"credentials",
    r"get-access-token|secretsmanager|get-secret-value|ssm\s+get-parameter|keyvault\s+secret",
    r"--skip-guardrail",
    r"\bgit\s+(push|commit|reset|checkout|clean)\b",
)

#: Binaries deploy.sh / teardown.sh need on the host running the service.
COMMON_PREREQS = ("bash", "terraform", "docker", "python3")
TUNNEL_PREREQS = ("wg-quick", "sudo")
PROVIDER_PREREQS = {"azure": ("az",), "aws": ("aws",), "proxmox": ()}


def missing_prerequisites(provider: str, mode: Mode, *, which: Callable[[str], str | None] | None = None) -> list[str]:
    which = which or shutil.which
    needed = [*COMMON_PREREQS, *PROVIDER_PREREQS.get(provider, ())]
    if mode is Mode.DEPLOY:
        needed += TUNNEL_PREREQS
    return [b for b in needed if which(b) is None]


class DeployPreconditionError(RuntimeError):
    pass


class DeployOperatorAgent(BaseAgent):
    definition_name = "deploy-operator"
    # deploys are long (terraform + ansible): generous wall clock, modest turns
    default_limits = BudgetLimits(max_turns=40, max_total_tokens=1_500_000, max_wall_seconds=4 * 3600)

    def lab_context(
        self, spec: str, mode: Mode, *, which: Callable[[str], str | None] | None = None
    ) -> tuple[str, str, str]:
        """(spec relative to the repo, lab name, provider) — or a precondition error that
        names exactly what is missing, before any LLM token is spent."""
        spec_path = (self.repo_root / spec).resolve()
        if not spec_path.is_file():
            raise DeployPreconditionError(f"spec not found: {spec}")
        data = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        lab = data.get("lab") or {}
        name, provider = lab.get("name"), lab.get("provider", "")
        if not name:
            raise DeployPreconditionError(f"{spec}: missing lab.name")
        missing = missing_prerequisites(provider, mode, which=which)
        if missing:
            raise DeployPreconditionError(
                f"this host can't {mode.value} a {provider or '?'} lab — missing on PATH: {', '.join(missing)}. "
                "deploy.sh needs the operator toolchain (terraform, docker for the Ansible runner, "
                "the cloud CLI, sudo wg-quick for the tunnel): run the service on an operator host "
                "that has them (not the slim container)."
            )
        if mode is Mode.TEARDOWN and not (self.repo_root / "generated" / name).is_dir():
            raise DeployPreconditionError(f"generated/{name}/ not found — nothing was rendered/deployed from here")
        return str(spec_path.relative_to(self.repo_root.resolve())), name, provider

    def build_tools(self, spec_rel: str, mode: Mode) -> list[Tool]:
        return [
            ForgeTool(
                self.repo_root,
                allowed_subcommands=FORGE_BY_MODE[mode],
                spec_lock=spec_rel,
                forbidden_flags={"--skip-guardrail"},
                required_flags={"teardown": {"--force"}},  # non-interactive; the human approval IS the confirmation
                allow_cloud_credentials=True,
            ),
            BashTool(
                self.repo_root,
                deny_patterns=DEPLOY_BASH_DENY,
                approve_unless_readonly=READONLY_BASH,
                allow_cloud_credentials=True,
            ),
            FileReadTool(self.repo_root),
            GrepTool(self.repo_root),
            GlobTool(self.repo_root),
        ]

    def task(self, spec_rel: str, lab_name: str, mode: Mode, instructions: str = "") -> str:
        if mode is Mode.DEPLOY:
            text = (
                f"Deploy the lab `{lab_name}` from `{spec_rel}`. A human approved this lab for deployment; "
                "each infra-touching action you take will ALSO ask a human for approval.\n"
                f"1. `forge generate {spec_rel} --plan` — structural check; if it fails, STOP and report.\n"
                f"2. `forge deploy {spec_rel}` — the deterministic path: guardrail gate, then deploy.sh "
                "(remote state, auto-sizing, terraform apply, WireGuard, site.yml in the mandated order, "
                "clean snapshot). Do not reimplement its steps by hand.\n"
                "3. If it fails, diagnose with read-only commands and report the exact failing step and output. "
                "Do NOT tear down (that is a separate, separately approved run) and never bypass the guardrail."
            )
        else:
            text = (
                f"Tear down the lab `{lab_name}` to cost-zero: `forge teardown {spec_rel} --force` "
                "(destroy + verification). Report whether cost-zero was verified; if anything is left "
                "behind, report exactly what, with the command output."
            )
        return text + (f"\n\nOperator notes: {instructions}" if instructions else "")

    async def run(self, spec: str, mode: Mode, *, run_id: str | None = None, instructions: str = "") -> AgentResult:
        spec_rel, lab_name, _ = self.lab_context(spec, mode)
        return await self._run(
            self.task(spec_rel, lab_name, mode, instructions), self.build_tools(spec_rel, mode), run_id=run_id
        )
