"""One place that answers "which tools does agent X get on lab Y?".

Both brains use it: the in-process AgentEngine (via each agent's ``build_tools``)
and an external brain such as Claude Code, which reaches the very same Tool
instances through the agent-tools MCP server. Same classes, same lanes (spec
lock, writable roots, deny/approval patterns, credential scrubbing) by
construction — no second copy of the policy.
"""

from __future__ import annotations

from pathlib import Path

from agents.catalog_author import CatalogAuthorAgent
from agents.deploy_operator import DeployOperatorAgent, Mode
from agents.lab_designer import LabDesignerAgent
from agents.tools import Tool
from agents.validator import ValidatorAgent

TOOLSETS = ("lab-designer", "deploy-operator", "deploy-operator-teardown", "purple-validator", "catalog-author")


def build_toolset(
    agent: str, repo_root: Path, *, lab_name: str | None = None, spec_path: str | None = None
) -> list[Tool]:
    """``agent`` is the registry name (deploy-operator-teardown differs from deploy-operator)."""
    if agent == "lab-designer":
        if not lab_name:
            raise ValueError("lab-designer needs a lab")
        return LabDesignerAgent(None, repo_root=repo_root).build_tools(lab_name)  # type: ignore[arg-type]
    if agent in ("deploy-operator", "deploy-operator-teardown"):
        if not spec_path:
            raise ValueError(f"{agent} needs a spec")
        mode = Mode.TEARDOWN if agent.endswith("teardown") else Mode.DEPLOY
        return DeployOperatorAgent(None, repo_root=repo_root).build_tools(spec_path, mode)  # type: ignore[arg-type]
    if agent == "purple-validator":
        if not spec_path:
            raise ValueError("purple-validator needs a spec")
        return ValidatorAgent(None, repo_root=repo_root).tools_for(spec_path)  # type: ignore[arg-type]
    if agent == "catalog-author":
        return CatalogAuthorAgent(None, repo_root=repo_root).build_tools()  # type: ignore[arg-type]
    raise ValueError(f"unknown toolset {agent!r}; known: {', '.join(TOOLSETS)}")
