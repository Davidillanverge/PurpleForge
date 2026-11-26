"""Load agent definitions from ``.claude/agents/<name>.md``.

The .md files stay the single source of truth for each agent's instructions
(rule 4): their body becomes the system prompt, verbatim. They were written for
Claude Code, so a runtime preamble maps Claude Code tool names onto the tools
this service actually exposes.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

#: Claude Code tool name in the .md frontmatter -> this service's tool name.
CLAUDE_CODE_TOOL_MAP = {
    "Bash": "bash",
    "Read": "read_file",
    "Write": "write_file",
    "Edit": "edit_file",
    "Grep": "grep",
    "Glob": "glob",
    "WebFetch": "web_fetch",
}


class AgentDefinition(BaseModel):
    name: str
    description: str = ""
    tools: list[str] = Field(default_factory=list)
    model: str | None = None
    body: str
    source: Path


def parse_agent_markdown(text: str, source: Path) -> AgentDefinition:
    if not text.startswith("---"):
        raise ValueError(f"{source}: missing YAML frontmatter")
    try:
        _, front, body = text.split("---", 2)
    except ValueError as exc:
        raise ValueError(f"{source}: unterminated YAML frontmatter") from exc
    meta = yaml.safe_load(front) or {}
    if not isinstance(meta, dict) or "name" not in meta:
        raise ValueError(f"{source}: frontmatter must be a mapping with a 'name'")
    tools = meta.get("tools") or []
    if isinstance(tools, str):
        tools = [t.strip() for t in tools.split(",") if t.strip()]
    return AgentDefinition(
        name=str(meta["name"]),
        description=" ".join(str(meta.get("description", "")).split()),
        tools=[str(t) for t in tools],
        model=meta.get("model"),
        body=body.strip(),
        source=source,
    )


def load_agent_definition(repo_root: Path, name: str) -> AgentDefinition:
    path = Path(repo_root) / ".claude" / "agents" / f"{name}.md"
    return parse_agent_markdown(path.read_text(encoding="utf-8"), path)


def runtime_preamble(definition: AgentDefinition, tool_names: list[str], repo_root: Path) -> str:
    mapped = [f"{cc} → `{ours}`" for cc, ours in CLAUDE_CODE_TOOL_MAP.items() if ours in tool_names]
    unavailable = [t for t in definition.tools if CLAUDE_CODE_TOOL_MAP.get(t) not in tool_names]
    lines = [
        "# Runtime",
        "",
        "You run inside the PurpleForge agent service (not Claude Code). The instructions below were",
        "written for Claude Code; apply them with the tools you actually have:",
        "",
        f"- Tools available: {', '.join(f'`{t}`' for t in sorted(tool_names))}.",
    ]
    if mapped:
        lines.append(f"- Name mapping: {', '.join(mapped)}.")
    if "forge" in tool_names:
        lines.append("- Run the deterministic CLI with the `forge` tool (`subcommand` + `args`), not via bash.")
    if unavailable:
        lines.append(
            f"- Not available here: {', '.join(unavailable)}. Work with the tools you have; if something "
            "really needs a missing one, say so in your final answer instead of improvising around it."
        )
    lines += [
        "- Skills referenced below live in `.claude/skills/<name>/SKILL.md`; read them with `read_file`.",
        f"- Repository root (cwd for every tool): `{Path(repo_root).resolve()}`.",
        "- There is no human in the loop mid-run except the approval gate: don't ask questions, decide and",
        "  report. End with a concise final answer summarising what you did and what you found.",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def build_system_prompt(definition: AgentDefinition, tool_names: list[str], repo_root: Path) -> str:
    return runtime_preamble(definition, tool_names, repo_root) + definition.body + "\n"
