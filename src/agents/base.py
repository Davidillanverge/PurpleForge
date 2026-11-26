"""Shared wiring for concrete agents: definition → system prompt → engine."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from agents.budget import BudgetLimits
from agents.definitions import AgentDefinition, build_system_prompt, load_agent_definition
from agents.engine import AgentEngine, AgentResult, Approver
from agents.events import EventCallback
from agents.tools import Tool
from llm.provider import LLMProvider


def default_repo_root() -> Path:
    # forge resolves REPO_ROOT from its own __file__ — reuse it, don't re-derive.
    from forge.core import REPO_ROOT

    return Path(REPO_ROOT)


class BaseAgent:
    #: basename of .claude/agents/<definition_name>.md
    definition_name: ClassVar[str]
    default_limits: ClassVar[BudgetLimits] = BudgetLimits()

    def __init__(
        self,
        llm: LLMProvider,
        *,
        repo_root: Path | None = None,
        on_event: EventCallback | None = None,
        approver: Approver | None = None,
        limits: BudgetLimits | None = None,
        definition: AgentDefinition | None = None,
    ) -> None:
        self.llm = llm
        self.repo_root = Path(repo_root or default_repo_root()).resolve()
        self.on_event = on_event
        self.approver = approver
        self.limits = limits or self.default_limits
        self.definition = definition or load_agent_definition(self.repo_root, self.definition_name)

    def build_engine(self, tools: list[Tool]) -> AgentEngine:
        prompt = build_system_prompt(self.definition, [t.name for t in tools], self.repo_root)
        return AgentEngine(
            self.llm,
            tools,
            system_prompt=prompt,
            agent_name=self.definition.name,
            limits=self.limits,
            on_event=self.on_event,
            approver=self.approver,
        )

    async def _run(self, task: str, tools: list[Tool], *, run_id: str | None = None) -> AgentResult:
        return await self.build_engine(tools).run(task, run_id=run_id)
