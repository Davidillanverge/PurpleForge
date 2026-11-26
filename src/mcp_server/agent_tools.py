"""Per-run agent-tools MCP server — how an external brain (Claude Code on your
subscription) uses an agent's tools WITHOUT getting a broader lane.

    python -m mcp_server.agent_tools --run-id <uuid> --toolset deploy-operator \
        --spec specs/lab.yml --lab lab [--tenant default]

It exposes exactly the tools ``agents.toolsets.build_toolset`` gives that agent
(the same Tool instances the AgentEngine uses), and executes every call through
``AgentEngine._execute``: argument validation, the human approval gate (fail
closed, decided in the dashboard via the shared approvals table), error results
back to the model, and tool_call / approval / tool_result events appended to the
run that the dashboard is streaming. Launched by the API's Claude brain with
``--strict-mcp-config`` and Claude's own built-in tools disabled.
"""

from __future__ import annotations

import argparse
import uuid
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import Tool as McpTool
from fastmcp.tools import ToolResult as McpToolResult
from pydantic import PrivateAttr

from agents.engine import AgentEngine
from agents.toolsets import build_toolset
from api.approvals import db_polling_approver
from api.settings import AppSettings
from db.recorder import Recorder
from db.session import create_engine, create_sessionmaker
from db.settings import DatabaseSettings
from llm.provider import ToolCall

SERVER_NAME = "pf"  # Claude sees the tools as mcp__pf__<tool>


class EngineBackedTool(McpTool):
    """An MCP tool whose execution is the engine's own ``_execute`` for one run."""

    _executor: AgentEngine = PrivateAttr()
    _recorder: Recorder = PrivateAttr()
    _run_id: str = PrivateAttr()

    def bind(self, executor: AgentEngine, recorder: Recorder, run_id: str) -> EngineBackedTool:
        self._executor, self._recorder, self._run_id = executor, recorder, run_id
        return self

    async def run(self, arguments: dict[str, Any]) -> McpToolResult:
        call = ToolCall(id=f"cc-{uuid.uuid4().hex[:12]}", name=self.name, arguments=dict(arguments or {}))
        result = await self._executor._execute(call, self._recorder, self._run_id)  # type: ignore[arg-type]
        if result.is_error:
            raise ToolError(result.content)
        return McpToolResult(content=result.content)


def build_server(
    *,
    run_id: str,
    toolset: str,
    tenant: str,
    lab: str | None,
    spec: str | None,
    app: AppSettings | None = None,
    db: DatabaseSettings | None = None,
) -> FastMCP:
    app = app or AppSettings()
    db = db or DatabaseSettings()
    sessionmaker = create_sessionmaker(create_engine(settings=db))
    tools = build_toolset(toolset, app.repo_root, lab_name=lab, spec_path=spec)
    recorder = Recorder(sessionmaker, tenant, run_id, toolset)
    executor = AgentEngine(
        None,  # type: ignore[arg-type]  # no LLM here: the brain is the MCP client
        tools,
        system_prompt="",
        agent_name=toolset,
        approver=db_polling_approver(sessionmaker, tenant, timeout_seconds=app.approval_timeout_seconds),
    )
    server = FastMCP(SERVER_NAME, instructions=f"PurpleForge {toolset} tools for run {run_id}.")
    for tool in tools:
        spec_ = tool.spec()
        server.add_tool(
            EngineBackedTool(name=spec_.name, description=spec_.description, parameters=spec_.input_schema).bind(
                executor, recorder, run_id
            )
        )
    return server


def main(argv: list[str] | None = None) -> None:
    from api.app import configure_logging

    parser = argparse.ArgumentParser(prog="python -m mcp_server.agent_tools")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--toolset", required=True)
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--lab")
    parser.add_argument("--spec")
    args = parser.parse_args(argv)
    configure_logging("WARNING")  # stdout is the MCP channel; logs go to stderr
    build_server(run_id=args.run_id, toolset=args.toolset, tenant=args.tenant, lab=args.lab, spec=args.spec).run(
        transport="stdio", show_banner=False
    )


if __name__ == "__main__":
    main()
