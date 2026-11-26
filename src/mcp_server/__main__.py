"""python -m mcp_server — start the PurpleForge MCP server on stdio.

Claude Code launches it from .mcp.json. It reads the same .env as the standalone
service (database, repo root) and needs no LLM API key: the client is the LLM.
stdout is the MCP channel — all logging goes to stderr.
"""

from __future__ import annotations

from api.app import configure_logging
from mcp_server.server import mcp


def main() -> None:
    configure_logging("INFO")
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
