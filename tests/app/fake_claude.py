"""A stand-in for the `claude` CLI in headless mode, for tests. It behaves like the real
one where it matters to PurpleForge: reads --mcp-config, really launches that MCP server
over stdio, calls one of its tools, and prints stream-json (init / assistant / result).

Behaviour knobs via env: FAKE_CLAUDE_TOOL / FAKE_CLAUDE_ARGS (JSON) choose the call,
FAKE_CLAUDE_KEYSRC=1 pretends an API key is in use, FAKE_CLAUDE_FAIL=1 ends in error."""

import asyncio
import json
import os
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


def out(obj):
    print(json.dumps(obj), flush=True)


async def main(argv):
    cfg_path = argv[argv.index("--mcp-config") + 1]
    server = json.load(open(cfg_path))["mcpServers"]["pf"]
    assert argv[argv.index("--tools") + 1] == "", "built-in tools must be disabled"
    assert "--strict-mcp-config" in argv and argv[argv.index("--allowedTools") + 1] == "mcp__pf"
    out(
        {
            "type": "system",
            "subtype": "init",
            "model": "claude-test-model",
            "apiKeySource": "ANTHROPIC_API_KEY" if os.environ.get("FAKE_CLAUDE_KEYSRC") else "none",
            "tools": [],
            "mcp_servers": [{"name": "pf", "status": "connected"}],
        }
    )
    tool = os.environ.get("FAKE_CLAUDE_TOOL", "read_file")
    args = json.loads(os.environ.get("FAKE_CLAUDE_ARGS", '{"path": "catalog/vulnerabilities/asreproast.yml"}'))
    out(
        {
            "type": "assistant",
            "message": {
                "id": "m1",
                "content": [
                    {"type": "text", "text": f"calling {tool}; api key visible={'ANTHROPIC_API_KEY' in os.environ}"},
                    {"type": "tool_use", "id": "t1", "name": f"mcp__pf__{tool}", "input": args},
                ],
                "usage": {
                    "input_tokens": 10,
                    "cache_creation_input_tokens": 1000,
                    "cache_read_input_tokens": 500,
                    "output_tokens": 20,
                },
            },
        }
    )
    transport = StdioTransport(command=server["command"], args=server["args"], env=dict(os.environ), cwd=os.getcwd())
    async with Client(transport) as c:
        names = sorted(t.name for t in await c.list_tools())
        r = await c.call_tool(tool, args, raise_on_error=False)
        text = r.content[0].text if r.content else ""
    out(
        {
            "type": "assistant",
            "message": {
                "id": "m2",
                "content": [{"type": "text", "text": f"tools={names} error={r.is_error} result={text[:80]}"}],
                "usage": {
                    "input_tokens": 5,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 1500,
                    "output_tokens": 30,
                },
            },
        }
    )
    fail = bool(os.environ.get("FAKE_CLAUDE_FAIL"))
    out(
        {
            "type": "result",
            "subtype": "error_during_execution" if fail else "success",
            "is_error": fail,
            "result": "boom" if fail else "done via subscription",
            "num_turns": 2,
        }
    )


asyncio.run(main(sys.argv[1:]))
