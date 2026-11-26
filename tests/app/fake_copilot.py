"""A stand-in for the `copilot` CLI in prompt mode (-p --output-format json), for tests.
It checks the isolation flags, really launches the MCP server from
--additional-mcp-config over stdio, calls one tool and prints Copilot-style JSONL
(assistant.message / assistant.usage / assistant.turn_end / session.error / result),
and writes the --usage-output-file.

Knobs: FAKE_COPILOT_TOOL / FAKE_COPILOT_ARGS (JSON), FAKE_COPILOT_AUTHFAIL=1."""

import asyncio
import json
import os
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


def out(obj):
    print(json.dumps(obj), flush=True)


def flag_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


async def main(argv):
    assert argv[argv.index("--output-format") + 1] == "json"
    assert "--disable-builtin-mcps" in argv and "--no-ask-user" in argv and "--no-custom-instructions" in argv
    assert flag_values(argv, "--allow-tool") == ["pf"], "only the pf MCP server may be allowed"
    assert set(flag_values(argv, "--deny-tool")) >= {"shell", "write", "read", "url", "memory"}
    prompt = argv[argv.index("-p") + 1]
    assert "## Your task" in prompt  # agent .md + task travel in the prompt (no system-prompt flag)
    usage_file = argv[argv.index("--usage-output-file") + 1]
    if os.environ.get("FAKE_COPILOT_AUTHFAIL"):
        out(
            {
                "type": "session.error",
                "data": {"errorType": "authentication", "message": "No authentication information found."},
            }
        )
        out({"type": "result", "exitCode": 1, "usage": {"premiumRequests": 0}})
        sys.exit(1)
    cfg_arg = argv[argv.index("--additional-mcp-config") + 1]
    server = json.load(open(cfg_arg.removeprefix("@")))["mcpServers"]["pf"]
    assert server["type"] == "local" and server["tools"] == ["*"]
    tool = os.environ.get("FAKE_COPILOT_TOOL", "read_file")
    args = json.loads(os.environ.get("FAKE_COPILOT_ARGS", '{"path": "catalog/vulnerabilities/asreproast.yml"}'))
    token_seen = bool(os.environ.get("COPILOT_GITHUB_TOKEN"))
    out({"type": "assistant.turn_start", "data": {"turnId": "0"}})
    out(
        {
            "type": "assistant.message",
            "data": {
                "messageId": "m1",
                "content": f"calling {tool}; token={token_seen}; anthropic={'ANTHROPIC_API_KEY' in os.environ}",
                "toolRequests": [{"toolCallId": "t1", "name": f"pf-{tool}", "arguments": args, "type": "function"}],
            },
        }
    )
    out(
        {
            "type": "assistant.usage",
            "data": {
                "model": "claude-sonnet-4.6",
                "apiCallId": "a1",
                "inputTokens": 1200,
                "cacheReadTokens": 300,
                "cacheWriteTokens": 0,
                "outputTokens": 40,
            },
        }
    )
    transport = StdioTransport(command=server["command"], args=server["args"], env=server["env"], cwd=os.getcwd())
    async with Client(transport) as c:
        names = sorted(t.name for t in await c.list_tools())
        r = await c.call_tool(tool, args, raise_on_error=False)
        text = r.content[0].text if r.content else ""
    out(
        {
            "type": "tool.execution_start",
            "data": {
                "toolCallId": "t1",
                "toolName": f"pf-{tool}",
                "arguments": args,
                "mcpServerName": "pf",
                "mcpToolName": tool,
            },
        }
    )
    out(
        {
            "type": "tool.execution_complete",
            "data": {"toolCallId": "t1", "success": not r.is_error, "result": {"content": text[:200]}},
        }
    )
    out({"type": "assistant.turn_end", "data": {"turnId": "0"}})
    out({"type": "assistant.message", "data": {"messageId": "m2", "content": f"tools={names} error={r.is_error}"}})
    out(
        {
            "type": "assistant.usage",
            "data": {
                "model": "claude-sonnet-4.6",
                "apiCallId": "a2",
                "inputTokens": 1800,
                "cacheReadTokens": 1200,
                "outputTokens": 25,
            },
        }
    )
    out({"type": "assistant.turn_end", "data": {"turnId": "1"}})
    json.dump(
        {
            "totalPremiumRequestCost": 1,
            "totalNanoAiu": 12345,
            "modelMetrics": {"claude-sonnet-4.6": {"usage": {"inputTokens": 3000, "outputTokens": 65}}},
        },
        open(usage_file, "w"),
    )
    out({"type": "result", "exitCode": 0, "usage": {"premiumRequests": 1, "sessionDurationMs": 900}})


asyncio.run(main(sys.argv[1:]))
