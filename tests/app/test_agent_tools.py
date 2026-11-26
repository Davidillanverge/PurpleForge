"""Real-subprocess / real-filesystem tests for the agent tools."""

from __future__ import annotations

from pathlib import Path

from agents.budget import Budget, BudgetLimits
from agents.tools import (
    BashInput,
    BashTool,
    FileReadInput,
    FileReadTool,
    FileWriteInput,
    FileWriteTool,
    ForgeInput,
    ForgeTool,
    scrub_env,
    truncate,
)
from llm import Usage

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- bash


async def test_bash_runs_in_cwd_and_reports_exit_code(tmp_path):
    tool = BashTool(tmp_path, environ={"PATH": "/usr/bin:/bin"})
    ok = await tool.run(BashInput(command="pwd && echo hi"))
    assert not ok.is_error and ok.data["exit_code"] == 0
    assert str(tmp_path.resolve()) in ok.content and ok.content.rstrip().endswith("hi")
    bad = await tool.run(BashInput(command="echo oops >&2; exit 3"))
    assert bad.is_error and bad.data["exit_code"] == 3 and "oops" in bad.content


async def test_bash_timeout_kills_process_group(tmp_path):
    tool = BashTool(tmp_path, environ={"PATH": "/usr/bin:/bin"})
    res = await tool.run(BashInput(command="sleep 30 & sleep 30", timeout_seconds=1))
    assert res.is_error and res.data["timed_out"]


async def test_bash_deny_and_approval_patterns(tmp_path):
    tool = BashTool(tmp_path, deny_patterns=[r"\bterraform\b"], approval_patterns=[r"\brm\b"], environ={})
    denied = await tool.run(BashInput(command="cd x && terraform destroy"))
    assert denied.is_error and "deny rule" in denied.content
    assert tool.needs_approval(BashInput(command="rm -rf build")) is not None
    assert tool.needs_approval(BashInput(command="ls")) is None


async def test_bash_env_has_no_credentials(tmp_path):
    env = {
        "PATH": "/usr/bin:/bin",
        "ANTHROPIC_API_KEY": "sk",
        "AWS_SECRET_ACCESS_KEY": "aws",
        "PF_FLEET_ENROLLMENT_TOKEN": "tok",
        "LANG": "C",
    }
    res = await BashTool(tmp_path, environ=env).run(BashInput(command="env"))
    assert "LANG=C" in res.content
    for secret in ("sk", "aws", "tok"):
        assert f"={secret}\n" not in res.content


def test_scrub_env_allow_cloud_keeps_cloud_but_never_llm_keys():
    env = {"AWS_REGION": "eu-west-1", "ARM_CLIENT_SECRET": "x", "ANTHROPIC_API_KEY": "k", "HOME": "/h"}
    assert scrub_env(env) == {"HOME": "/h"}
    assert scrub_env(env, allow_cloud=True) == {"AWS_REGION": "eu-west-1", "ARM_CLIENT_SECRET": "x", "HOME": "/h"}


def test_truncate_keeps_head_and_tail():
    text = "A" * 100 + "B" * 100
    out = truncate(text, 60)
    assert out.startswith("A" * 20) and out.endswith("B" * 40) and "truncated 140" in out


# --------------------------------------------------------------------------- forge


async def test_forge_tool_runs_real_cli():
    tool = ForgeTool(REPO_ROOT, allowed_subcommands={"validate"})
    res = await tool.run(ForgeInput(subcommand="validate", args=["specs/does-not-exist.yml"]))
    assert res.is_error and res.data["exit_code"] == 2 and "spec file not found" in res.content


async def test_forge_tool_allowlist_and_approval():
    tool = ForgeTool(REPO_ROOT, allowed_subcommands={"validate", "deploy"})
    refused = await ForgeTool(REPO_ROOT, allowed_subcommands={"validate"}).run(
        ForgeInput(subcommand="deploy", args=["specs/x.yml"])
    )
    assert refused.is_error and "not allowed" in refused.content
    assert tool.needs_approval(ForgeInput(subcommand="deploy")) is not None
    assert tool.needs_approval(ForgeInput(subcommand="validate")) is None
    # a subcommand the agent may not run at all is refused, not escalated to a human
    assert (
        ForgeTool(REPO_ROOT, allowed_subcommands={"validate"}).needs_approval(ForgeInput(subcommand="deploy")) is None
    )
    assert tool.spec().input_schema["properties"]["subcommand"]["enum"] == ["deploy", "validate"]


# --------------------------------------------------------------------------- files


async def test_read_file_numbered_with_paging(tmp_path):
    (tmp_path / "a.txt").write_text("one\ntwo\nthree\n")
    tool = FileReadTool(tmp_path)
    res = await tool.run(FileReadInput(path="a.txt", offset=2, limit=1))
    assert "     2\ttwo" in res.content and "offset=3" in res.content


async def test_read_file_blocks_traversal_and_secrets(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("AWS_SECRET=x")
    (repo / ".env.example").write_text("AWS_REGION=")
    (tmp_path / "outside.txt").write_text("nope")
    (repo / "link").symlink_to(tmp_path / "outside.txt")
    tool = FileReadTool(repo)
    assert (await tool.run(FileReadInput(path="../outside.txt"))).is_error
    assert (await tool.run(FileReadInput(path="link"))).is_error  # symlink escaping the root
    assert "protected" in (await tool.run(FileReadInput(path=".env"))).content
    assert not (await tool.run(FileReadInput(path=".env.example"))).is_error


async def test_write_file_only_inside_roots(tmp_path):
    lab = tmp_path / "generated" / "lab1"
    tool = FileWriteTool(tmp_path, roots=[lab])
    ok = await tool.run(FileWriteInput(path="generated/lab1/reports/lab-report.md", content="# report"))
    assert not ok.is_error and (lab / "reports" / "lab-report.md").read_text() == "# report"
    for path in ("specs/lab1.yml", "generated/lab2/x.md", "generated/lab1/../lab2/x.md"):
        assert (await tool.run(FileWriteInput(path=path, content="x"))).is_error, path


# --------------------------------------------------------------------------- budget


def test_budget_limits():
    now = [0.0]
    b = Budget(BudgetLimits(max_turns=3, max_input_tokens=100, max_wall_seconds=10), clock=lambda: now[0])
    assert b.exceeded() is None
    b.charge(Usage(input_tokens=60, output_tokens=5))
    assert b.exceeded() is None and b.snapshot()["turns"] == 1
    b.charge(Usage(input_tokens=60, output_tokens=5))
    assert "input token" in b.exceeded()

    b2 = Budget(BudgetLimits(max_turns=1), clock=lambda: now[0])
    b2.charge(Usage())
    assert "turn limit" in b2.exceeded()

    b3 = Budget(BudgetLimits(max_wall_seconds=10), clock=lambda: now[0])
    now[0] = 11
    assert "wall-clock" in b3.exceeded()
