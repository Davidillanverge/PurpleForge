"""ValidatorAgent wiring: prompt from the real .md, tool lane, preconditions."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from _fakes import ScriptedLLM, call, reply

from agents import EventType, RunStatus, ValidatorAgent
from agents.definitions import load_agent_definition
from agents.validator import ValidatorPreconditionError

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def lab_repo(tmp_path):
    """Minimal repo: the real agent .md + a spec + a generated manifest."""
    agents_dir = tmp_path / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    shutil.copy(REPO_ROOT / ".claude" / "agents" / "purple-validator.md", agents_dir)
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "lab1.yml").write_text("lab:\n  name: lab1\n")
    (tmp_path / "generated" / "lab1").mkdir(parents=True)
    (tmp_path / "generated" / "lab1" / "lab-manifest.json").write_text('{"vulnerabilities_planned": []}')
    return tmp_path


def test_definition_loaded_from_real_markdown():
    d = load_agent_definition(REPO_ROOT, "purple-validator")
    assert d.name == "purple-validator"
    assert d.tools[:3] == ["Bash", "Read", "Write"]
    assert "lab-report.md" in d.body and not d.body.startswith("---")


def test_system_prompt_is_md_body_plus_runtime_preamble():
    agent = ValidatorAgent(ScriptedLLM(), repo_root=REPO_ROOT)
    lab_dir = REPO_ROOT / "generated" / "x"
    eng = agent.build_engine(agent.build_tools(lab_dir))
    assert eng.system_prompt.endswith(agent.definition.body + "\n")
    assert "Bash → `bash`" in eng.system_prompt and "Not available here: Artifact." in eng.system_prompt
    assert sorted(eng.tools) == ["bash", "forge", "glob", "grep", "read_file", "write_file"]
    assert eng.tools["forge"].allowed == {"validate", "ad-inventory", "guardrail"}


async def test_validator_lane_is_enforced(lab_repo):
    llm = ScriptedLLM(
        reply(
            "",
            call("forge", "f1", subcommand="deploy", args=["specs/lab1.yml"]),
            call("bash", "b1", command="terraform -chdir=generated/lab1/terraform destroy"),
            call("write_file", "w1", path="specs/lab1.yml", content="pwned"),
            call("write_file", "w2", path="generated/lab1/lab-report.md", content="# lab1 report"),
            call("read_file", "r1", path="generated/lab1/lab-manifest.json"),
        ),
        reply("report written"),
    )
    events = []
    res = await ValidatorAgent(llm, repo_root=lab_repo, on_event=events.append).run("specs/lab1.yml")

    assert res.status is RunStatus.COMPLETED
    results = {e.data["id"]: e.data for e in events if e.type is EventType.TOOL_RESULT}
    assert results["f1"]["is_error"] and "not allowed" in results["f1"]["content"]
    assert results["b1"]["is_error"] and "deny rule" in results["b1"]["content"]
    assert results["w1"]["is_error"]
    assert not results["w2"]["is_error"] and not results["r1"]["is_error"]
    assert (lab_repo / "specs" / "lab1.yml").read_text() == "lab:\n  name: lab1\n"
    assert (lab_repo / "generated" / "lab1" / "lab-report.md").read_text() == "# lab1 report"
    task = llm.requests[0]["messages"][0].content
    assert "forge validate specs/lab1.yml --run" in task and "generated/lab1/lab-report.md" in task


def test_preconditions(lab_repo):
    agent = ValidatorAgent(ScriptedLLM(), repo_root=lab_repo)
    with pytest.raises(ValidatorPreconditionError, match="spec not found"):
        agent.lab_context("specs/nope.yml")
    (lab_repo / "generated" / "lab1" / "lab-manifest.json").unlink()
    with pytest.raises(ValidatorPreconditionError, match="forge generate"):
        agent.lab_context("specs/lab1.yml")
