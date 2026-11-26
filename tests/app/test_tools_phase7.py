"""Phase 7 tool guards: forge spec lock, approval-by-default bash, edit/grep/glob, web_fetch allowlist,
deploy toolchain preflight, catalog_check."""

from __future__ import annotations

import shutil
from pathlib import Path

import httpx
import pytest

from agents.catalog_author import CatalogCheckInput, CatalogCheckTool
from agents.deploy_operator import (
    DEPLOY_BASH_DENY,
    READONLY_BASH,
    DeployOperatorAgent,
    DeployPreconditionError,
    Mode,
    missing_prerequisites,
)
from agents.tools import (
    BashInput,
    BashTool,
    FileEditInput,
    FileEditTool,
    ForgeInput,
    ForgeTool,
    GlobInput,
    GlobTool,
    GrepInput,
    GrepTool,
    WebFetchInput,
    WebFetchTool,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- forge spec lock


def _forge(tmp_path, **kw):
    (tmp_path / "specs").mkdir(exist_ok=True)
    (tmp_path / "specs" / "a.yml").write_text("lab:\n  name: lab-a\n")
    return ForgeTool(tmp_path, spec_lock="specs/a.yml", **kw)


def test_spec_lock_refuses_other_labs_before_asking_a_human(tmp_path):
    tool = _forge(
        tmp_path,
        allowed_subcommands={"deploy", "teardown", "lab-spec"},
        forbidden_flags={"--skip-guardrail"},
        required_flags={"teardown": {"--force"}, "lab-spec": {"--check-only"}},
    )
    ok = ForgeInput(subcommand="deploy", args=["specs/a.yml"])
    assert tool.refusal(ok) is None and "acts on live infrastructure" in tool.needs_approval(ok)
    for bad, why in [
        (ForgeInput(subcommand="deploy", args=["specs/b.yml"]), "only act on"),
        (ForgeInput(subcommand="deploy", args=["specs/../specs/b.yml"]), "only act on"),
        (ForgeInput(subcommand="deploy", args=[]), "no spec"),
        (ForgeInput(subcommand="deploy", args=["specs/a.yml", "--skip-guardrail"]), "--skip-guardrail"),
        (ForgeInput(subcommand="deploy", args=["specs/a.yml", "--out-dir=/tmp/x"]), "--out-dir"),
        (ForgeInput(subcommand="teardown", args=["specs/a.yml"]), "--force"),
        (ForgeInput(subcommand="lab-spec", args=["specs/a.yml"]), "--check-only"),
    ]:
        assert why in tool.refusal(bad), bad
        assert tool.needs_approval(bad) is None  # never page a human for a call that can't run
    assert tool.refusal(ForgeInput(subcommand="deploy", args=["./specs/a.yml"])) is None  # same file


def test_spec_lock_pins_out_dir_to_the_service_tree(tmp_path):
    tool = _forge(tmp_path, allowed_subcommands={"lab-spec"})
    assert tool._pinned_out_dir() == ["--out-dir", str(tmp_path / "generated" / "lab-a")]
    assert ForgeTool(tmp_path, allowed_subcommands={"x"})._pinned_out_dir() == []


# --------------------------------------------------------------------------- bash approval-by-default


@pytest.fixture
def deploy_bash(tmp_path):
    return BashTool(tmp_path, deny_patterns=DEPLOY_BASH_DENY, approve_unless_readonly=READONLY_BASH, environ={})


@pytest.mark.parametrize(
    "cmd",
    [
        "terraform -chdir=generated/x/terraform/azure output -json",
        "terraform state list",
        "az group show -n pf-lab",
        "az vm list -g pf-lab",
        "aws ec2 describe-instances --filters Name=tag:pf:lab,Values=x",
        "aws sts get-caller-identity",
        "cat generated/x/deploy.log",
        "wg show",
    ],
)
def test_readonly_commands_run_without_approval(deploy_bash, cmd):
    assert deploy_bash.needs_approval(BashInput(command=cmd)) is None


@pytest.mark.parametrize(
    "cmd",
    [
        "terraform apply -auto-approve",
        "terraform destroy",
        "az group delete -n pf-lab --yes",
        "aws ec2 terminate-instances --instance-ids i-1",
        "bash generated/x/deploy.sh generated/x",
        "terraform output; terraform destroy -auto-approve",  # chaining hides a write behind a read
        "cat x | sh",
        "terraform output $(rm -rf generated)",
        "ls > /tmp/x",
    ],
)
def test_everything_else_needs_a_human(deploy_bash, cmd):
    assert deploy_bash.needs_approval(BashInput(command=cmd)) is not None


@pytest.mark.parametrize(
    "cmd",
    [
        "env",
        "printenv AWS_SECRET_ACCESS_KEY",
        "cat .env",
        "cat ~/.aws/credentials",
        "az account get-access-token",
        "aws secretsmanager get-secret-value --secret-id x",
        "az keyvault secret show --name x --vault-name v",
    ],
)
async def test_credential_exfiltration_is_refused(deploy_bash, cmd):
    assert deploy_bash.needs_approval(BashInput(command=cmd)) is None  # refused, not escalated
    res = await deploy_bash.run(BashInput(command=cmd))
    assert res.is_error and "deny rule" in res.content


# --------------------------------------------------------------------------- edit / grep / glob


async def test_edit_file(tmp_path):
    f = tmp_path / "specs" / "a.yml"
    f.parent.mkdir()
    f.write_text("a: 1\nb: 1\n")
    tool = FileEditTool(tmp_path, roots=[f])
    assert (await tool.run(FileEditInput(path="specs/a.yml", old_string="a: 1", new_string="a: 2"))).content.startswith(
        "replaced"
    )
    assert f.read_text() == "a: 2\nb: 1\n"
    dup = await tool.run(FileEditInput(path="specs/a.yml", old_string=": ", new_string="="))
    assert dup.is_error and "occurs 2 times" in dup.content
    assert not (
        await tool.run(FileEditInput(path="specs/a.yml", old_string=": ", new_string="=", replace_all=True))
    ).is_error
    (tmp_path / "specs" / "b.yml").write_text("x")
    assert (await tool.run(FileEditInput(path="specs/b.yml", old_string="x", new_string="y"))).is_error  # not its file


async def test_grep_and_glob_are_read_only_and_hide_secrets(tmp_path):
    (tmp_path / "catalog").mkdir()
    (tmp_path / "catalog" / "k.yml").write_text("id: kerberoasting\nmitre: T1558.003\n")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-secret-T1558\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("T1558")
    grep = await GrepTool(tmp_path).run(GrepInput(pattern=r"T1558"))
    assert "catalog/k.yml:2: mitre: T1558.003" in grep.content
    assert "sk-secret" not in grep.content and ".git" not in grep.content
    glob = await GlobTool(tmp_path).run(GlobInput(pattern="**/*"))
    assert "catalog/k.yml" in glob.content and ".env" not in glob.content
    assert (await GlobTool(tmp_path).run(GlobInput(pattern="../*"))).is_error
    assert (await GrepTool(tmp_path).run(GrepInput(pattern="(", path="."))).is_error  # bad regex


# --------------------------------------------------------------------------- web_fetch


def _web(handler):
    return WebFetchTool(["attack.mitre.org"], transport=httpx.MockTransport(handler))


async def test_web_fetch_allowlist_and_untrusted_label():
    def handler(request):
        if request.url.path == "/redirect-out":
            return httpx.Response(302, headers={"location": "https://evil.example/x"})
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><script>alert(1)</script><h1>Kerberoasting</h1><p>ID: T1558.003</p></html>",
        )

    tool = _web(handler)
    ok = await tool.run(WebFetchInput(url="https://attack.mitre.org/techniques/T1558/003/"))
    assert ok.content.startswith("[untrusted web content") and "T1558.003" in ok.content and "alert" not in ok.content
    assert "not on this agent's allowlist" in (await tool.run(WebFetchInput(url="https://evil.example/"))).content
    assert "https" in (await tool.run(WebFetchInput(url="http://attack.mitre.org/"))).content
    hop = await tool.run(WebFetchInput(url="https://attack.mitre.org/redirect-out"))
    assert hop.is_error and "refused redirect" in hop.content


# --------------------------------------------------------------------------- deploy preflight


def test_missing_prerequisites_by_provider_and_mode():
    nothing = lambda _b: None  # noqa: E731
    assert set(missing_prerequisites("azure", Mode.DEPLOY, which=nothing)) >= {"terraform", "docker", "az", "wg-quick"}
    assert "aws" in missing_prerequisites("aws", Mode.TEARDOWN, which=nothing)
    assert "wg-quick" not in missing_prerequisites("aws", Mode.TEARDOWN, which=nothing)  # no tunnel to tear down
    everything = lambda b: f"/usr/bin/{b}"  # noqa: E731
    assert missing_prerequisites("azure", Mode.DEPLOY, which=everything) == []


def test_deploy_preflight_names_what_is_missing(tmp_path):
    agents_dir = tmp_path / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    shutil.copy(REPO_ROOT / ".claude" / "agents" / "deploy-operator.md", agents_dir)
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "x.yml").write_text("lab:\n  name: x-lab\n  provider: aws\n")
    agent = DeployOperatorAgent(None, repo_root=tmp_path)  # type: ignore[arg-type]
    with pytest.raises(DeployPreconditionError, match="missing on PATH: .*terraform.*aws"):
        agent.lab_context("specs/x.yml", Mode.DEPLOY, which=lambda _b: None)
    assert agent.lab_context("specs/x.yml", Mode.DEPLOY, which=lambda b: b) == ("specs/x.yml", "x-lab", "aws")
    with pytest.raises(DeployPreconditionError, match="generated/x-lab"):
        agent.lab_context("specs/x.yml", Mode.TEARDOWN, which=lambda b: b)


def test_deploy_tools_by_mode(tmp_path):
    (tmp_path / ".claude" / "agents").mkdir(parents=True)
    shutil.copy(REPO_ROOT / ".claude" / "agents" / "deploy-operator.md", tmp_path / ".claude" / "agents")
    agent = DeployOperatorAgent(None, repo_root=tmp_path)  # type: ignore[arg-type]
    deploy = {t.name: t for t in agent.build_tools("specs/x.yml", Mode.DEPLOY)}
    teardown = {t.name: t for t in agent.build_tools("specs/x.yml", Mode.TEARDOWN)}
    assert "write_file" not in deploy and "edit_file" not in deploy  # md: Bash, Read, Grep, Glob
    assert deploy["forge"].allowed == {"lab-spec", "generate", "guardrail", "deploy"}
    assert teardown["forge"].allowed == {"teardown"}  # a deploy run can't tear down, and vice versa


# --------------------------------------------------------------------------- catalog_check


async def test_catalog_check_uses_forge_schemas(tmp_path):
    shutil.copytree(REPO_ROOT / "catalog", tmp_path / "catalog")
    tool = CatalogCheckTool(tmp_path)
    ok = await tool.run(CatalogCheckInput(action="validate_file", path="catalog/vulnerabilities/asreproast.yml"))
    assert not ok.is_error and ok.content.rstrip().endswith("OK"), ok.content

    broken = tmp_path / "catalog" / "vulnerabilities" / "broken.yml"
    broken.write_text("id: broken\nname: Broken\n")
    bad = await tool.run(CatalogCheckInput(action="validate_file", path="catalog/vulnerabilities/broken.yml"))
    assert bad.is_error and "FAIL" in bad.content

    outside = await tool.run(CatalogCheckInput(action="validate_file", path="specs/x.yml"))
    assert outside.is_error and "outside the allowed paths" in outside.content
    assert (await tool.run(CatalogCheckInput(action="lab_spec_check", path="specs/x.yml"))).is_error  # scratch only
