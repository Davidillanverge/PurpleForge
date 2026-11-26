"""PurpleForge MCP server — the second execution mode.

Standalone mode: AgentEngine + LLM pool (Anthropic/Gemini/Ollama) drive the agents.
MCP mode (this): Claude Code / Cursor / Claude Desktop IS the LLM. This server
exposes the deterministic lab operations over the SAME database, FSM, services,
ForgeTool policy and outcomes, and the agent instructions as prompts loaded from
``.claude/agents/*.md``.

What the MCP mode can NOT do: approve. Deploy/teardown create a pending approval
in the shared table; a human decides it in the dashboard/API (actor ``user:…``).

    python -m mcp_server        # stdio (Claude Code launches it via .mcp.json)
"""

from __future__ import annotations

from fastmcp import FastMCP

from agents.definitions import load_agent_definition
from agents.deploy_operator import Mode
from db import repository as repo
from mcp_server import ops
from mcp_server.context import get_context

mcp = FastMCP(
    "purpleforge",
    instructions=(
        "PurpleForge builds isolated purple-team Active Directory labs from specs/<lab>.yml. "
        "Use the lab_* tools for every lab operation so the lab state machine, the deterministic "
        "forge gates and the human approval gate apply. NEVER run `forge deploy`, `forge teardown`, "
        "`terraform apply/destroy` or cloud CLIs that change resources through your shell: use "
        "lab_deploy / lab_teardown, which wait for a human approval in the dashboard."
    ),
)


def _err(exc: Exception) -> str:
    return f"ERROR: {exc}"


# --------------------------------------------------------------------------- read


@mcp.tool
async def lab_list() -> str:
    """List every lab with its state, cloud, spec and tokens consumed by agents."""
    return await _lab_list_text()


async def _lab_list_text() -> str:
    ctx = await get_context()
    async with ctx.sessionmaker() as s:
        labs = await repo.list_labs(s, ctx.tenant)
        usage = await repo.usage_by_lab(s, ctx.tenant)
    if not labs:
        return "No labs yet. Create one with lab_create."
    rows = [
        f"- {lab.name}: {lab.state.value} | cloud={lab.cloud or '-'} | spec={lab.spec_path or '-'}"
        f" | tokens={usage[lab.id].total_tokens if lab.id in usage else 0}"
        for lab in labs
    ]
    return "\n".join(rows)


@mcp.tool
async def lab_status(lab: str) -> str:
    """State, spec, recent timeline, runs (engine or MCP), pending approvals and the next step for a lab."""
    return await _lab_status_text(lab)


async def _lab_status_text(lab: str) -> str:
    ctx = await get_context()
    try:
        async with ctx.sessionmaker() as s:
            obj = await ops._lab(ctx, lab, session=s)
            transitions = list(await repo.list_transitions(s, ctx.tenant, obj.id))[-6:]
            runs = list(await repo.list_runs(s, ctx.tenant, lab_id=obj.id, limit=5))
            pending = [a for a in await repo.list_pending_approvals(s, ctx.tenant) if a.lab_id == obj.id]
            usage = await repo.usage_total(s, ctx.tenant, lab_id=obj.id)
    except ops.McpError as exc:
        return _err(exc)
    lines = [
        f"Lab {obj.name}: **{obj.state.value}** (cloud={obj.cloud or '-'}, spec={obj.spec_path or '-'})",
        f"Tokens by engine agents: {usage.total_tokens} over {usage.runs} runs",
    ]
    if obj.last_error:
        lines.append(f"Last error: {obj.last_error}")
    lines.append("Timeline (latest last):")
    lines += [
        f"  {t.at:%Y-%m-%d %H:%M:%SZ} {t.from_state.value if t.from_state else '∅'} → {t.to_state.value}"
        f" by {t.actor}: {t.reason}"
        for t in transitions
    ]
    if runs:
        lines.append("Recent runs:")
        lines += [f"  {r.id} {r.agent} [{r.source}] {r.status.value}{' — ' + r.error if r.error else ''}" for r in runs]
    for a in pending:
        lines.append(f"⏸ Pending human approval {a.id}: {a.reason} → {ctx.mcp.dashboard_url}/approvals")
    lines.append(f"Dashboard: {ctx.mcp.dashboard_url}/labs/{obj.id}")
    lines.append("Next: " + _next_step(obj.state.value))
    return "\n".join(lines)


def _next_step(state: str) -> str:
    return {
        "draft": "lab_design_start (then write the spec with your own file tools, then lab_design_finish)",
        "designing": "finish writing the spec, then lab_design_finish",
        "designed": "lab_check, then lab_compile (forge lab-spec + guardrail)",
        "compiled": "lab_compile again (guardrail did not pass) or fix the spec",
        "ready": "a HUMAN reviews cost/isolation and approves the lab in the dashboard",
        "approved": "lab_deploy (asks a human to approve the actual forge deploy)",
        "deploying": "wait — check lab_status / the dashboard",
        "deployed": "lab_validate, or lab_teardown when done",
        "validating": "wait — check lab_status / the dashboard",
        "validated": "lab_teardown when done (cost!)",
        "destroying": "wait — check lab_status / the dashboard",
        "destroyed": "lab_design_start to redesign, or leave it",
        "failed": "lab_teardown — the only way out of failed (resources may remain)",
    }.get(state, "see the dashboard")


@mcp.tool
async def approvals_pending() -> str:
    """Pending human approvals (decided by a human in the dashboard, never by you)."""
    ctx = await get_context()
    async with ctx.sessionmaker() as s:
        pending = await repo.list_pending_approvals(s, ctx.tenant)
    if not pending:
        return "Nothing pending."
    return "\n".join(f"- {a.id}: {a.tool_name} {a.arguments} — {a.reason}" for a in pending) + (
        f"\nA human approves or denies them at {ctx.mcp.dashboard_url}/approvals"
    )


# --------------------------------------------------------------------------- deterministic


@mcp.tool
async def lab_create(name: str, description: str = "", spec_path: str | None = None) -> str:
    """Create a lab. Lowercase name (letters, digits, '-'). If specs/<name>.yml exists it is
    picked up and the lab starts DESIGNED; otherwise it starts as a DRAFT. The description is
    what the designer will build."""
    ctx = await get_context()
    try:
        lab = await ops.create_lab(ctx, name, description, spec_path)
    except Exception as exc:  # noqa: BLE001 - surfaced to the client
        return _err(exc)
    return f"Lab {lab.name} created in state {lab.state.value}. Dashboard: {ctx.mcp.dashboard_url}/labs/{lab.id}"


@mcp.tool
async def lab_check(lab: str) -> str:
    """`forge lab-spec --check-only`: validate the lab's spec. Writes nothing, changes no state."""
    ctx = await get_context()
    try:
        out = await ops.check(ctx, lab)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return ("OK" if out.ok else "FAILED") + "\n" + out.steps[0].output


@mcp.tool
async def lab_compile(lab: str) -> str:
    """`forge lab-spec` + `forge guardrail` (deterministic). DESIGNED → COMPILED → READY on a PASS.
    Recompiling drops any approval. READY then needs a HUMAN approval in the dashboard."""
    ctx = await get_context()
    try:
        obj, out = await ops.compile_(ctx, lab)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    body = "\n\n".join(f"$ {st.command} → exit {st.exit_code}\n{st.output}" for st in out.steps)
    return f"Lab {obj.name} is now {obj.state.value}.\n\n{body}"


@mcp.tool
async def lab_generate(lab: str) -> str:
    """`forge generate`: Terraform + Ansible + lifecycle scripts into generated/<lab>/. Cloud-free,
    deterministic, changes no state. generated/ contains lab secrets — don't paste them anywhere."""
    ctx = await get_context()
    try:
        out = await ops.generate(ctx, lab)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    if not out.ok:
        return "FAILED\n" + out.steps[0].output
    return f"Generated {len(out.files)} files in {out.out_dir}:\n" + "\n".join(out.files[:200])


# --------------------------------------------------------------------------- design


@mcp.tool
async def lab_design_start(lab: str, request: str = "") -> str:
    """Start designing a lab (DRAFT/DESIGNED/… → DESIGNING). Returns the exact task: which spec
    file to write with your own file tools, the schema to follow and the checks to pass.
    Finish with lab_design_finish."""
    ctx = await get_context()
    try:
        run, task = await ops.design_start(ctx, lab, request)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return f"Design run {run.id} started.\n\n{task}\n\nWhen the spec is written, call lab_design_finish('{lab}')."


@mcp.tool
async def lab_design_finish(lab: str) -> str:
    """Close the design: forge checks the spec on disk and decides the state (DESIGNED, or back
    to DRAFT if no valid spec exists). Your own judgement of the spec doesn't count."""
    ctx = await get_context()
    try:
        outcome = await ops.design_finish(ctx, lab)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return f"{lab} → {outcome.target.value}: {outcome.reason}"


# --------------------------------------------------------------------------- gated / long-running


@mcp.tool
async def lab_deploy(lab: str) -> str:
    """Deploy an APPROVED lab. Runs `forge generate`, then requests a HUMAN approval for
    `forge deploy` and returns immediately. After approval the deploy runs in the background
    (guardrail gate, deploy.sh, clean snapshot); follow it with lab_status. You cannot approve it."""
    ctx = await get_context()
    try:
        run, approval_id = await ops.gated(ctx, lab, Mode.DEPLOY)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return (
        f"⏸ Waiting for a human: approval {approval_id} for `forge deploy` of {lab}.\n"
        f"Approve or deny at {ctx.mcp.dashboard_url}/approvals — the deploy then runs in the background.\n"
        f"Live console: {ctx.mcp.dashboard_url}/runs/{run.id} · poll with lab_status('{lab}')."
    )


@mcp.tool
async def lab_teardown(lab: str) -> str:
    """Tear a lab down to cost-zero (`forge teardown --force` + verification). Requests a HUMAN
    approval and returns immediately; runs in the background after approval."""
    ctx = await get_context()
    try:
        run, approval_id = await ops.gated(ctx, lab, Mode.TEARDOWN)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return (
        f"⏸ Waiting for a human: approval {approval_id} for `forge teardown` of {lab}.\n"
        f"Approve or deny at {ctx.mcp.dashboard_url}/approvals. Live console: {ctx.mcp.dashboard_url}/runs/{run.id}"
    )


@mcp.tool
async def lab_validate(lab: str) -> str:
    """Validate a DEPLOYED lab: `forge validate <spec> --run` over the tunnel, in the background.
    VALIDATED only if forge exits 0. Follow it with lab_status; then write lab-report.md as the
    purple_validator prompt describes."""
    ctx = await get_context()
    try:
        run = await ops.validate(ctx, lab)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return f"Validation of {lab} started (run {run.id}). Live console: {ctx.mcp.dashboard_url}/runs/{run.id}"


# --------------------------------------------------------------------------- resources


@mcp.resource("lab://list")
async def labs_resource() -> str:
    """All labs and their states."""
    return await _lab_list_text()


@mcp.resource("lab://{name}")
async def lab_resource(name: str) -> str:
    """One lab: state, timeline, runs, approvals, next step."""
    return await _lab_status_text(name)


# --------------------------------------------------------------------------- prompts (.claude/agents/*.md)

_PREAMBLE = """# Runtime: PurpleForge MCP mode

You are running inside an MCP client (e.g. Claude Code) with the `purpleforge` MCP server.
The instructions below were written for the PurpleForge agents; apply them like this:

- Lab operations go through the MCP tools: lab_status, lab_create, lab_design_start / lab_design_finish,
  lab_check, lab_compile, lab_generate, lab_deploy, lab_teardown, lab_validate, approvals_pending.
- You may read the repo and write the spec (`specs/<lab>.yml`) / catalog files with your own file tools.
- NEVER run `forge deploy|teardown|destroy|reset`, `terraform apply|destroy` or resource-changing cloud
  CLIs from your shell — use lab_deploy / lab_teardown: they enforce the guardrail, the spec lock and a
  HUMAN approval in the dashboard, and record the lab state. You cannot approve anything yourself.
- The lab state is decided by forge's exit codes, not by your report.

---

"""


def _agent_prompt(agent: str, task: str) -> str:
    from mcp_server.context import _ctx

    root = _ctx.app.repo_root if _ctx is not None else None
    if root is None:
        from api.settings import AppSettings

        root = AppSettings().repo_root
    body = load_agent_definition(root, agent).body
    return f"{_PREAMBLE}{body}\n\n## Your task\n\n{task}\n"


@mcp.prompt
def lab_designer(lab: str, request: str = "") -> str:
    """Design a lab: natural-language request → specs/<lab>.yml (via lab_design_start / _finish)."""
    return _agent_prompt(
        "lab-designer",
        f"Design the lab `{lab}`{': ' + request if request else ''}. Create it with lab_create if it doesn't "
        f"exist, call lab_design_start('{lab}'), write the spec it tells you to, make "
        f"lab_check('{lab}') pass, then lab_design_finish('{lab}') and lab_compile('{lab}').",
    )


@mcp.prompt
def deploy_operator(lab: str) -> str:
    """Deploy an approved lab (human approval required for the actual deploy)."""
    return _agent_prompt(
        "deploy-operator",
        f"Deploy `{lab}`: check lab_status('{lab}') is approved, call lab_deploy('{lab}'), tell the user to "
        f"approve it in the dashboard, then follow it with lab_status until it is deployed or failed.",
    )


@mcp.prompt
def purple_validator(lab: str) -> str:
    """Validate a deployed lab and write lab-report.md."""
    return _agent_prompt(
        "purple-validator",
        f"Validate `{lab}`: lab_validate('{lab}'), follow it with lab_status, complete the interactive checks "
        f"over the tunnel as described above, then write generated/{lab}/lab-report.md.",
    )


@mcp.prompt
def catalog_author(request: str) -> str:
    """Author or edit catalog content (vulns, themes, defense)."""
    return _agent_prompt("catalog-author", request)
