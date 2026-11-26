"""Deterministic run outcomes — shared by the standalone engine and the MCP server.

The lab's next state is computed from what actually happened (the persisted
tool calls/results and approvals), never from what the agent — or Claude Code —
claims. Both modes persist the same event shapes (``tool_call``,
``tool_result``, ``approval_resolved``), so they share these functions.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from db.states import LabState


class EventLike(Protocol):
    type: str
    data: dict[str, Any]


@dataclass
class Outcome:
    target: LabState
    reason: str
    error: str | None = None


def _calls_and_results(events: Sequence[EventLike]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    calls = {str(e.data.get("id")): e.data for e in events if e.type == "tool_call"}
    results = {str(e.data.get("id")): e.data for e in events if e.type == "tool_result"}
    return calls, results


def forge_call_succeeded(events: Sequence[EventLike], subcommand: str) -> bool:
    """Did a `forge <subcommand>` call actually run and exit 0?"""
    calls, results = _calls_and_results(events)
    for cid, call in calls.items():
        if call.get("name") == "forge" and (call.get("arguments") or {}).get("subcommand") == subcommand:
            res = results.get(cid) or {}
            if (res.get("data") or {}).get("exit_code") == 0:
                return True
    return False


def approved_action_ran(events: Sequence[EventLike]) -> bool:
    """Did any human-approved (= potentially infra-touching) tool call execute?"""
    _, results = _calls_and_results(events)
    approved = {str(e.data.get("id")) for e in events if e.type == "approval_resolved" and e.data.get("approved")}
    return any(cid in results for cid in approved)


def deploy_outcome(events: Sequence[EventLike], error: str | None = None) -> Outcome:
    if forge_call_succeeded(events, "deploy"):
        return Outcome(LabState.DEPLOYED, "forge deploy exited 0 (clean snapshot taken by deploy.sh)")
    if approved_action_ran(events):
        why = error or "forge deploy did not succeed"
        return Outcome(LabState.FAILED, f"deploy failed after touching infrastructure: {why}", error=why)
    return Outcome(LabState.READY, "deploy never touched infrastructure (no approved action ran) — re-approve to retry")


def teardown_outcome(events: Sequence[EventLike], previous_state: LabState | None, error: str | None = None) -> Outcome:
    if forge_call_succeeded(events, "teardown"):
        return Outcome(LabState.DESTROYED, "forge teardown exited 0 (cost-zero verified)")
    if approved_action_ran(events):
        why = error or "forge teardown did not succeed"
        return Outcome(LabState.FAILED, f"teardown incomplete — resources may remain: {why}", error=why)
    if previous_state in (LabState.DEPLOYED, LabState.VALIDATED, LabState.STOPPED):
        return Outcome(previous_state, "teardown never touched infrastructure (no approved action ran)")
    # came from FAILED: stays failed (still possibly billable)
    return Outcome(LabState.FAILED, "teardown never ran — the lab still needs one", error="teardown not executed")


def validate_outcome(events: Sequence[EventLike]) -> Outcome:
    """`forge validate --run` exit 0 → VALIDATED. A failed validation says nothing bad
    about the lab itself → back to DEPLOYED (never FAILED: that means 'maybe billable leftovers')."""
    if forge_call_succeeded(events, "validate"):
        return Outcome(LabState.VALIDATED, "forge validate --run exited 0")
    return Outcome(LabState.DEPLOYED, "validation did not complete — the lab is unchanged")


def stop_outcome(events: Sequence[EventLike]) -> Outcome:
    """`forge stop` exit 0 → STOPPED. Otherwise the VMs are assumed still running:
    back to DEPLOYED (a validation isn't assumed to survive a half-done stop)."""
    if forge_call_succeeded(events, "stop"):
        return Outcome(LabState.STOPPED, "forge stop exited 0 (VMs powered off, Terraform state untouched)")
    return Outcome(LabState.DEPLOYED, "forge stop did not succeed — VMs may still be running", error="stop failed")


def start_outcome(events: Sequence[EventLike]) -> Outcome:
    """`forge start` exit 0 → DEPLOYED (powered on, tunnel up, connectivity checked).
    A failed start stays STOPPED: some VMs may be up, a retry or stop fixes it."""
    if forge_call_succeeded(events, "start"):
        return Outcome(LabState.DEPLOYED, "forge start exited 0 (VMs on, WireGuard tunnel up, connectivity OK)")
    return Outcome(LabState.STOPPED, "forge start did not succeed — some VMs may be running", error="start failed")
