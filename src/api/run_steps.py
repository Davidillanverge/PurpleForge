"""The steps of a forge operation, rebuilt from a run's streamed output.

deploy.sh / teardown.sh / stop.sh … announce each phase as ``== <title>`` and the
Ansible phase prints ``PLAY [..]`` / ``TASK [..]`` / ``fatal:`` / ``PLAY RECAP``.
Both the no-AI forge runs and the agents' background forge jobs stream that output
as ``tool_output`` events, so the run console can show where an operation is —
every phase, the current play/task, failures — while it runs.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

_PHASE = re.compile(r"^== (.+?)\s*$")
_PLAY = re.compile(r"^PLAY \[(.+?)\]")
_TASK = re.compile(r"^TASK \[(.+?)\]")
_FATAL = re.compile(r"^(fatal|failed): \[([^\]]+)\]")
_RECAP_HOST = re.compile(r"^(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)")
_WARN = re.compile(r"^(WARN|FAIL|ERROR)\b[: ]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
#: deploy.sh's own banners that aren't phases
_NOT_PHASES = ("guardrail gate", "DEPLOY ", "TEARDOWN ", "STOP ", "START ", "RESTART ", "RESET ")


@dataclass
class Phase:
    title: str
    status: str = "done"  # done | running | failed
    plays: int = 0
    tasks: int = 0


@dataclass
class RecapHost:
    host: str
    ok: int
    changed: int
    unreachable: int
    failed: int


@dataclass
class ForgeSteps:
    command: str
    phases: list[Phase] = field(default_factory=list)
    current_play: str | None = None
    current_task: str | None = None
    tasks_seen: int = 0
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recap: list[RecapHost] = field(default_factory=list)
    finished: bool = False
    exit_code: int | None = None
    last_lines: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.finished and self.exit_code == 0


def _parse(text: str, steps: ForgeSteps) -> None:
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).rstrip()
        if not line:
            continue
        if m := _PHASE.match(line):
            title = m.group(1)
            if title.startswith(_NOT_PHASES) or title.startswith("Connectivity check"):
                continue
            steps.phases.append(Phase(title=title, status="running"))
            steps.current_play = steps.current_task = None
        elif m := _PLAY.match(line):
            steps.current_play, steps.current_task = m.group(1), None
            if steps.phases:
                steps.phases[-1].plays += 1
        elif m := _TASK.match(line):
            steps.current_task = m.group(1)
            steps.tasks_seen += 1
            if steps.phases:
                steps.phases[-1].tasks += 1
        elif m := _FATAL.match(line):
            where = f"{steps.current_task or steps.current_play or '?'} @ {m.group(2)}"
            steps.failures.append(f"{where}: {line[len(m.group(0)) :].strip()[:300]}")
        elif m := _RECAP_HOST.match(line):
            h, ok, ch, un, fa = m.groups()
            steps.recap = [r for r in steps.recap if r.host != h]
            steps.recap.append(RecapHost(h, int(ok), int(ch), int(un), int(fa)))
        elif _WARN.match(line):
            (steps.failures if line.startswith(("FAIL", "ERROR")) else steps.warnings).append(line[:300])
        steps.last_lines.append(line)
    steps.last_lines = steps.last_lines[-8:]


def forge_steps(events: Sequence[Any]) -> list[ForgeSteps]:
    """One ForgeSteps per forge call of the run that streamed output, in call order."""
    calls: dict[str, ForgeSteps] = {}
    order: list[str] = []
    for e in events:
        d = e.data or {}
        cid = str(d.get("id"))
        if e.type == "tool_call" and d.get("name") == "forge":
            a = d.get("arguments") or {}
            calls[cid] = ForgeSteps(command=f"forge {a.get('subcommand', '')} {' '.join(a.get('args') or [])}".strip())
        elif e.type == "tool_output" and cid in calls:
            if cid not in order:
                order.append(cid)
            _parse(d.get("content", ""), calls[cid])
        elif e.type == "tool_result" and cid in calls:
            data = d.get("data") or {}
            if data.get("background") and not data.get("final"):
                continue  # the "started in background" ack, not the end
            st = calls[cid]
            st.finished, st.exit_code = True, data.get("exit_code")
    out = [calls[c] for c in order]
    for st in out:
        if st.phases:
            last = st.phases[-1]
            if st.finished:
                last.status = "done" if st.exit_code == 0 else "failed"
            for p in st.phases[:-1]:
                p.status = "done"
    return out
