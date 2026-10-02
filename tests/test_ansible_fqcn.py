"""Ansible module FQCN lint for the vuln/hardening templates.

Guards the bug class behind AWS-DEPLOY-RUNBOOK bug #7: a task referenced
`ansible.windows.win_firewall_rule`, but that module ships in the
**community.windows** collection, not `ansible.windows` — so vuln-injection
aborted at deploy time with "couldn't resolve module/action". That is invisible
until a live deploy and expensive to discover there.

This lint catches it at test time with no Ansible/collection install: it scans
every rendered-template source under `templates/` for `ansible.windows.<module>`
references and fails if any names a module that does NOT ship in ansible.windows
(i.e. it belongs to another collection and the FQCN is wrong).

The check is a denylist of modules known to live in **community.windows** (not
ansible.windows). It cannot false-positive on a legitimate ansible.windows
module; extend `COMMUNITY_WINDOWS_MODULES` when a new misplacement shows up.
"""

from __future__ import annotations

import re

from _helpers import REPO_ROOT

TEMPLATES_DIR = REPO_ROOT / "templates"

# Modules that ship in community.windows (NOT ansible.windows). Writing any of
# these as `ansible.windows.<name>` is the bug #7 class. Seeded with the firewall
# family that caused it; add others as they surface.
COMMUNITY_WINDOWS_MODULES = {
    "win_firewall",
    "win_firewall_rule",
    "win_robocopy",
    "win_scheduled_task",
    "win_dns_record",
    "win_pagefile",
    "win_psmodule",
    "win_rds_cap",
    "win_region",
    "win_timezone",
}

_FQCN_RE = re.compile(r"\bansible\.windows\.([a-z0-9_]+)")


def _template_sources():
    for path in TEMPLATES_DIR.rglob("*"):
        if path.is_file() and path.suffix in {".yml", ".yaml", ".j2"}:
            yield path


def test_no_misplaced_ansible_windows_fqcn():
    offenders = []
    for path in _template_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for mod in _FQCN_RE.findall(line):
                if mod in COMMUNITY_WINDOWS_MODULES:
                    rel = path.relative_to(REPO_ROOT)
                    offenders.append(
                        f"{rel}:{lineno}: ansible.windows.{mod} -> should be community.windows.{mod}"
                    )
    assert not offenders, "Wrong module collection (FQCN) in template(s):\n" + "\n".join(offenders)
