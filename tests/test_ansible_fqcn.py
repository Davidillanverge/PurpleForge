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

# Allowlist of FQCN module invocations that are KNOWN to exist in their collection
# AND are deliberately used by the templates. The denylist above catches a real
# module under the wrong collection prefix; this allowlist catches the other half
# of the bug class — a module that does not exist in ANY collection (e.g. the
# invented `community.windows.win_iis_webconfigproperty` that aborted a live deploy
# — use win_shell + Set-WebConfigurationProperty instead). A new module here forces
# a conscious "does this module actually exist?" check before it can ship.
# Keep sorted; add a line only after verifying the module is real.
VALID_MODULE_FQCNS = {
    # ansible.builtin
    "ansible.builtin.assert",
    "ansible.builtin.debug",
    "ansible.builtin.include_role",
    "ansible.builtin.include_tasks",
    "ansible.builtin.set_fact",
    # ansible.windows
    "ansible.windows.win_acl",
    "ansible.windows.win_command",
    "ansible.windows.win_copy",
    "ansible.windows.win_dsc",
    "ansible.windows.win_feature",
    "ansible.windows.win_file",
    "ansible.windows.win_get_url",
    "ansible.windows.win_package",
    "ansible.windows.win_powershell",
    "ansible.windows.win_reboot",
    "ansible.windows.win_regedit",
    "ansible.windows.win_service",
    "ansible.windows.win_shell",
    "ansible.windows.win_stat",
    "ansible.windows.win_template",
    "ansible.windows.win_uri",
    "ansible.windows.win_user",
    "ansible.windows.win_user_right",
    "ansible.windows.win_wait_for",
    # community.general
    "community.general.random_string",
    # community.windows
    "community.windows.win_domain_computer",
    "community.windows.win_domain_group_membership",
    "community.windows.win_domain_ou",
    "community.windows.win_firewall_rule",
    "community.windows.win_iis_webapppool",
    "community.windows.win_scheduled_task",
}

# Matches an FQCN used as a task module KEY (not prose/comments): `<fqcn>:` at the
# start of a line, optionally after a YAML list dash.
_MODULE_KEY_RE = re.compile(
    r"^\s*(?:-\s+)?((?:ansible\.(?:windows|builtin|utils)|community\.(?:windows|general))\.[a-z0-9_]+):",
)


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


def test_only_known_modules_used():
    """Every FQCN module invoked by a template must be a real module we've vetted
    (in VALID_MODULE_FQCNS). Catches an invented/typo'd module that resolves in no
    collection — the win_iis_webconfigproperty class — at test time, not live."""
    offenders = []
    for path in _template_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            m = _MODULE_KEY_RE.match(line)
            if m and m.group(1) not in VALID_MODULE_FQCNS:
                rel = path.relative_to(REPO_ROOT)
                offenders.append(
                    f"{rel}:{lineno}: {m.group(1)} is not in VALID_MODULE_FQCNS "
                    f"(does it exist? if real, add it; if invented, fix it)"
                )
    assert not offenders, "Unknown/unvetted Ansible module(s) in template(s):\n" + "\n".join(offenders)
