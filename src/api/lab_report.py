"""The operator's lab report for the UI: everything needed to run the lab.

Sources, all written by forge (nothing here re-derives a value):
- ``generated/<lab>/lab-report.md`` (``forge generate``): topology, hostnames/IPs,
  credentials, AD population (users, groups, computers), hardening, EDR,
  telemetry/BAS agents, vulnerabilities and the attack path.
- ``terraform-outputs.json`` / ``connectivity.json`` (``deploy.sh``): the live
  bastion address, WireGuard config, per-host reachability.
- ``validation-report.md`` (``forge validate --run``) and ``ad-inventory.md``
  (``forge ad-inventory``), when present.

Markdown is rendered with raw HTML disabled (markdown-it escapes it), so a report
can never inject markup into the dashboard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from markdown_it import MarkdownIt


def _slug(text: str) -> str:
    """GitHub-style heading anchor, so the report's own [..](#anchor) links work."""
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def _markdown() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")
    return md


@dataclass
class Heading:
    level: int
    text: str
    anchor: str


@dataclass
class RenderedDoc:
    path: str
    html: str
    headings: list[Heading] = field(default_factory=list)
    modified: datetime | None = None


def render_markdown(text: str, *, anchor_prefix: str = "") -> tuple[str, list[Heading]]:
    md = _markdown()
    tokens = md.parse(text)
    headings: list[Heading] = []
    seen: dict[str, int] = {}
    for i, tok in enumerate(tokens):
        if tok.type == "heading_open" and i + 1 < len(tokens):
            title = tokens[i + 1].content
            base = anchor_prefix + _slug(title)
            n = seen.get(base, 0)
            seen[base] = n + 1
            anchor = base if n == 0 else f"{base}-{n}"
            tok.attrSet("id", anchor)
            headings.append(Heading(level=int(tok.tag[1]), text=title, anchor=anchor))
    if anchor_prefix:  # keep the doc's own #links pointing at its prefixed anchors
        for tok in tokens:
            for child in tok.children or []:
                href = child.attrGet("href") if child.type == "link_open" else None
                if isinstance(href, str) and href.startswith("#"):
                    child.attrSet("href", "#" + anchor_prefix + href[1:])
    return md.renderer.render(tokens, md.options, {}), headings


def _doc(lab_dir: Path, repo_root: Path, name: str, *, anchor_prefix: str = "") -> RenderedDoc | None:
    path = lab_dir / name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    html, headings = render_markdown(text, anchor_prefix=anchor_prefix)
    rel = str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)
    return RenderedDoc(
        path=rel,
        html=html,
        headings=headings,
        modified=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc),
    )


def _json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class Endpoint:
    name: str
    role: str
    ip: str
    probes: list[dict[str, Any]]


@dataclass
class LiveAccess:
    bastion_ip: str | None = None
    region: str | None = None
    bastion_ssh_key: str | None = None
    bastion_ssh_user: str = "purpleforge"
    wireguard_conf: str | None = None
    hosts: dict[str, str] = field(default_factory=dict)
    endpoints: list[Endpoint] = field(default_factory=list)
    connectivity_checked_at: datetime | None = None
    wireguard_handshake: bool | None = None
    bastion_ssh_login: bool | None = None


@dataclass
class LabReport:
    lab_dir: str
    report: RenderedDoc | None
    validation: RenderedDoc | None
    inventory: RenderedDoc | None
    live: LiveAccess | None

    @property
    def toc(self) -> list[Heading]:
        out: list[Heading] = []
        for doc in (self.report, self.validation, self.inventory):
            if doc:
                out.extend(h for h in doc.headings if h.level <= 3)
        return out


def _rel(path: Path, repo_root: Path) -> str:
    return str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)


#: the bastion's login user, as each provider's deploy.sh uses it (AWS: the Ubuntu AMI's)
BASTION_SSH_USER = {"aws": "ubuntu", "azure": "purpleforge", "proxmox": "purpleforge"}


def _live(lab_dir: Path, repo_root: Path, provider: str | None) -> LiveAccess | None:
    outputs = _json(lab_dir / "terraform-outputs.json")
    conn = _json(lab_dir / "connectivity.json")
    if outputs is None and conn is None:
        return None

    def out(name: str) -> Any:
        v = (outputs or {}).get(name)
        return v.get("value") if isinstance(v, dict) and not v.get("sensitive") else None

    live = LiveAccess(
        bastion_ip=out("bastion_public_ip"),
        region=out("region"),
        hosts={str(k): str(v) for k, v in (out("windows_hosts") or {}).items()},
        bastion_ssh_user=BASTION_SSH_USER.get(provider or "", "purpleforge"),
    )
    key = out("bastion_ssh_private_key_path")
    confs = sorted(lab_dir.glob("terraform/*/ssh_keys/*.conf"))
    if confs:
        live.wireguard_conf = _rel(confs[0], repo_root)
        if isinstance(key, str):
            live.bastion_ssh_key = _rel((confs[0].parent.parent / key).resolve(), repo_root.resolve())
    nodes = (conn or {}).get("nodes") or {}
    if not nodes:
        nodes = out("lab_endpoints") or {}
    for name, node in nodes.items():
        if isinstance(node, dict):
            live.endpoints.append(
                Endpoint(
                    name=str(name),
                    role=str(node.get("role") or ""),
                    ip=str(node.get("ip") or ""),
                    probes=[p for p in node.get("probes") or [] if isinstance(p, dict)],
                )
            )
    if conn:
        ts = conn.get("checked_at")
        if isinstance(ts, (int, float)):
            live.connectivity_checked_at = datetime.fromtimestamp(ts, tz=timezone.utc)
        live.wireguard_handshake = conn.get("wireguard_handshake")
        live.bastion_ssh_login = conn.get("bastion_ssh_login")
    return live


def load_lab_report(repo_root: Path, lab_name: str, provider: str | None = None) -> LabReport:
    lab_dir = repo_root / "generated" / lab_name
    return LabReport(
        lab_dir=_rel(lab_dir, repo_root),
        report=_doc(lab_dir, repo_root, "lab-report.md"),
        validation=_doc(lab_dir, repo_root, "validation-report.md", anchor_prefix="val-"),
        inventory=_doc(lab_dir, repo_root, "ad-inventory.md", anchor_prefix="inv-"),
        live=_live(lab_dir, repo_root, provider),
    )
