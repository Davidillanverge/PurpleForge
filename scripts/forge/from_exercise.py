"""`forge from-exercise` — author a lab-spec from a BAS exercise.

The inverse direction of the usual flow: instead of hand-writing a spec and
letting it drive the lab, this takes the ATT&CK technique list a Breach & Attack
Simulation exercise produced (an ATT&CK Navigator layer JSON — the portable,
tool-agnostic artifact the `bas-purple-team-exercise` skill emits) and writes a
`specs/<lab>.yml` whose intentional gaps are exactly the catalog vulnerabilities
that reproduce those techniques. It is a deterministic translator — same layer
in, same spec out — and it stops at the spec: `forge lab-spec`/`generate`/
`deploy` take over unchanged, as they do for a hand-written or `/new-lab` spec.

It authors ONLY the security-relevant half of the spec (the vulnerabilities, the
services and machines they require, and a defense block that forces every
selected gap to stay open — so the lab is provably vulnerable to the exercise).
The infrastructure envelope (provider, theme, region, population size, topology)
has no place in a Navigator layer, so it comes from defaults or the CLI flags.

Pipeline position (parallel to the natural-language /new-lab front):

    exercise-layer.json ──from-exercise──▶ specs/<lab>.yml ──generate──▶ ...
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import jsonschema
import yaml

from .catalog import build_technique_index, load_vuln_catalog
from .core import REPO_ROOT, SpecError, load_schema

# Spec-envelope defaults for everything a Navigator layer cannot carry. Every
# one is overridable by a CLI flag; they only decide the shape of the lab, never
# which vulns it has (that is 100% driven by the exercise's techniques).
DEFAULT_PROVIDER = "azure"
DEFAULT_REGION = "eastus"
DEFAULT_THEME = "corporate"
DEFAULT_DOMAIN = "corp.local"
DEFAULT_USERS = 25
DEFAULT_DENSITY = "realistic"
DEFAULT_SEED = 1337
DEFAULT_BUDGET_USD = 30
DEFAULT_AUTO_SHUTDOWN = "20:00 Europe/Madrid"
DEFAULT_FUNCTIONAL_LEVEL = "2016"

# Per-role default OS — mirrors the committed example specs (Fasv7 sizes need
# 2019+, see AZURE-DEPLOY-RUNBOOK.md; workstations on Win10 22H2).
OS_BY_ROLE = {
    "domain-controller": "windows-server-2019",
    "member-server": "windows-server-2019",
    "workstation": "windows-10-22h2",
}

# AWS publishes no stock client-Windows (10/11) AMI — only Windows Server — so a
# client OS would fail the terraform precondition at deploy time unless the
# operator supplies a BYOL AMI. On AWS, default the workstation to a stock Server
# SKU so `from-exercise` labs deploy out of the box. See AWS-DEPLOY-RUNBOOK.md.
_AWS_CLIENT_OS_FALLBACK = "windows-server-2022"

_LAB_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_navigator_layer(path: Path) -> list[str]:
    """Extract the ordered, de-duplicated list of ATT&CK technique ids from an
    ATT&CK Navigator layer. Lenient about shape: accepts the standard
    `{"techniques": [{"techniqueID": "T1059.001"}, ...]}`, a `techniques` list of
    bare id strings, or a top-level list of ids."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SpecError(f"could not read ATT&CK Navigator layer {path}: {exc}") from exc

    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict) and isinstance(data.get("techniques"), list):
        raw = data["techniques"]
    else:
        raise SpecError(
            f"{path} does not look like an ATT&CK Navigator layer "
            "(expected a top-level list or a 'techniques' array)"
        )

    ids: list[str] = []
    seen: set[str] = set()
    for item in raw:
        tid = item.get("techniqueID") if isinstance(item, dict) else item
        if not isinstance(tid, str):
            continue
        tid = tid.strip().upper()
        if _TECH_RE.match(tid) and tid not in seen:
            seen.add(tid)
            ids.append(tid)
    if not ids:
        raise SpecError(f"{path} contains no valid ATT&CK technique ids (T#### / T####.###)")
    return ids


def match_techniques(
    layer_ids: list[str], index: dict[str, list[str]], *, exact_only: bool = False
) -> tuple[dict[str, dict], list[str]]:
    """Map the layer's techniques onto catalog vulns via the reverse index.

    Returns (selected, uncovered):
      selected  — {vuln_id: {"techniques": [...], "match": "exact"|"approx"}} for
                  every vuln whose ATT&CK id the exercise asked for. A vuln is
                  'exact' if any of its techniques is in the layer verbatim;
                  'approx' if it was reached only by parent<->sub-technique
                  roll-up (e.g. layer T1003 -> catalog T1003.006).
      uncovered — layer techniques that matched no catalog vuln, in layer order:
                  the honest gap list (a runtime-only TTP, or a precondition the
                  catalog cannot yet represent — the operator/catalog-author
                  decides which).

    exact_only suppresses the parent<->sub roll-up, matching verbatim ids only.
    """
    index_keys = set(index)
    selected: dict[str, dict] = {}
    matched_layer: set[str] = set()

    def _record(vid: str, layer_tech: str, kind: str) -> None:
        slot = selected.setdefault(vid, {"techniques": [], "match": "approx"})
        if layer_tech not in slot["techniques"]:
            slot["techniques"].append(layer_tech)
        if kind == "exact":
            slot["match"] = "exact"

    for layer_tech in layer_ids:
        hit = False
        # 1) verbatim
        if layer_tech in index_keys:
            for vid in index[layer_tech]:
                _record(vid, layer_tech, "exact")
            hit = True
        if exact_only:
            if hit:
                matched_layer.add(layer_tech)
            continue
        # 2) layer named the parent (T1003) -> catalog has a sub (T1003.006)
        for key in index_keys:
            if key.startswith(layer_tech + "."):
                for vid in index[key]:
                    _record(vid, layer_tech, "approx")
                hit = True
        # 3) layer named a sub (T1003.006) -> catalog has the parent (T1003)
        if "." in layer_tech:
            parent = layer_tech.split(".", 1)[0]
            if parent in index_keys:
                for vid in index[parent]:
                    _record(vid, layer_tech, "approx")
                hit = True
        if hit:
            matched_layer.add(layer_tech)

    uncovered = [t for t in layer_ids if t not in matched_layer]
    return selected, uncovered


def _sanitize_lab_name(raw: str | None) -> str:
    """Coerce an exercise name into a schema-valid lab.name
    (^[a-z][a-z0-9-]{1,30}[a-z0-9]$), falling back to 'exercise-lab'."""
    candidate = re.sub(r"[^a-z0-9-]+", "-", (raw or "").lower()).strip("-")
    candidate = re.sub(r"-{2,}", "-", candidate)
    if candidate and not candidate[0].isalpha():
        candidate = "ex-" + candidate
    candidate = candidate[:32].rstrip("-")
    return candidate if _LAB_NAME_RE.match(candidate) else "exercise-lab"


def _netbios_from_domain(domain: str) -> str:
    """First DNS label -> a schema-valid NetBIOS name (^[A-Z][A-Z0-9]{0,14}$)."""
    label = re.sub(r"[^A-Z0-9]", "", domain.split(".", 1)[0].upper())
    if not label or not label[0].isalpha():
        label = "LAB" + label
    return label[:15]


def _os_for_role(role: str, provider: str) -> str:
    """Per-role default OS, provider-aware.

    On AWS the workstation falls back to a stock Server SKU because AWS publishes
    no stock client-Windows AMI (a `windows-10-*`/`windows-11-*` machine would
    fail the terraform precondition unless the operator supplies a BYOL AMI)."""
    os_name = OS_BY_ROLE[role]
    if provider == "aws" and os_name.startswith(("windows-10", "windows-11")):
        return _AWS_CLIENT_OS_FALLBACK
    return os_name


def _plan_machines(
    selected_entries: list[dict], domain: str, provider: str
) -> tuple[list[dict], list[str], bool]:
    """Decide the smallest topology that can host the selected vulns.

    A DC is always present. A member-server is added (carrying the union of
    required services) iff some vuln declares attack.requires_services. A
    workstation is added iff some vuln is attack.target_role: workstation.
    Returns (machines, services, needs_workstation)."""
    services: list[str] = []
    needs_workstation = False
    for entry in selected_entries:
        attack = entry.get("attack", {})
        for svc in attack.get("requires_services", []) or []:
            if svc not in services:
                services.append(svc)
        if attack.get("target_role") == "workstation":
            needs_workstation = True

    machines = [{"role": "domain-controller", "os": _os_for_role("domain-controller", provider), "domain": domain, "count": 1}]
    if services:
        machines.append(
            {
                "role": "member-server",
                "os": _os_for_role("member-server", provider),
                "domain": domain,
                "services": sorted(services),
                "count": 1,
            }
        )
    if needs_workstation:
        machines.append({"role": "workstation", "os": _os_for_role("workstation", provider), "domain": domain, "count": 1})
    return machines, sorted(services), needs_workstation


def build_spec(
    selected: dict[str, dict],
    catalog: dict[str, dict],
    *,
    name: str,
    theme: str,
    provider: str,
    region: str,
    domain: str,
    users: int,
    seed: int,
    density: str,
    budget: float,
    auto_shutdown: str,
    chain_mode: str,
) -> dict:
    """Assemble a lab-spec dict from the selected vulns + the infra envelope.

    The defense block is the load-bearing part: intentional_gaps_auto + on_conflict
    exclude-control make PurpleForge's reconciler force every selected vuln's
    neutralized_by gap to stay open, so `forge guardrail` certifies the lab is
    vulnerable to exactly the exercise's techniques — not merely that we asked."""
    vuln_ids = sorted(selected)
    selected_entries = [catalog[v] for v in vuln_ids]
    machines, _services, _ws = _plan_machines(selected_entries, domain, provider)

    atomics = sorted(
        {
            a
            for e in selected_entries
            if (a := e.get("validate", {}).get("atomic"))
        }
    )

    spec: dict = {
        "lab": {
            "name": name,
            "theme": theme,
            "provider": provider,
            "region": region,
            "isolation": "vpn-only",
            "auto_shutdown": auto_shutdown,
            "budget_alert_usd": budget,
        },
        "forest": [
            {
                "domain": domain,
                "netbios": _netbios_from_domain(domain),
                "functional_level": DEFAULT_FUNCTIONAL_LEVEL,
                "domain_controllers": 1,
            }
        ],
        "machines": machines,
        "population": {"users": users, "density": density, "seed": seed},
        "vulnerabilities": vuln_ids,
        "attack_chain": {"mode": chain_mode},
        "defense": {
            "profile": "realistic",
            "hardening": {
                "baseline": "baseline-controls",
                "apply_to": "all",
                "controls": {"laps": True},
                "intentional_gaps_auto": True,
            },
            "edr": [
                {
                    "product": "defender-av",
                    "mode": "enabled",
                    "settings": {"asr_rules": "audit", "tamper_protection": True, "network_protection": True},
                    "targets": "all",
                }
            ],
            "deception": {"honey_accounts": 0},
        },
        "on_conflict": "exclude-control",
        "validation": {"bloodhound": True, "pingcastle": True, "atomic_red_team": atomics},
    }
    return spec


def _render_spec_yaml(spec: dict, *, layer_path: Path, selected: dict[str, dict], uncovered: list[str]) -> str:
    """YAML body with a provenance header documenting the translation (what the
    exercise asked for, what mapped, and what did not) — the spec stays the
    single hand-editable source, so the provenance travels with it."""
    lines = [
        "# PurpleForge spec authored by `forge from-exercise` (deterministic translation).",
        f"# Source ATT&CK Navigator layer: {layer_path.name}",
        "#",
        "# Selected vulnerabilities (exercise technique -> catalog vuln):",
    ]
    for vid in sorted(selected):
        info = selected[vid]
        tag = "" if info["match"] == "exact" else "  [approx: parent<->sub roll-up]"
        lines.append(f"#   - {vid}: {', '.join(info['techniques'])}{tag}")
    if uncovered:
        lines += [
            "#",
            "# Techniques with NO catalog coverage (not represented in this lab — a",
            "# runtime-only TTP the red team performs, or a precondition the catalog",
            "# cannot yet build; author a vuln with the catalog-author agent to cover it):",
            "#   " + ", ".join(uncovered),
        ]
    lines.append("")
    body = yaml.safe_dump(spec, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100)
    return "\n".join(lines) + body


def cmd_from_exercise(args: argparse.Namespace) -> int:
    layer_path = Path(args.layer).resolve()
    if not layer_path.exists():
        print(f"error: ATT&CK Navigator layer not found: {layer_path}", file=sys.stderr)
        return 2

    try:
        layer_ids = load_navigator_layer(layer_path)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    catalog = load_vuln_catalog()
    index = build_technique_index(catalog)
    selected, uncovered = match_techniques(layer_ids, index, exact_only=args.exact_only)

    print(f"from-exercise — {layer_path.name}: {len(layer_ids)} technique(s)")
    if selected:
        print(f"  matched {len(selected)} vuln(s):")
        for vid in sorted(selected):
            info = selected[vid]
            kind = "" if info["match"] == "exact" else " (approx)"
            print(f"    - {vid}{kind}  <- {', '.join(info['techniques'])}")
    if uncovered:
        print(f"  {len(uncovered)} technique(s) with no catalog coverage (not built into the lab):")
        print(f"    {', '.join(uncovered)}")

    if not selected:
        print(
            "FAIL: no exercise technique maps to a catalog vulnerability — the lab "
            "would be vulnerable to nothing. Add a covering vuln (catalog-author) or "
            "check the layer.",
            file=sys.stderr,
        )
        return 1

    name = _sanitize_lab_name(args.name)
    spec = build_spec(
        selected,
        catalog,
        name=name,
        theme=args.theme,
        provider=args.provider,
        region=args.region,
        domain=args.domain,
        users=args.users,
        seed=args.seed,
        density=args.density,
        budget=args.budget,
        auto_shutdown=args.auto_shutdown,
        chain_mode=args.chain,
    )

    # Note any provider-driven OS fallback so the operator isn't surprised that
    # an exercise workstation landed on Windows Server.
    if args.provider == "aws":
        for m in spec["machines"]:
            if m["role"] == "workstation" and m["os"] == _AWS_CLIENT_OS_FALLBACK:
                print(
                    f"  note: workstation OS set to {_AWS_CLIENT_OS_FALLBACK} — AWS has no "
                    "stock client-Windows AMI. For a real client OS, set machines[].image_id "
                    "to a BYOL AMI (see AWS-DEPLOY-RUNBOOK.md)."
                )

    # Self-check: the authored spec must satisfy the lab-spec JSON Schema before
    # we write it (fail here, not three commands later in `lab-spec`).
    try:
        jsonschema.Draft202012Validator(load_schema()).validate(spec)
    except jsonschema.ValidationError as exc:
        print(f"error: authored spec failed schema validation: {exc.message}", file=sys.stderr)
        return 1

    out_path = Path(args.out).resolve() if args.out else (REPO_ROOT / "specs" / f"{name}.yml")
    if out_path.exists() and not args.force:
        print(f"error: {out_path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        _render_spec_yaml(spec, layer_path=layer_path, selected=selected, uncovered=uncovered), encoding="utf-8"
    )

    rel = out_path.relative_to(REPO_ROOT) if out_path.is_relative_to(REPO_ROOT) else out_path
    print(f"OK: wrote {rel} ({len(spec['vulnerabilities'])} vuln(s), {len(spec['machines'])} machine(s))")
    print(f"  next: forge lab-spec {rel}   # full semantic validation + reconciliation")
    return 0
