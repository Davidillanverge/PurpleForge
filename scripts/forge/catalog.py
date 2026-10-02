"""Catalog loaders: the vulnerability catalog, defense profiles, themes, and the
hardening baseline / control->CIS-rule mapping files under catalog/. Plus
resolve_defense (defense.profile defaults merged with the spec's overrides).
"""

from __future__ import annotations

import json

from .core import (
    CONTROL_CIS_RULES_PATH,
    DEFENSE_PROFILES_DIR,
    HARDENING_DIR,
    THEME_SCHEMA_PATH,
    THEMES_DIR,
    VULN_CATALOG_DIR,
    VULN_SCHEMA_PATH,
    SpecError,
    deep_merge,
    load_yaml,
)


def load_vulnerability_schema() -> dict:
    """JSON Schema for a catalog/vulnerabilities/*.yml entry (author-time contract
    for CLAUDE.md invariant #2). Used by the catalog schema tests and available to
    the catalog-author agent to validate a new vuln before it lands."""
    return json.loads(VULN_SCHEMA_PATH.read_text(encoding="utf-8"))


def load_theme_schema() -> dict:
    """JSON Schema for a catalog/themes/*.yml entry."""
    return json.loads(THEME_SCHEMA_PATH.read_text(encoding="utf-8"))


def load_vuln_catalog() -> dict[str, dict]:
    catalog = {}
    for f in sorted(VULN_CATALOG_DIR.glob("*.yml")):
        entry = load_yaml(f)
        catalog[entry["id"]] = entry
    return catalog


def load_defense_profile(name: str) -> dict:
    path = DEFENSE_PROFILES_DIR / f"{name}.yml"
    if not path.exists():
        raise SpecError(f"defense.profile '{name}' has no catalog/defense/profiles/{name}.yml")
    return load_yaml(path)["defaults"]


def resolve_defense(spec: dict) -> dict:
    defense = spec["defense"]
    profile_defaults = load_defense_profile(defense["profile"])
    overrides = {k: v for k, v in defense.items() if k != "profile"}
    return deep_merge(profile_defaults, overrides)


def load_theme(theme_id: str) -> dict:
    return load_yaml(THEMES_DIR / f"{theme_id}.yml")


def load_hardening_baseline(baseline_id: str) -> dict:
    if baseline_id in ("none", None):
        return {"id": "none", "engine": "none", "role_by_os": {}, "tags_by_role": {}, "skip_rule_vars_prefix_by_os": {}}
    return load_yaml(HARDENING_DIR / f"{baseline_id}.yml")


def build_technique_index(catalog: dict[str, dict]) -> dict[str, list[str]]:
    """Reverse index ATT&CK-technique-id -> sorted list of catalog vuln ids that
    carry it in attack.mitre_attack. Computed from the loaded catalog (never a
    hand-maintained file), so adding a vuln extends the index for free. Used by
    from_exercise to pick the vulns that reproduce a BAS exercise's techniques."""
    index: dict[str, set[str]] = {}
    for vid, entry in catalog.items():
        for tech in entry.get("attack", {}).get("mitre_attack", []):
            index.setdefault(tech, set()).add(vid)
    return {tech: sorted(vids) for tech, vids in sorted(index.items())}


def load_control_cis_rules() -> dict:
    if not CONTROL_CIS_RULES_PATH.exists():
        return {}
    return load_yaml(CONTROL_CIS_RULES_PATH).get("controls", {})
