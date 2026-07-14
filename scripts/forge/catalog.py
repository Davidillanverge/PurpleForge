"""Catalog loaders: the vulnerability catalog, defense profiles, themes, and the
hardening baseline / control->CIS-rule mapping files under catalog/. Plus
resolve_defense (defense.profile defaults merged with the spec's overrides).
"""

from __future__ import annotations

from .core import (
    CONTROL_CIS_RULES_PATH,
    DEFENSE_PROFILES_DIR,
    HARDENING_DIR,
    THEMES_DIR,
    VULN_CATALOG_DIR,
    SpecError,
    deep_merge,
    load_yaml,
)


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


def load_control_cis_rules() -> dict:
    if not CONTROL_CIS_RULES_PATH.exists():
        return {}
    return load_yaml(CONTROL_CIS_RULES_PATH).get("controls", {})
