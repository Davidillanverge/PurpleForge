"""PurpleForge core: paths, shared constants, the SpecError type, and the small
pure helpers (YAML/schema loading, deep_merge, deterministic naming/passwords)
that every other module in the package builds on.

This is the leaf of the dependency graph — it imports nothing else in the
package, so anything here is safe to import from anywhere.
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
import secrets
import string
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "specs" / "schema" / "lab-spec.schema.json"
VULN_CATALOG_DIR = REPO_ROOT / "catalog" / "vulnerabilities"
THEMES_DIR = REPO_ROOT / "catalog" / "themes"
CATALOG_SCHEMA_DIR = REPO_ROOT / "catalog" / "schema"
VULN_SCHEMA_PATH = CATALOG_SCHEMA_DIR / "vulnerability.schema.json"
THEME_SCHEMA_PATH = CATALOG_SCHEMA_DIR / "theme.schema.json"
DEFENSE_PROFILES_DIR = REPO_ROOT / "catalog" / "defense" / "profiles"
HARDENING_DIR = REPO_ROOT / "catalog" / "defense" / "hardening"
EDR_DIR = REPO_ROOT / "catalog" / "defense" / "edr"
CONTROL_CIS_RULES_PATH = HARDENING_DIR / "control-cis-rules.yml"
GENERATED_DIR = REPO_ROOT / "generated"
TEMPLATES_DIR = REPO_ROOT / "templates"

ROLE_ABBREV = {"domain-controller": "dc", "member-server": "mbr", "workstation": "ws"}

# Single source of truth for the two Windows-side automation accounts every
# generated VM gets (see render.render_azure_terraform / templates/ansible/roles/
# pf_*) — referenced again by render_lab_report, so it's a named constant
# rather than a literal duplicated in two places.
WINDOWS_ADMIN_USERNAME = "purpleforge"
WINRM_AUTOMATION_USERNAME = "ansible"

# Per-vuln (account_var, password_var) in that vuln's build_vuln_vars() output
# — used to render a "account / password" row. Vulns absent here have no
# credentialed account (a machine-wide policy change, a computer-object flag,
# or a fixed value baked into the task file) and get a NOTE instead. Shared
# across planning (plan_vuln_injection), render (describe_vuln_credentials) and
# validate (build_vuln_check), so it lives here rather than in any one of them.
VULN_CREDENTIAL_VARS = {
    "kerberoasting": ("vuln_kerberoast_account", "vuln_kerberoast_password"),
    "asreproast": ("vuln_asrep_account", "vuln_asrep_password"),
    "dcsync-acl": ("vuln_dcsync_account", "vuln_dcsync_password"),
    "passwords-in-description": ("vuln_pwddesc_account", "vuln_pwddesc_password"),
    "constrained-delegation": ("vuln_delegation_account", "vuln_delegation_password"),
    "shadow-credentials": ("vuln_shadowcred_target", "vuln_shadowcred_target_password"),
    "dnsadmins-privesc": ("vuln_dnsadmins_account", "vuln_dnsadmins_password"),
    "rbcd-abuse": ("vuln_rbcd_delegate_account", "vuln_rbcd_delegate_password"),
    "backup-operators-membership": ("vuln_backupop_account", "vuln_backupop_password"),
    "writable-gpo": ("vuln_gpo_account", "vuln_gpo_password"),
    "adminsdholder-acl": ("vuln_adminsdholder_account", "vuln_adminsdholder_password"),
    "readable-gmsa": ("vuln_gmsa_reader_account", "vuln_gmsa_reader_password"),
    "esc4-template-acl": ("vuln_esc4_account", "vuln_esc4_password"),
    "mssql-weak-sa": (None, "vuln_mssql_sa_password"),  # sa is a fixed SQL login, not a cast AD account
    "sysvol-script-creds": ("vuln_sysvol_account", "vuln_sysvol_password"),
    "autologon-credentials": ("vuln_autologon_account", "vuln_autologon_password"),
}


class SpecError(Exception):
    """Raised for validation/semantic/reconciliation failures that should stop generation."""


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_schema() -> dict:
    with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def deep_merge(base: dict, override: dict) -> dict:
    """override wins; lists in override fully replace lists in base (no element-wise merge)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def yaml_scalar(value) -> str:
    """Renders a Python value as a YAML-safe scalar string for direct
    interpolation into a Jinja template (avoids fragile in-template filters —
    the template just prints these, it doesn't reason about types)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))  # quoted string, JSON quoting is valid YAML


def stable_octet(name: str) -> int:
    """Deterministic 10..209 second-octet derived from lab.name (not population.seed:
    seed governs population/theming determinism, not the network plan)."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return 10 + (digest[0] % 200)


def generate_password(length: int = 20, rng: random.Random | None = None) -> str:
    """Random password meeting basic Windows complexity rules (upper/lower/digit/symbol).

    The symbol set deliberately EXCLUDES cmd.exe-hostile characters
    (`& ^ % $ < > | " '` and space): the ansible bootstrap extension creates the
    WinRM user with `net user ansible <pw>` under cmd.exe, where an unquoted `&`
    silently splits the command and the user is never created (WinRM then never
    comes up). We also quote the password there now, but keeping these out of the
    alphabet is the load-bearing fix — see terraform/azure/windows.tf.

    `rng`: pass a seeded random.Random to make the result reproducible from
    population.seed (population user passwords, most vuln account passwords —
    CLAUDE.md invariant #5). Left as None (the default), it draws from
    `secrets` — Python's CSPRNG, deliberately NOT seedable — which is the
    correct behavior for the two real per-deployer infra secrets
    (admin_password/ansible_password) that must stay unguessable and must NOT
    be reproducible across a regenerate."""
    choice = rng.choice if rng is not None else secrets.choice
    symbols = "!@#*-_=+"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in symbols for c in pw)
        ):
            return pw
