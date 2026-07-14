"""Every catalog entry validates against its JSON Schema.

test_catalog.py asserts a few hand-picked invariants (invariant #2 fields, ATT&CK
id shape, no detection block); this locks the FULL shape of every
catalog/vulnerabilities/*.yml and catalog/themes/*.yml against a schema, so a
malformed or typo'd field (a stray key, a missing `vocabulary.family_names`, a
honey pattern without `{n}`) fails at author time instead of at deploy time.
"""

from __future__ import annotations

from pathlib import Path

import forge
import jsonschema
import pytest
import yaml

VULN_SCHEMA = forge.load_vulnerability_schema()
THEME_SCHEMA = forge.load_theme_schema()

VULN_FILES = sorted((forge.REPO_ROOT / "catalog" / "vulnerabilities").glob("*.yml"))
THEME_FILES = sorted((forge.REPO_ROOT / "catalog" / "themes").glob("*.yml"))


def test_schema_files_are_valid_metaschemas():
    jsonschema.Draft202012Validator.check_schema(VULN_SCHEMA)
    jsonschema.Draft202012Validator.check_schema(THEME_SCHEMA)


def test_found_some_catalog_files():
    assert VULN_FILES, "no vulnerability files discovered"
    assert THEME_FILES, "no theme files discovered"


@pytest.mark.parametrize("path", VULN_FILES, ids=lambda p: p.stem)
def test_vulnerability_matches_schema(path: Path):
    entry = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(VULN_SCHEMA).iter_errors(entry), key=lambda e: list(e.path))
    assert not errors, f"{path.name}: " + "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
    # the filename stem must match the declared id (load_vuln_catalog keys off id).
    assert entry["id"] == path.stem, f"{path.name}: id '{entry['id']}' != filename stem '{path.stem}'"


@pytest.mark.parametrize("path", THEME_FILES, ids=lambda p: p.stem)
def test_theme_matches_schema(path: Path):
    entry = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(THEME_SCHEMA).iter_errors(entry), key=lambda e: list(e.path))
    assert not errors, f"{path.name}: " + "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
    assert entry["id"] == path.stem, f"{path.name}: id '{entry['id']}' != filename stem '{path.stem}'"
