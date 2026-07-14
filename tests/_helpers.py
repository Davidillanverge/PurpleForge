"""Shared constants and helpers for the PurpleForge tests."""

from __future__ import annotations

import json
from pathlib import Path

import forge

REPO_ROOT = Path(forge.REPO_ROOT)
EXAMPLES_DIR = REPO_ROOT / "specs" / "examples"
SPECS_DIR = REPO_ROOT / "specs"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

# The canonical example specs are the golden-tested set: single/multi-domain
# forests, both providers, the reconciliation exclusion path, and a broad vuln
# selection.
EXAMPLE_SPECS = sorted(EXAMPLES_DIR.glob("*.yml"))
# Every hand-maintained spec (examples + top-level) must at least resolve.
ALL_SPECS = sorted(EXAMPLES_DIR.glob("*.yml")) + sorted(SPECS_DIR.glob("*.yml"))


def normalize_manifest(manifest: dict) -> dict:
    """JSON round-trip (tuples->lists, stable ordering) with `source_spec`
    pinned to a basename so goldens don't depend on the checkout path."""
    data = json.loads(json.dumps(manifest, sort_keys=True))
    if "source_spec" in data:
        data["source_spec"] = Path(data["source_spec"]).name
    return data
