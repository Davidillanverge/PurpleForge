"""Shared constants and helpers for the PurpleForge tests."""

from __future__ import annotations

import json
from pathlib import Path

import forge

REPO_ROOT = Path(forge.REPO_ROOT)
SPECS_DIR = REPO_ROOT / "specs"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

# The golden-tested corpus lives with the tests as minimal SYNTHETIC fixtures
# (not demo labs — the harness generates real labs from a prompt on demand). They
# deliberately cover the manifest code paths: azure/aws/proxmox providers, single
# and multi-domain forests with a trust, each defense baseline (none/
# baseline-controls/cis-l1/cis-l2/realistic-profile), the reconciliation
# exclude + fixed-toggle + warn paths, and adcs/mssql/iis services.
GOLDEN_SPECS = sorted(FIXTURES_DIR.glob("*.yml"))
# Every hand-maintained spec (fixtures + any top-level regression specs) must at
# least resolve — this catches a spec left with a now-invalid field.
ALL_SPECS = GOLDEN_SPECS + sorted(SPECS_DIR.glob("*.yml"))


def normalize_manifest(manifest: dict) -> dict:
    """JSON round-trip (tuples->lists, stable ordering) with `source_spec`
    pinned to a basename so goldens don't depend on the checkout path."""
    data = json.loads(json.dumps(manifest, sort_keys=True))
    if "source_spec" in data:
        data["source_spec"] = Path(data["source_spec"]).name
    return data
