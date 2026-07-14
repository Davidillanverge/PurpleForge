"""Golden-file regression tests for the deterministic core.

For each canonical example spec, the resolved lab-manifest.json (schema +
semantic checks + defense resolution + IP plan + cost + reconciliation) must
match a committed golden. If the deterministic core changes on purpose,
regenerate with `python3 tests/generate_golden.py` and review the diff.
"""

from __future__ import annotations

import json

import forge
import pytest
from _helpers import GOLDEN_DIR, GOLDEN_SPECS, normalize_manifest


@pytest.mark.parametrize("spec_path", GOLDEN_SPECS, ids=lambda p: p.stem)
def test_manifest_matches_golden(spec_path):
    golden = GOLDEN_DIR / f"{spec_path.stem}.json"
    assert golden.exists(), f"no golden for {spec_path.stem} — run `python3 tests/generate_golden.py`"

    res = forge.load_and_resolve(spec_path)
    assert res is not None, f"{spec_path.name} failed to resolve"
    _, manifest = res

    expected = json.loads(golden.read_text(encoding="utf-8"))
    assert normalize_manifest(manifest) == expected, (
        f"manifest for {spec_path.stem} drifted from its golden — inspect the "
        f"change; if intended, regenerate with tests/generate_golden.py"
    )


def test_resolution_is_deterministic():
    """The same spec resolved twice yields an identical manifest (invariant #5)."""
    spec_path = GOLDEN_SPECS[0]
    first = normalize_manifest(forge.load_and_resolve(spec_path)[1])
    second = normalize_manifest(forge.load_and_resolve(spec_path)[1])
    assert first == second
