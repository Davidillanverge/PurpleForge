#!/usr/bin/env python3
"""Regenerate the golden manifests under tests/golden/.

Run this ON PURPOSE after an intended change to the deterministic core (IP plan,
cost model, reconciliation, defense resolution) — never to "make the test pass"
without understanding the diff. `git diff tests/golden/` is the review surface
for what changed in the manifest.

    python3 tests/generate_golden.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import forge  # noqa: E402
from _helpers import EXAMPLE_SPECS, GOLDEN_DIR, normalize_manifest  # noqa: E402


def main() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for spec in EXAMPLE_SPECS:
        res = forge.load_and_resolve(spec)
        if res is None:
            print(f"ERROR: {spec} failed to resolve", file=sys.stderr)
            return 1
        _, manifest = res
        out = GOLDEN_DIR / f"{spec.stem}.json"
        payload = json.dumps(normalize_manifest(manifest), indent=2, sort_keys=True, ensure_ascii=False)
        out.write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {out.relative_to(forge.REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
