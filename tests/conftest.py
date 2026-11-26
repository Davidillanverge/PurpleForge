"""Path safety for the test suite.

`pyproject.toml` sets `pythonpath = ["scripts", "src"]`, so `import forge` / `import
population` / `import llm` resolve without an install. This conftest just fails fast with a
clear message if that ever regresses.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _p in (ROOT / "scripts", ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
