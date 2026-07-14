"""Path safety for the test suite.

`pyproject.toml` sets `pythonpath = ["scripts"]`, so `import forge` / `import
population` resolve without an install. This conftest just fails fast with a
clear message if that ever regresses.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
