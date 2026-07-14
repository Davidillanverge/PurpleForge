"""Enable `python -m forge ...` (used by lifecycle._run_self for the guardrail
gate, and handy for running the CLI without the installed console script)."""

from __future__ import annotations

from forge import main

if __name__ == "__main__":
    raise SystemExit(main())
