---
description: NL description -> validated specs/<lab>.yml (design + compile + guardrail gates)
argument-hint: <natural-language lab description>
---

Orchestrate a NEW lab from the MAIN thread. The request: $ARGUMENTS

You own ordering and gates; run the deterministic gates yourself with Bash.

1. Parse intents: topology, population/theme, chosen-vs-auto vulns, defense
   profile, cloud/region.
2. Dispatch **`lab-designer`** to write the whole `specs/<lab>.yml`. Hand any
   gate failure back to it.
3. Compile: `forge lab-spec specs/<lab>.yml` → produces
   `lab-manifest.json`. On failure, return the exact error to `lab-designer`.
4. Guardrail: `forge guardrail specs/<lab>.yml`. Non-zero =
   FAIL: STOP, report the named invariant(s), don't deploy. Also make the
   invariant #6 (authorized use) judgement it prints.
5. **HUMAN GATE**: present spec summary + cost + reconciliation outcome; ask for
   approval before any spend. Do not deploy here.
