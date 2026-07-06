---
description: NL description -> validated specs/<lab>.yml (design + compile + guardrail gates)
argument-hint: <natural-language lab description>
---

Orchestrate a NEW lab from the MAIN thread. The request: $ARGUMENTS

You own ordering and the gates; delegate the design work, run the deterministic
gates yourself with Bash (they are just `forge.py` — no subagent needed).

1. Parse the request into intents (topology, population/theme, chosen-vs-auto
   vulnerabilities, defense profile, cloud/region).
2. Dispatch **`lab-designer`** to write the whole `specs/<lab>.yml` (infra +
   topology, population + theme, vuln selection + attack chain). One agent owns
   the full spec; hand back any gate failure to it.
3. Compile: `python3 scripts/forge.py lab-spec specs/<lab>.yml` → produces
   `generated/<lab>/lab-manifest.json` (validate + reconcile + IP plan + cost).
   On failure, hand the exact error back to `lab-designer` and re-run.
4. Guardrail: `python3 scripts/forge.py guardrail specs/<lab>.yml`. If it exits
   non-zero (FAIL), STOP and report the named invariant(s) — do not proceed to
   deploy. Also make the invariant #6 (authorized use) judgement it prints.
5. **HUMAN GATE**: present the spec summary + estimated cost + reconciliation
   outcome and ask for approval before any cloud spend. Do not deploy here.
