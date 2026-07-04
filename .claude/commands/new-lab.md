---
description: NL description -> validated specs/<lab>.yml (design cell + compile + guardrail gates)
argument-hint: <natural-language lab description>
---

Act as `forge-orchestrator` for a NEW lab. The request: $ARGUMENTS

1. Parse the request into intents (topology, population/theme, chosen-vs-auto
   vulnerabilities, defense profile, cloud/region).
2. Dispatch the design cell — `topology-architect`, `domain-designer`, and
   `redteam-designer` — to converge on a single `specs/<lab>.yml`. Run the
   independent ones in parallel; they edit disjoint blocks. Only run vuln
   SELECTION if the user did not name vulnerabilities (always design the chain).
3. Run `spec-compiler` to produce `generated/<lab>/lab-manifest.json`
   (`scripts/forge.py lab-spec`). Hand any failure back to the responsible
   design subagent and re-run.
4. Run `policy-guardrail`. If any invariant fails, STOP and report — do not
   proceed to deploy.
5. Present the spec summary + estimated cost + reconciliation outcome and ask
   the human to approve before any cloud spend. Do not deploy in this command.
