---
description: Deploy a generated lab (deterministic — forge.py deploy runs the generated deploy.sh)
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DEPLOY from the MAIN thread for: $ARGUMENTS

Deploy is now deterministic — a single `forge.py deploy` runs the generated
`deploy.sh` (state backend, auto-sizing, terraform apply, WireGuard, site.yml)
after its own guardrail gate. You do NOT need the `deploy-operator` subagent for
a normal deploy; run the command yourself with Bash and only fall back to the
agent if the script fails in a way that needs judgment.

Preconditions to confirm:
- `generated/<lab>/lab-manifest.json` and `deploy.sh` exist and are current (if
  stale or missing, run `python3 scripts/forge.py generate specs/<lab>.yml`).
- The human approved this specific lab's spec + cost. Approval never carries
  over from another lab.
- Cloud creds are available (`az login` done, or `ARM_*` exported). If the human
  must log in interactively, tell them to run `! az login`.

Then:
1. **First deploy of a new subscription only** — use the Azure MCP
   (`mcp__azure__quota`, `mcp__azure__compute`, `mcp__azure__pricing`) to sanity-check
   region quota and the SKU `deploy.sh` will auto-pick; note it for the human.
2. `python3 scripts/forge.py deploy specs/<lab>.yml` (it runs the guardrail gate,
   then `deploy.sh`; it is idempotent — re-run on a transient failure).
3. Report deploy status honestly, including any failure and which step it hit.
