---
description: Deploy a generated lab (deterministic — forge deploy runs the generated deploy.sh)
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DEPLOY from the MAIN thread for: $ARGUMENTS

Deploy is deterministic: `forge deploy` runs the generated `deploy.sh` (state
backend, auto-sizing, terraform apply, WireGuard, site.yml) after its own
guardrail gate. Run it yourself with Bash; fall back to `deploy-operator` only
if the script fails in a way that needs judgment.

Preconditions:
- `generated/<lab>/lab-manifest.json` and `deploy.sh` exist and are current
  (else run `forge generate specs/<lab>.yml`).
- The human approved THIS lab's spec + cost (approval never carries over).
- Cloud creds available (`az login` or `ARM_*` exported). If interactive login
  is needed, tell them to run `! az login`.

Then:
1. **First deploy on a new subscription only** — use the Azure MCP
   (`mcp__azure__quota`/`compute`/`pricing`) to sanity-check region quota and
   the auto-picked SKU; note it for the human.
2. `forge deploy specs/<lab>.yml` (runs guardrail then
   `deploy.sh`; idempotent — re-run on transient failure).
3. Report status honestly, including any failure and the step it hit.
