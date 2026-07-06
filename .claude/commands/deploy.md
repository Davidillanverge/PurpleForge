---
description: Deploy a generated lab (only after guardrail PASS + human approval)
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate DEPLOY from the MAIN thread for: $ARGUMENTS

Preconditions you must confirm before dispatching:
- `generated/<lab>/lab-manifest.json` exists and is current (if stale, re-run
  `python3 scripts/forge.py lab-spec specs/<lab>.yml`).
- `python3 scripts/forge.py guardrail specs/<lab>.yml` exits 0 (PASS). Run it now
  if unsure — never deploy on FAIL.
- The human approved this specific lab's spec + cost. Approval never carries over
  from another lab.

Then dispatch `deploy-operator`. It follows `AZURE-DEPLOY-RUNBOOK.md` and the
mandated order (infra -> topology -> population -> hardening -> vuln gaps ->
EDR/telemetry -> CLEAN SNAPSHOT before any attack). Do not run terraform/ansible
yourself. Relay any manual step the operator needs (e.g. interactive `az login`
via `! <cmd>`), and report deploy status honestly including failures.
