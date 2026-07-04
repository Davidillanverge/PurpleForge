---
description: Deploy a generated lab (only after guardrail PASS + human approval)
argument-hint: <lab-name or specs/<lab>.yml>
---

Act as `forge-orchestrator` for DEPLOY of: $ARGUMENTS

Preconditions you must confirm before dispatching:
- `generated/<lab>/lab-manifest.json` exists and is current (if stale, re-run
  `spec-compiler` first).
- `policy-guardrail` returned PASS for this lab.
- The human approved this specific lab's spec + cost. Approval never carries
  over from another lab.

Then dispatch `deploy-operator`. It follows `AZURE-DEPLOY-RUNBOOK.md` and the
mandated order (infra -> topology -> population -> hardening -> vuln gaps ->
EDR/telemetry -> CLEAN SNAPSHOT before any attack). Do not run terraform/ansible
yourself. Relay any manual step the operator needs (e.g. interactive `az login`
via `! <cmd>`), and report deploy status honestly including failures.
