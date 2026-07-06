---
description: Validate a live lab's vulnerabilities (config applied + exploitable) and write lab-report.md
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate VALIDATE from the MAIN thread for: $ARGUMENTS

1. Confirm the lab is live and the clean snapshot already exists (attacks fire
   only after the snapshot, so exercises can reset).
2. Dispatch `purple-validator` (follows the `purple-validation` skill). It does
   both halves in one context: for each injected vuln, confirm the config was
   APPLIED (the AD artifact is present) and is EXPLOITABLE — flow is
   `forge.py validate` for the checklist + results template, live confirmation
   with a signing-aware client (`nxc`/netexec — the hardening enforces LDAP
   signing), then `forge.py validate --results <filled>` for the confirmed
   `validation-report.md` — and then it folds that + the manifest into
   `generated/<lab>/lab-report.md`. NOT a detection/coverage matrix.

Report the applied/exploitable summary (N/total) and the path of the report.
