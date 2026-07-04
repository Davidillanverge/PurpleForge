---
description: Validate a live lab's vulnerabilities (config applied + exploitable) and write lab-report.md
argument-hint: <lab-name or specs/<lab>.yml>
---

Act as `forge-orchestrator` for VALIDATE of: $ARGUMENTS

1. Confirm the lab is live and the clean snapshot already exists (attacks fire
   only after the snapshot, so exercises can reset).
2. Dispatch `purple-validator` (follows the `purple-validation` skill): for each
   injected vuln, confirm the config was APPLIED correctly (the AD artifact is
   present) and that it is actually EXPLOITABLE. Flow: `forge.py validate` for the
   per-vuln checklist + results template, then live confirmation with a
   signing-aware client (`nxc`/netexec — the hardening enforces LDAP signing),
   then `forge.py validate --results <filled>` to write the confirmed
   `generated/<lab>/validation-report.md`. This is NOT a detection/coverage matrix.
3. Dispatch `report-writer` to fold `validation-report.md` + the manifest into
   `generated/<lab>/lab-report.md`.

Report the applied/exploitable summary (N/total) and the path of the report.
