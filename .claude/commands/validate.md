---
description: Validate a live lab and write lab-report.md (paths, posture, coverage matrix)
argument-hint: <lab-name or specs/<lab>.yml>
---

Act as `forge-orchestrator` for VALIDATE of: $ARGUMENTS

1. Confirm the lab is live and the clean snapshot already exists (attacks fire
   only after the snapshot, so exercises can reset).
2. Dispatch `purple-validator` (follows the `purple-validation` skill):
   `forge.py validate` for the predicted plan + results template, then live
   SharpHound->BloodHound (confirm intended edges), PingCastle (posture) and
   Atomic Red Team per vuln, then `forge.py validate --results <filled>` to write
   the confirmed `generated/<lab>/validation-report.md`.
3. Dispatch `report-writer` to fold `validation-report.md` + the manifest into
   `generated/<lab>/lab-report.md` (and an Artifact of the coverage matrix if the
   user wants one).

Report the coverage matrix summary and the path of the report. Never inline
generated secrets.
