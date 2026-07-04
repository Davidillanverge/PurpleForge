---
description: Validate a live lab and write lab-report.md (paths, posture, coverage matrix)
argument-hint: <lab-name or specs/<lab>.yml>
---

Act as `forge-orchestrator` for VALIDATE of: $ARGUMENTS

1. Confirm the lab is live and the clean snapshot already exists (attacks fire
   only after the snapshot, so exercises can reset).
2. Dispatch `purple-validator`: SharpHound->BloodHound (confirm intended edges),
   PingCastle (posture), Atomic Red Team per injected vuln -> classify each
   ATT&CK technique as PREVENIDO / DETECTADO / NO VISTO.
3. Dispatch `report-writer` to consolidate the manifest + validation results into
   `generated/<lab>/lab-report.md` (and an Artifact of the coverage matrix if the
   user wants one).

Report the coverage matrix summary and the path of the report. Never inline
generated secrets.
