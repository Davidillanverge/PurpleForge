---
description: Validate a live lab's vulnerabilities (config applied + exploitable) — forge.py validate --run
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate VALIDATE from the MAIN thread for: $ARGUMENTS

Validation is now a single deterministic command — run it yourself with Bash; you
do NOT need the `purple-validator` subagent for the normal case.

1. Confirm the lab is live and reachable (WireGuard tunnel up — `deploy.sh` brings
   it up; if it's down, re-run `forge.py deploy`).
2. `python3 scripts/forge.py validate specs/<lab>.yml --run` — it drives the live
   checks over the tunnel (nxc/netexec): auto-confirms the roasting vulns and, for
   the interactive ones (ACL/cert/SYSVOL abuse), writes the exact command to run
   and marks them `REQUIRES-HUMAN`. It writes `generated/<lab>/validation-report.md`.
3. For any `REQUIRES-HUMAN` row, either run the emitted command yourself over the
   tunnel and re-check, or hand the human the command list from the report.

Report the applied/exploitable summary (N/total, plus how many need a manual
command) and the path of the report. This is NOT a detection/coverage matrix.
