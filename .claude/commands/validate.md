---
description: Validate a live lab's vulnerabilities (config applied + exploitable) — forge validate --run
argument-hint: <lab-name or specs/<lab>.yml>
---

Orchestrate VALIDATE from the MAIN thread for: $ARGUMENTS

A single deterministic command — run it yourself with Bash.

1. Confirm the lab is live (WireGuard tunnel up; if down, re-run `forge
   deploy`).
2. `forge validate specs/<lab>.yml --run` — drives live
   checks over the tunnel (nxc/netexec): auto-confirms roasting vulns; for
   interactive ones (ACL/cert/SYSVOL) it writes the exact command and marks them
   `REQUIRES-HUMAN`. Writes `generated/<lab>/validation-report.md`.
3. For each `REQUIRES-HUMAN` row, run the emitted command over the tunnel and
   re-check, or hand the human the command list.

Report the applied/exploitable summary (N/total + how many need a manual
command) and the report path. This is NOT a detection/coverage matrix.
