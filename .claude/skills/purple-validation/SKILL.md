---
name: purple-validation
description: >
  Validates a deployed PurpleForge lab against its plan and produces the
  three-state coverage matrix. First derives the EXPECTED PREVENIDO / DETECTADO /
  NO VISTO matrix offline from lab-manifest.json (scripts/forge.py validate),
  then confirms it against the LIVE lab over the WireGuard tunnel: SharpHound →
  BloodHound (do the intended attack-path edges exist?), PingCastle (AD posture),
  and the Atomic Red Team tests mapped from each injected vuln (did the technique
  get prevented, detected, or go unseen?). Runs after the clean snapshot, before
  report-writer consolidates lab-report.md. Consumed by the purple-validator agent.
---

# purple-validation

## When to use this skill

- The user runs `/validate`, or the `purple-validator` agent needs to measure a
  deployed lab's defensive coverage.
- Only against a LIVE, isolated lab reachable over the bastion tunnel, and only
  AFTER `deploy-operator` took the clean snapshot (attacks must be resettable).

## What it does — two phases

### 1. Offline plan (deterministic — always run first)

```bash
python3 scripts/forge.py validate specs/<lab>.yml
```

Crosses each `vulnerabilities_planned` entry in `lab-manifest.json` with its
catalog `detect`/`validate` metadata and the resolved defense stack to write
`generated/<lab>/validation-plan.{json,md}`: the **expected** matrix plus the
Atomic test id and BloodHound edge to confirm per technique. This is the
deterministic checklist — the state machine lives in `forge.py`, not in
eyeballing (CLAUDE.md). It is a prediction, not a measurement.

Phase 1 also writes `validation-results.template.json` — the exact skeleton you
fill in during phase 2 (one `actual_state` + `evidence` per technique, plus a
true/false per BloodHound edge and a PingCastle score).

### 2. Live confirmation (over the tunnel)

Run the real tools against the live lab and fill in the template:

- **Paths** — collect with SharpHound, open in BloodHound, confirm every
  `bloodhound_edge` from the plan exists (e.g. `HasSPN`, `DontReqPreauth`,
  `ADCSESC1`). Set each edge true/false. A missing edge means injection didn't
  land or hardening closed it.
- **Posture** — run PingCastle; put the score in `pingcastle_score`.
- **Techniques** — run each Atomic Red Team test and record the ACTUAL result in
  `actual_state`:
  - **PREVENIDO** — blocked (EDR prevent / hardening control).
  - **DETECTADO** — ran and produced the expected detection signal/telemetry.
  - **NO VISTO** — ran and nothing caught it (a real coverage gap).

Connectivity mirrors `AZURE-DEPLOY-RUNBOOK.md` (WireGuard up, Ansible-over-Docker
`--network host`). `forge.py ad-inventory` can corroborate that the injected
accounts/edges are live before firing attacks.

### 3. Confirm — close the loop (deterministic)

```bash
python3 scripts/forge.py validate specs/<lab>.yml --results <filled-template>.json
```

Merges the live results with the predicted plan and writes the confirmed
`generated/<lab>/validation-report.md` (+ `.json`): the actual-vs-expected
three-state matrix, every **divergence** flagged (⚠️), and a Findings list
(state divergences + intended BloodHound edges that did not materialize). A
divergence is a finding, not an error — it is the whole point of the exercise.

## Output

`validation-report.md` is the confirmed deliverable; hand it to `report-writer`,
which folds it into `lab-report.md`. Never inline generated secrets (credentials,
NT hashes) into a committed report.

## What is / isn't automated

Phases 1 and 3 (predict, and merge→confirmed report) are fully deterministic in
`forge.py` and tested. Phase 2 — driving SharpHound/PingCastle/Atomic over the
tunnel — is run by the agent following this skill; a future phase can wrap it the
way `ad-inventory` already wraps live LDAP/DCSync.
