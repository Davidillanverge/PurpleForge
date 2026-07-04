---
name: purple-validation
description: >
  Validates a deployed PurpleForge lab's injected vulnerabilities: for each one,
  confirm the config was APPLIED correctly (the AD artifact the injection should
  have created is present) and that it is actually EXPLOITABLE (the attack
  primitive works). This is NOT a detection/coverage matrix — whether a SIEM/EDR
  would catch the technique is detection-lab's concern, not vulnerability
  validation. Runs against the live lab over the WireGuard tunnel, after the clean
  snapshot. Consumed by the purple-validator agent; produces validation-report.md.
---

# purple-validation

## When to use this skill

- The user runs `/validate`, or the `purple-validator` agent needs to confirm a
  deployed lab's vulnerabilities landed and are exploitable.
- Only against a LIVE, isolated lab reachable over the bastion tunnel, after
  `deploy-operator` took the clean snapshot.

## What validation is (and isn't)

For each injected vuln, confirm exactly two things:

1. **Applied** — the config the injection was supposed to create is actually
   present in AD (a `userAccountControl` flag, an SPN, an ACE, a group
   membership, a SYSVOL file…). Present ⇒ the injection landed.
2. **Exploitable** — running the vuln's own primitive actually yields what it
   should (a roastable hash, a readable cpassword, a usable ACL).

It is **not** about PREVENIDO/DETECTADO/NO VISTO — a vuln's whole point is to be
reachable. Detection coverage (would a SIEM alert?) belongs to `detection-lab`,
which is a separate stack.

## Flow

### 1. Build the checklist (deterministic)

```bash
python3 scripts/forge.py validate specs/<lab>.yml
```

Writes `generated/<lab>/validation-plan.{json,md}` — per vuln, the **applied
signature** to confirm present and the **exploitability check** to run — plus a
`validation-results.template.json` to fill in.

### 2. Confirm live (over the tunnel)

The hardening baseline usually enforces **LDAP signing**, so plain-LDAP tools
(`impacket-dacledit`, bare `ldap3`, `forge.py ad-inventory`) fail
`strongerAuthRequired`. Use a signing-aware client — **`nxc`/netexec**:

- **Applied**: `nxc ldap <dc> -u <user> -p <pass> --query "(<filter>)" "<attrs>"`
  to read the artifact; `nxc ldap ... -M daclread` to confirm ACEs (DCSync
  grant, KeyCredentialLink write, etc.).
- **Exploitable**: run the primitive — `--asreproast`, `--kerberoasting out
  --kdcHost <dc-ip>` (pass `--kdcHost` when the attacker box has no DNS to the
  domain), `nxc smb ... -M gpp_password`, read the description field, etc.
- Record `applied` and `exploitable` as **YES / NO / PARTIAL** + an evidence
  string per vuln in the template.

### 3. Confirm — write the report (deterministic)

```bash
python3 scripts/forge.py validate specs/<lab>.yml --results <filled-template>.json
```

Writes `generated/<lab>/validation-report.md` (+ `.json`): per vuln, Applied and
Exploitable with evidence, an `N/total` summary, and Findings for anything not
applied (injection didn't land) or applied-but-not-exploitable (a control may
have neutralized it).

## Output

`validation-report.md` is the deliverable; hand it to `report-writer`, which folds
it into `lab-report.md`. Do not fire attacks before the clean snapshot exists.

## What is / isn't automated

Phases 1 and 3 (checklist, and merge→report) are deterministic in `forge.py` and
tested. Phase 2 — the live `nxc` queries/exploits over the tunnel — is run by the
agent following this skill.
