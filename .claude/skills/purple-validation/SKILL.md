---
name: purple-validation
description: >
  Validates a deployed PurpleForge lab's injected vulnerabilities: for each one,
  confirm the config was APPLIED (the AD artifact the injection should have
  created is present) and that it is actually EXPLOITABLE (the primitive works).
  NOT a detection/coverage matrix — whether a SIEM/EDR would catch it is out of
  scope. Runs against the live lab over the WireGuard tunnel, after the clean
  snapshot. Produces validation-report.md.
---

# purple-validation

## When to use

- `/validate`, or the `purple-validator` agent confirming a deployed lab's vulns.
- Only against a LIVE, isolated lab over the bastion tunnel, after the clean
  snapshot.

## What validation is (and isn't)

Per injected vuln, confirm two things:

1. **Applied** — the config the injection should have created is present in AD (a
   `userAccountControl` flag, an SPN, an ACE, a group membership, a SYSVOL file).
2. **Exploitable** — running the vuln's own primitive yields what it should (a
   roastable hash, a readable cpassword, a usable ACL).

It is NOT about detection state — a vuln's whole point is to be reachable.
Detection coverage is out of scope; this harness ships no detection pipeline.

## Flow

**1. Build the checklist (deterministic)**

```bash
forge validate specs/<lab>.yml
```

Writes `validation-plan.{json,md}` (per vuln: the applied signature + the
exploitability check) + `validation-results.template.json` to fill.

**2. Confirm live (over the tunnel)** — the hardening baseline usually enforces
**LDAP signing**, so plain-LDAP tools (`impacket-dacledit`, bare `ldap3`,
`forge ad-inventory`) fail `strongerAuthRequired`. Use a signing-aware client,
**`nxc`/netexec**:

- **Applied**: `nxc ldap <dc> -u <user> -p <pass> --query "(<filter>)" "<attrs>"`;
  `-M daclread` to confirm ACEs.
- **Exploitable**: `--asreproast`, `--kerberoasting out --kdcHost <dc-ip>` (pass
  `--kdcHost` when the attacker box has no DNS to the domain), `-M gpp_password`,
  read the description, etc.
- Record `applied`/`exploitable` as **YES / NO / PARTIAL** + evidence per vuln.

**3. Write the report (deterministic)**

```bash
forge validate specs/<lab>.yml --results <filled>.json
```

Writes `validation-report.md` (+`.json`): per vuln Applied + Exploitable with
evidence, an `N/total` summary, and Findings for anything not applied or
applied-but-not-exploitable.

## Output

`validation-report.md` is intermediate; `purple-validator` folds it + the
manifest into `lab-report.md`. Don't fire attacks before the clean snapshot.

Phases 1 and 3 are deterministic in `forge` and tested. Phase 2 (live nxc
queries/exploits) is run by the agent.
