# Vulnerability validation plan — pirates-lab

_Generated 2026-07-06 17:10 UTC from `lab-manifest.json`. For each injected vuln,
confirm two things live: the config was **applied** (the AD artifact landed) and it is
actually **exploitable**. This is not a detection/coverage matrix._

| Vuln | ATT&CK | Host | Reconciliation | Applied signature (confirm present) | Exploitability check |
|---|---|---|---|---|---|
| asreproast | T1558.004 | dc01 | clear | DontReqPreauth | T1558.004 |
| kerberoasting | T1558.003 | dc01 | clear | HasSPN | T1558.003 |
| dcsync-acl | T1003.006 | dc01 | clear | DCSync | T1003.006 |

## How to confirm each vuln

1. **Applied** — query AD with a signing-aware client (e.g. `nxc`) for the artifact in
   the 'Applied signature' column (a UAC flag, an SPN, an ACE, a group membership, a
   SYSVOL file…). Present ⇒ the injection landed.
2. **Exploitable** — run the primitive in the last column (roast the hash, read the
   cpassword, abuse the ACL) and confirm it actually yields what it should.
3. Record YES/NO/PARTIAL + evidence per vuln in the results template, then re-run with
   `--results` to write the confirmed report.
