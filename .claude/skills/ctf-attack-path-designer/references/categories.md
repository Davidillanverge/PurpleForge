# CTF category reference

Per-category realism rules, canonical technique families, common design pitfalls,
and difficulty calibration. Read the section for the challenge's category before
designing. The technique families are *design vocabulary*, not an exhaustive list —
use them to keep stages realistic, not to pad a chain with unnecessary steps.

## Contents

- [Difficulty calibration (all categories)](#difficulty-calibration)
- [Web Application Security](#web)
- [Pwn / Binary Exploitation](#pwn)
- [Reverse Engineering](#reverse)
- [Cryptography](#crypto)
- [Digital Forensics](#forensics)
- [Active Directory](#ad)
- [Cloud Security](#cloud)
- [Linux Privilege Escalation](#linux-privesc)
- [Windows Privilege Escalation](#windows-privesc)
- [Network Security](#network)
- [Miscellaneous](#misc)
- [Multi-stage / Red-Team Infrastructure](#multistage)

<a id="difficulty-calibration"></a>
## Difficulty calibration (all categories)

Difficulty is a function of *stage count*, *obscurity of each vuln*, *subtlety of
breadcrumbs*, and *how much chaining/correlation is required* — not of artificial
obstacles (rate limits, deliberately broken tooling, trivia).

| Level | Stages | Vuln obscurity | Breadcrumbs | Chaining |
|---|---|---|---|---|
| Beginner | 1–2 | Textbook, single well-known class | Explicit, adjacent to the vuln | None/linear |
| Intermediate | 2–4 | Common but needs correct configuration/parameters | Present but requires enumeration | One clear chain |
| Advanced | 3–6 | Requires combining two primitives or a non-default twist | Subtle, may need correlating 2 artifacts | Multi-step, some branching |
| Insane | 5+ | Novel chaining, custom protocol, or a hard constraint to bypass | Minimal; deduced from behavior | Deep, with dead-ends that teach |

Never raise difficulty by removing the breadcrumb that makes a step deducible —
that converts the step into guessing (violates quality rule #1).

<a id="web"></a>
## Web Application Security

**Realism rules:** pick a concrete stack (framework + language + datastore + proxy)
and keep every flaw consistent with it. A flaw must be reachable by the role the
player currently holds.

**Technique families (map to OWASP/CWE):** injection — SQLi `CWE-89`, command
injection `CWE-78`, SSTI `CWE-1336`; broken access control `A01` — IDOR, forced
browsing, path traversal `CWE-22`; auth flaws — JWT confusion/`alg:none`, weak reset
tokens; SSRF `CWE-918` (→ cloud metadata, internal services); deserialization
`CWE-502`; file upload → webshell (requires a reachable, executable upload dir);
XXE `CWE-611`; LFI→RCE *only* via a concrete vector (log poisoning, PHP wrappers,
session files).

**Common pitfalls:** declaring LFI as RCE with no inclusion vector; SQLi "leads to
shell" without `INTO OUTFILE`/`xp_cmdshell`/stacked-query justification; an upload
bypass whose directory isn't executable; a JWT bug where the secret is
undiscoverable.

<a id="pwn"></a>
## Pwn / Binary Exploitation

**Realism rules:** state arch (x86/x64/ARM), libc version, and every mitigation
(NX, ASLR, PIE, stack canary, RELRO, Full/Partial). The exploit technique must be
consistent with the mitigations you declared — do not leave a primitive enabled that
trivializes the intended path unless that is the intended path.

**Technique families:** stack BOF (ret2win / ret2libc / ROP), format string
`CWE-134` (leak + arbitrary write), heap (UAF `CWE-416`, double-free, tcache
poisoning, fastbin dup), integer overflow `CWE-190` → OOB, GOT overwrite. Provide
the leak the player needs (a libc/stack leak) before requiring it.

**Common pitfalls:** ROP chain with no gadget source; ret2libc without a libc leak
under ASLR; a heap technique impossible on the stated libc version.

<a id="reverse"></a>
## Reverse Engineering

**Realism rules:** state language/toolchain (C, Go, Rust, .NET, packed native,
obfuscated JS/bytecode). The flag-check logic must be *solvable by analysis* — a
keygen-me, a constraint set solvable with a SAT/SMT approach, or a reversible
transform — not an opaque remote oracle.

**Technique families:** static analysis (disassembly/decompilation), dynamic
analysis (debugger, instrumentation), unpacking (UPX/custom), anti-debug/anti-VM to
defeat, VM/bytecode interpreters to reverse, symbolic execution targets.

**Common pitfalls:** flag derived from data not present in the binary; anti-debug
with no documented bypass; "just brute force" where the space is infeasible.

<a id="crypto"></a>
## Cryptography

**Realism rules:** the weakness must be a *property of the construction*, and the
player must have enough oracle/ciphertext/known-plaintext to exploit it. Prefer
classic, well-understood breaks over bespoke math unless Insane.

**Technique families:** RSA (small `e`, common modulus, Wiener low-`d`, Håstad
broadcast, partial-key); block-cipher misuse (ECB pattern, CBC bit-flip/padding
oracle, nonce reuse in CTR/GCM); weak PRNG / seed recovery; hash length-extension;
poor DH/ECC parameter choices.

**Common pitfalls:** requiring a break with insufficient data (e.g. padding oracle
with no oracle); "factor a 2048-bit modulus"; a scheme whose only solution is
guessing the key.

<a id="forensics"></a>
## Digital Forensics

**Realism rules:** the evidence container (pcap, memory image, disk image, log
bundle, office doc, image/audio) must actually *contain* the artifact the flag
requires, placed so enumeration reveals it. State the tools the format implies
(Wireshark, Volatility + a real profile, Autopsy, binwalk, exiftool).

**Technique families:** network forensics (protocol carving, credential/file
extraction from pcap), memory forensics (process/injection/credential artifacts),
disk/file carving, steganography (only with a discoverable key/method —
never pure guessing), log analysis & timeline reconstruction, document metadata.

**Common pitfalls:** stego with no hint to the embedding method/password;
"find the flag in the pcap" with no protocol trail; a memory image with no stated
profile.

<a id="ad"></a>
## Active Directory

**Realism rules:** define the forest/domain, users, groups, ACLs, and host roles;
every abuse must correspond to a real object relationship the player can enumerate
(BloodHound-style). Keep it consistent with Windows/AD-CS versions. This aligns with
PurpleForge labs — see the repo's `catalog/vulnerabilities/` for the canonical
primitives and their `mitigate`/`neutralized_by`.

**Technique families:** AS-REP roasting (`T1558.004`), Kerberoasting (`T1558.003`),
ACL abuse (GenericAll/WriteDACL/GenericWrite → targeted reset/`T1098`), delegation
abuse (unconstrained/constrained/RBCD), AD CS ESC1–ESC8 (`T1649`), DCSync
(`T1003.006`), GPO abuse, AdminSDHolder, trust abuse for cross-domain.

**Common pitfalls:** Kerberoasting a user with no SPN; ESC1 with no vulnerable
template or no enrollment rights; DCSync without the replication rights that grant
it; a path BloodHound would not actually surface.

<a id="cloud"></a>
## Cloud Security

**Realism rules:** name the provider (AWS/Azure/GCP) and keep IAM/resource names and
privilege-escalation paths faithful to that provider's real model. Credentials must
be discovered, never assumed.

**Technique families:** SSRF → instance metadata (IMDSv1) → role creds; over-
permissive IAM policy → privesc (`iam:PassRole`, `*:*`); public storage bucket/blob;
exposed secrets in functions/pipelines/env; container escape → node → cluster
(K8s RBAC, service-account token); cross-account trust abuse.

**Common pitfalls:** IMDSv2 declared but exploited as v1; a privesc that the stated
IAM policy does not actually permit; inventing a service API behavior.

<a id="linux-privesc"></a>
## Linux Privilege Escalation

**Realism rules:** the misconfiguration must be enumerable (LinPEAS-style) and the
escalation must follow from it deterministically.

**Technique families:** sudo misconfig (`NOPASSWD`, GTFOBins binary), SUID/SGID
GTFOBins, cron/path injection, writable service/unit/`PATH`, capabilities
(`cap_setuid`), kernel exploit (only with a stated vulnerable kernel version),
secrets in history/config, container/namespace escape.

**Common pitfalls:** kernel exploit with no version pinned; a SUID binary with no
GTFOBins route; "writable /etc/passwd" dropped in without a discovery breadcrumb.

<a id="windows-privesc"></a>
## Windows Privilege Escalation

**Realism rules:** enumerable (WinPEAS/PrivescCheck) and faithful to Windows
privilege semantics.

**Technique families:** token-impersonation privileges (`SeImpersonate` →
Potato family, `T1134`), unquoted service paths, weak service permissions/binary
hijack, `AlwaysInstallElevated`, DLL hijack, UAC bypass, stored creds / unattend /
registry autologon, scheduled-task abuse.

**Common pitfalls:** Potato without the impersonation privilege present; unquoted
service path where the player can't write the intermediate dir; a UAC bypass as the
*privilege* step when the player is already SYSTEM-adjacent.

<a id="network"></a>
## Network Security

**Realism rules:** topology, segments, and what is routable from where must be
explicit; attacks must be possible from the player's network position.

**Technique families:** service enumeration & exploitation of exposed services,
MitM/ARP (same-segment only), VLAN hopping, SNMP, protocol downgrade, pivoting via
SSH/chisel/proxychains, firewall/ACL evasion by legitimate reachable paths.

**Common pitfalls:** MitM across a routed boundary; attacking a host no path
reaches; pivoting through a host that has no second interface.

<a id="misc"></a>
## Miscellaneous

**Realism rules:** even "misc" needs a deducible mechanism. State the exact
technology (git, QR, esoteric lang, CI/CD, protocol quirk). No trivia-guessing.

**Common pitfalls:** flags behind out-of-band knowledge; puzzles with no in-scenario
breadcrumb; relying on a specific external site staying online.

<a id="multistage"></a>
## Multi-stage / Red-Team Infrastructure

**Realism rules:** compose single-category stages across multiple hosts/segments
with explicit trust boundaries and pivots. Map the whole thing to the Cyber Kill
Chain at the narrative level and to ATT&CK per stage. Each host is reachable only
after the stage that unlocks it — draw the pivot explicitly in the diagram.

**Design method:** design each host as its own mini attack path (use the relevant
category section), then define the *inter-host* transitions: the credential, token,
trust, or network route that carries the player from host N to host N+1. Those
transitions are the stages most prone to unintended solutions — scrutinize them in
validation.

**Common pitfalls:** a later host reachable directly from the start (segmentation
gap); a credential found early that unlocks a much later host (over-privilege); a
pivot host with no route onward.
