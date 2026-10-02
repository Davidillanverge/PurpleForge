---
description: BAS exercise's ATT&CK Navigator layer -> validated specs/<lab>.yml (translate + compile + guardrail gates)
argument-hint: <path to ATT&CK Navigator layer JSON> [--name x] [--provider azure|proxmox|aws] [--theme t] [--region r] [--domain d] [--users n] [--seed n] [--exact-only]
---

Author a NEW lab from a Breach & Attack Simulation exercise, from the MAIN
thread. The request: $ARGUMENTS

The inverse of `/new-lab`: there the human describes a lab; here the exercise's
ATT&CK technique list drives it. The lab's intentional gaps become exactly the
catalog vulnerabilities that reproduce the exercise's techniques — so the
environment is provably vulnerable to the attack that was designed first.

You own ordering and gates; run the deterministic steps yourself with Bash. The
translator is deterministic and AI-free — your job is to parse intent, fill the
infra envelope the layer cannot carry, judge the coverage gaps, and gate spend.

1. **Parse $ARGUMENTS.** First token is the path to an ATT&CK Navigator layer
   JSON (the artifact `bas-purple-team-exercise` emits). The rest are envelope
   overrides. The layer decides *which vulns*; everything below it does not —
   provider/theme/region/population/topology come from flags or defaults, so set
   them from any intent in the request (e.g. "on Proxmox, medieval theme, 300
   users" → `--provider proxmox --theme medieval --users 300`).

2. **Translate** — run the converter (do NOT hand-map techniques; it is the
   single source of truth, and the technique→vuln index is computed from the
   catalog):
   ```bash
   forge from-exercise <layer.json> [--name … --provider … --theme … --region … \
       --domain … --users … --seed … --density … --budget … --chain independent|ctf \
       --exact-only] [--out specs/<name>.yml]
   ```
   (`python3 -m forge from-exercise …` is the same entry point without the install.)
   It prints the matched vulns (exact vs `approx` parent↔sub roll-up) and the
   techniques with NO catalog coverage, then writes `specs/<lab>.yml`. Surface
   that report verbatim. **Exit 1** = no technique mapped to any vuln (the lab
   would be vulnerable to nothing): STOP and report — the layer is off, or the
   needed vulns don't exist yet (see step 3). **Exit 2** = bad layer/path.

3. **Judge the coverage gaps** (the uncovered-technique list). Each is one of:
   - a **runtime-only TTP** the red team performs anyway (recon, phishing,
     PowerShell exec, C2, exfil) — no lab change needed; say so and move on.
   - a **precondition the catalog can't build yet** — a real environmental gap
     with no `catalog/vulnerabilities/<id>.yml`. Offer to dispatch the
     **`catalog-author`** agent to author it (it researches the ATT&CK id + the
     upstream primitive and enforces the schema), then re-run step 2. This is a
     human decision — do not author vulns unprompted.
   Also sanity-check the `approx` matches: if a parent↔sub roll-up pulled in a
   vuln the exercise didn't intend, re-run with `--exact-only` or trim
   `vulnerabilities[]` in the spec by hand.

4. **Compile** — `forge lab-spec specs/<lab>.yml` → produces `lab-manifest.json`.
   On failure, surface the exact stderr (it's precise) and fix the spec. The
   reconciliation output is the point of this whole flow: `intentional_gaps_auto`
   + `on_conflict: exclude-control` force each selected vuln's `neutralized_by`
   gap open, so the manifest *proves* the lab stays vulnerable to the exercise's
   techniques even under the defensive baseline. Call that out explicitly.

5. **Guardrail** — `forge guardrail specs/<lab>.yml`. Non-zero = FAIL: STOP,
   report the named invariant(s), don't deploy. Also make the invariant #6
   (authorized use) judgement it prints — an isolated, authorized lab only.

6. **HUMAN GATE** — present: the technique→vuln table (matched, with exact/approx),
   the uncovered techniques and how you classified each, the lab summary
   (topology, services, defense), the cost estimate, and the reconciliation
   outcome (which gaps were forced open). Ask for approval before any spend. Do
   NOT generate/deploy here — that's `/generate` then `/deploy`.

Keep the exercise's own output (hypotheses, playbook, Sigma/SIEM, Caldera
abilities) intact — this command only builds the target it runs against.
