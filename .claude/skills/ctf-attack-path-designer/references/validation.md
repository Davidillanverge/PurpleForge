# Validation

Phase 5 of the workflow. A design is not finished until it passes these checks. The
goal is to catch the two failure modes that ruin CTFs: a chain that *can't actually
be completed as designed* (broken causality) and a chain that *can be completed the
wrong way* (unintended solution).

## A. Coherence checklist

Walk every stage and confirm:

1. **Tech/version compatibility** — the vulnerability exists for the stated
   technology and version; the exploitation technique is possible under the stated
   mitigations/configuration.
2. **Exploit preconditions present** — everything the vector needs (a leak, an
   oracle, enrollment rights, a writable+executable path, a reachable service) is
   provided by the architecture or an earlier stage.
3. **Identity/permission compatibility** — the role the player holds entering the
   stage is actually allowed to perform the action, and the result grants exactly
   the claimed new identity/permission (no silent privilege inflation).
4. **Connectivity** — the target is reachable from the player's current network
   position; pivots exist where the path crosses a trust boundary.
5. **Stage dependency** — each stage *consumes* exactly what the previous stage
   *produced*; trace the hand-off (credential, token, file, foothold) across the
   whole chain with no gap.
6. **Narrative coherence** — the theme doesn't contradict the technical reality.
7. **Difficulty fit** — stage count, obscurity, and breadcrumb subtlety match the
   declared level (see `categories.md` calibration table).
8. **Reproducibility** — the scenario can be built deterministically; nothing
   depends on a live external service or a random artifact the author can't pin.

Use verifiable references where a claim is non-obvious. **If you are unsure a CVE,
version, or tool behaves as needed, verify it or redesign** — do not ship a stage
built on an assumed behavior.

## B. Unintended-solution hunting

Actively try to break your own design. For each, find the cause, impact, a
realism-preserving mitigation, and a regression test. Check at least:

- **Direct flag access** — can any flag be read without completing its intended
  stage (world-readable file, misconfigured ACL, flag in a web root)?
- **Over-privileged credentials** — does a credential found early unlock something
  much later, collapsing the chain?
- **Accidentally exposed services** — is an internal/objective service reachable
  from the start, skipping the pivot?
- **Escalation that skips the progression** — a privesc or token that jumps past
  intended stages.
- **Prematurely leaked secrets** — a secret readable before the stage that is
  supposed to reveal it.
- **Network routes that bypass pivots** — a direct route to a host that should only
  be reachable after a foothold.
- **Secondary vulnerabilities** — an unintended but equivalent-access flaw
  introduced by the stack you chose.

Record every finding in the unintended-solutions table (`output-format.md` §4.7).
Mitigations tighten permissions/segmentation/exposure; they must **not** disable a
legitimate solving technique or add artificial obstacles.

## C. The four validation tiers

Label every claim with the tier it has actually reached. Be honest — a false
"tested" is worse than an admitted gap.

1. **Proposed design** — the stage/path as designed; not yet checked.
2. **Conceptually validated** — reasoned through the coherence checklist; preconditions
   and hand-offs confirmed on paper.
3. **Experimentally validated** — actually deployed and executed end to end; the
   stage worked and the flag was captured. Only claim this if it genuinely happened
   in this session or the user reports it.
4. **Integrity-validated** — the full scenario was rebuilt clean, the main path
   reproduced, flags verified, known alternative routes probed, and breadcrumbs
   confirmed sufficient (ideally by a fresh solver).

A new design from this skill defaults to tiers 1–2. Do not represent it as tier 3/4
without real execution. If the environment can deploy and run the scenario (and the
user wants it), you may advance tiers — but say exactly what was run.

## D. Test plan output

Produce the §4.8 procedure: clean deploy → reproduce main path → verify each flag →
probe alternative routes → confirm breadcrumbs. Make each step concrete enough that
the challenge author can run it, and tie each to the tier it would establish.
