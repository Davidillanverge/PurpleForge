---
name: lab-spec
description: >
  Validates a PurpleForge lab-spec.yml against the JSON Schema, runs semantic
  checks (name/IP collisions, vulnerability prerequisites, trust references),
  resolves defense.profile defaults, assigns the IP plan, estimates cost, and
  runs the hardening<->vulnerabilities reconciliation (on_conflict: warn |
  exclude-control | fail). Emits generated/<lab>/lab-manifest.json. This is
  always the FIRST skill invoked for any lab — every other skill
  (network-topology, infra-aws/azure, ad-topology, ad-theming, vuln-injection,
  defensive-controls, purple-validation) consumes the manifest this skill
  produces rather than re-reading the raw spec.
---

# lab-spec

## When to use this skill

- The user runs `/new-lab`, `/generate`, or otherwise asks to validate, resolve,
  or turn a `lab-spec.yml` into a `lab-manifest.json`.
- Any other skill that needs a resolved defense config, IP plan, or
  reconciliation result should ask for `generated/<lab>/lab-manifest.json` to
  exist first — if it's missing or stale, run this skill before continuing.

## What it does

All of the deterministic logic lives in `scripts/forge.py` (schema validation,
semantic checks, profile resolution, IP assignment, cost estimate,
reconciliation) — **do not reimplement this by hand or by eyeballing the YAML.**
Always shell out to the script; it is unit-testable and it is the single
source of truth for how a spec resolves.

```bash
# Validate + resolve + reconcile + write generated/<lab.name>/lab-manifest.json
python3 scripts/forge.py lab-spec specs/<name>.yml

# Validate + reconcile only, don't write the manifest (useful for /new-lab
# before the user has confirmed the spec, or for CI)
python3 scripts/forge.py lab-spec specs/<name>.yml --check-only
```

Exit code 0 = valid (manifest written unless `--check-only`). Exit code 1 =
schema, semantic, or reconciliation (`on_conflict: fail`) failure — the stderr
output lists every error; surface these to the user verbatim rather than
paraphrasing, they're already precise. Exit code 2 = spec file not found.

### Responsibilities in detail

1. **Schema validation** — `specs/schema/lab-spec.schema.json` via
   `jsonschema.Draft202012Validator`.
2. **Semantic checks** (beyond what JSON Schema can express):
   - Duplicate `forest[].domain` or `forest[].netbios`.
   - `forest[].trust.target` must reference another domain in `forest[]` and
     not itself.
   - `machines[].domain` must reference a domain in `forest[]`.
   - `forest[].domain_controllers` must equal the sum of
     `machines[]` entries with `role: domain-controller` for that domain.
   - Every id in `vulnerabilities[]` must exist in
     `catalog/vulnerabilities/*.yml`, and if the catalog entry declares
     `attack.requires_services`, at least one machine in the spec must offer
     that service (e.g. `adcs-esc1` requires a machine with `services: [adcs]`).
3. **defense.profile resolution** — loads
   `catalog/defense/profiles/<profile>.yml`, deep-merges the spec's
   `defense:` block on top (spec always wins; lists are replaced wholesale,
   not merged element-by-element).
4. **IP plan** — deterministic from `lab.name` (not `population.seed`, which
   only governs population/theming): a `/16` supernet, a `/24` management
   subnet for the jump host, and one `/24` per forest domain with
   domain-controller/member-server/workstation host ranges. Downstream
   `network-topology`/`infra-aws`/`infra-azure` skills consume this plan
   rather than inventing their own addressing.
5. **Cost estimate** — rough $/day and $/month from a per-role/provider
   hourly-rate table, flagged against `lab.budget_alert_usd`. This is an
   order-of-magnitude signal, not a substitute for the cloud provider's
   pricing calculator — say so if the user asks for precision.
6. **Eval image expiry** — informational note that Windows evaluation images
   expire 180 days after install for any `os:` used in `machines[]`.
7. **Reconciliation** (invariant #3 in `CLAUDE.md`) — cross-references
   every selected `vulnerabilities[]` id's `neutralized_by` list against the
   resolved `defense.hardening` (baseline + fixed toggle controls:
   `laps`, `lsa_protection`, `credential_guard`, `smb_signing`,
   `ldap_signing`, `disable_llmnr_nbtns_mdns`). `neutralized_by` entries come
   in two forms:
   - `hardening.controls.<fixed-toggle-name>` — independently checked against
     the resolved control's boolean value.
   - `hardening.controls.<free-form-label>` paired with a
     `hardening.baseline: [levels]` entry — the free-form label is a
     human-readable name for a rule bundled inside those baseline level(s)
     (e.g. `adcs_template_hardening` inside `cis-l2`); only the baseline
     membership check triggers the conflict, the label is purely for
     manifest readability.

   Resolution per `on_conflict`:
   - `fail` → raises, no manifest written, non-zero exit.
   - `warn` → manifest's `reconciliation.warnings` lists every conflict;
     nothing is changed.
   - `exclude-control` → if `hardening.intentional_gaps_auto` is true, fixed
     toggles are flipped to `false` in `defense_resolved`, and
     baseline-bundled conflicts are recorded in
     `reconciliation.excluded_controls` as an **abstract** exclusion (the
     concrete `ansible-lockdown` `skip_rule` variable mapping is the
     `defensive-controls` skill's job, later in the pipeline — don't try to
     invent rule IDs here). If `intentional_gaps_auto` is false, exclusions
     are NOT auto-derived even though `on_conflict: exclude-control` was
     requested — conflicts fall back to `warnings` with a note explaining why.

## Output contract

`generated/<lab.name>/lab-manifest.json` — gitignored, regenerated on every
run. Downstream skills should treat it as the source of truth for the
resolved defense stack, IP plan, and reconciliation outcome; they should not
re-read `defense.profile` or `neutralized_by` themselves.

## Testing this skill

`specs/examples/medieval-2dom-azure.yml` and
`specs/examples/corp-espionage-aws.yml` are the canonical golden specs — both
must validate cleanly (`--check-only` exit 0). The medieval example is a
deliberate reconciliation test case: `gpp-cpassword` + `hardening.baseline:
cis-l1` genuinely conflict (the catalog's `gpp-cpassword.yml` lists `cis-l1`
in its neutralizing baselines) while `kerberoasting`/`adcs-esc1`/`dcsync-acl`
only conflict at `cis-l2`/`stig` and should pass through untouched at `cis-l1`.
The corp-espionage example additionally exercises a fixed-toggle exclusion
(`lsa_protection` vs `unconstrained-delegation`). When adding a vulnerability
or hardening control, prefer extending these two specs' assertions over
writing a third example.
