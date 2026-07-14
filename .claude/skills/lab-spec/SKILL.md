---
name: lab-spec
description: >
  Validates a PurpleForge lab-spec.yml against the JSON Schema, runs semantic
  checks (name/IP collisions, vulnerability prerequisites, trust references),
  resolves defense.profile defaults, assigns the IP plan, estimates cost, and
  runs the hardening<->vulnerabilities reconciliation (on_conflict: warn |
  exclude-control | fail). Emits generated/<lab>/lab-manifest.json. Always the
  FIRST skill for any lab — every other skill consumes the manifest it produces,
  not the raw spec.
---

# lab-spec

## When to use

- `/new-lab`, `/generate`, or any request to validate/resolve a `lab-spec.yml`
  into a `lab-manifest.json`.
- Any skill needing a resolved defense config, IP plan, or reconciliation must
  ensure `generated/<lab>/lab-manifest.json` exists first; if missing/stale, run
  this skill.

## What it does

All deterministic logic is in `scripts/forge.py`. **Never reimplement it by hand
or eyeball the YAML** — always shell out; it's the single source of truth.

```bash
# validate + resolve + reconcile + write lab-manifest.json
python3 scripts/forge.py lab-spec specs/<name>.yml
# validate only, no manifest (for /new-lab before confirmation)
python3 scripts/forge.py lab-spec specs/<name>.yml --check-only
```

Exit 0 = valid. Exit 1 = schema/semantic/reconciliation (`on_conflict: fail`)
failure — surface the stderr errors verbatim, they're already precise. Exit 2 =
file not found.

### Responsibilities

1. **Schema** — `specs/schema/lab-spec.schema.json` (Draft2020-12).
2. **Semantic checks** (beyond schema):
   - Duplicate `forest[].domain`/`netbios`.
   - `forest[].trust.target` references another domain in `forest[]`, not itself.
   - `machines[].domain` references a domain in `forest[]`.
   - `forest[].domain_controllers` == count of `machines[]` with
     `role: domain-controller` for that domain.
   - Every `vulnerabilities[]` id exists in the catalog; if it declares
     `attack.requires_services`, at least one machine must offer that service.
3. **defense.profile resolution** — loads `catalog/defense/profiles/<profile>.yml`,
   deep-merges the spec's `defense:` on top (spec wins; lists replaced wholesale).
4. **IP plan** — deterministic from `lab.name` (not `population.seed`): a `/16`
   supernet, a `/24` management subnet, one `/24` per domain with DC/member/
   workstation ranges. Downstream skills consume this, not their own addressing.
5. **Cost estimate** — rough $/day, $/month vs `lab.budget_alert_usd`.
   Order-of-magnitude only.
6. **Eval image expiry** — note: Windows eval images expire 180 days after install.
7. **Reconciliation** (invariant #3) — cross-references each vuln's
   `neutralized_by` against resolved `defense.hardening` (baseline + fixed
   toggles: `laps`, `lsa_protection`, `credential_guard`, `smb_signing`,
   `ldap_signing`, `disable_llmnr_nbtns_mdns`). Two `neutralized_by` forms:
   - `hardening.controls.<fixed-toggle>` — checked against the toggle's boolean.
   - `hardening.controls.<free-label>` + `{hardening.baseline: [levels]}` — the
     label is a human name for a rule inside those baseline level(s) (e.g.
     `adcs_template_hardening` in `cis-l2`); only baseline membership triggers
     the conflict.

   Per `on_conflict`:
   - `fail` → raises, no manifest, non-zero exit.
   - `warn` → `reconciliation.warnings` lists every conflict; nothing changed.
   - `exclude-control` → if `hardening.intentional_gaps_auto` is true, fixed
     toggles flip to `false` in `defense_resolved` and baseline conflicts go to
     `reconciliation.excluded_controls` as ABSTRACT exclusions (the concrete
     `skip_rule` mapping is `defensive-controls`' job — don't invent rule IDs
     here). If `intentional_gaps_auto` is false, exclusions are NOT auto-derived;
     conflicts fall back to `warnings` with a note.

## Output contract

`generated/<lab.name>/lab-manifest.json` — gitignored, regenerated each run.
Downstream skills treat it as the source of truth for the resolved defense stack,
IP plan, and reconciliation; they don't re-read `defense.profile`/`neutralized_by`.

## Testing

`tests/test_manifest.py` asserts the resolution INVARIANTS on specs built in code
via `make_spec()` (`tests/_helpers.py`) — no committed example specs, no golden
files. It covers the IP plan (no collisions, in-subnet, deterministic), cost
(per-provider), and every reconciliation path: baseline-bundled exclusion
(`gpp-cpassword` ⟷ `cis-l1`, `exclude-control`), fixed-toggle exclusion
(`lsa_protection` vs `unconstrained-delegation`, `cis-l2`), `warn`, and `fail`
(returns None). When adding a vuln/control or changing the core, add or extend a
`make_spec()` case rather than an ad-hoc lab, and run `pytest tests/`.
