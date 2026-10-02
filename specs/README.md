# `specs/`

Hand-edited lab definitions — the only source of truth PurpleForge consumes. A
spec (`<lab>.yml`) compiles deterministically into `generated/<lab>/` via `forge
generate`. Your own `specs/*.yml` are gitignored (they are harness input/output,
not source); the JSON Schema (`specs/schema/`), the two committed smoke-test
specs, and the example files here are versioned.

## Authoring a spec

Three fronts produce a `specs/<lab>.yml`, all feeding the same pipeline:

```
natural language ──/new-lab──────────▶ specs/<lab>.yml ─┐
you, by hand (copy an example)        ─────────────────▶ ├─ forge lab-spec → generate → deploy
exercise layer  ──forge from-exercise──▶ specs/<lab>.yml ─┘
```

## `forge from-exercise` — author a spec from a BAS exercise

The inverse of `/new-lab`: instead of describing a lab, you hand it the ATT&CK
technique list a Breach & Attack Simulation exercise produced, and it writes a
spec whose intentional gaps are exactly the catalog vulnerabilities that
reproduce those techniques — so the lab is provably vulnerable to the attack that
was designed first.

### The only required input: a technique list (JSON)

An **ATT&CK Navigator layer**, the portable artifact a BAS exercise emits — but
you can write one by hand with zero other tooling. Only the technique IDs matter
(format `T####` or `T####.###`); everything else is ignored. Three shapes are
accepted:

```jsonc
// 1) full ATT&CK Navigator layer (see example-exercise.json)
{ "name": "...", "domain": "enterprise-attack",
  "techniques": [ { "techniqueID": "T1558.003" }, { "techniqueID": "T1649" } ] }

// 2) a techniques array of bare ids
{ "techniques": ["T1558.003", "T1649", "T1003.006"] }

// 3) a top-level list of ids
["T1558.003", "T1649", "T1003.006"]
```

That file is the **only** thing that comes from the exercise. The infrastructure
envelope (provider, theme, region, population size, topology) has no place in a
technique list, so it comes from defaults or CLI flags.

### Run it

```bash
# uses this folder's example; writes specs/example-exercise.yml
forge from-exercise specs/example-exercise.json

# with overrides (anything a technique list can't carry)
forge from-exercise specs/example-exercise.json \
    --name apt-demo --provider proxmox --theme medieval-kingdom \
    --region eastus --domain corp.local --users 200 --seed 1337

# match techniques verbatim only (suppress the parent<->sub-technique roll-up)
forge from-exercise specs/example-exercise.json --exact-only
```

(`PYTHONPATH=scripts python3 -m forge from-exercise ...` is the same entry point
without the console-script install.)

It prints which vulns were selected (exact vs `approx` roll-up) and which
techniques had **no catalog coverage** (a runtime-only TTP the red team performs,
or a precondition the catalog can't build yet), then writes the spec. A technique
maps only if its ID matches a catalog vuln's `attack.mitre_attack`.

### Flags

| Flag | Default | What it sets |
|---|---|---|
| `--name` | from the layer's `name`, else `exercise-lab` | `lab.name` + output filename |
| `--provider` | `azure` | `azure` \| `proxmox` \| `aws` |
| `--theme` | `corporate` | `catalog/themes/<theme>` |
| `--region` | `eastus` | cloud region |
| `--domain` | `corp.local` | the single forest domain |
| `--users` / `--seed` / `--density` | `25` / `1337` / `realistic` | population |
| `--budget` | `30` | `budget_alert_usd` |
| `--auto-shutdown` | `20:00 Europe/Madrid` | `lab.auto_shutdown` |
| `--chain` | `independent` | `attack_chain.mode` (`independent` \| `ctf`) |
| `--exact-only` | off | verbatim technique match only |
| `--out` / `--force` | `specs/<name>.yml` | output path / overwrite |

### Which techniques map? (the catalog's coverage)

Dump the reverse index (technique ID → catalog vulns) straight from the catalog —
it always reflects the current `catalog/vulnerabilities/`:

```bash
PYTHONPATH=scripts python3 -c "import forge; \
  [print(f'{t:12} -> {\", \".join(v)}') \
   for t, v in forge.build_technique_index(forge.load_vuln_catalog()).items()]"
```

A technique not in that list is reported as uncovered. If it's a real
environmental precondition you want in the lab, author a vuln for it (the
`catalog-author` agent) and re-run — the index extends for free.

### Next steps (unchanged pipeline)

```bash
forge lab-spec  specs/<name>.yml   # validate + reconcile -> lab-manifest.json
forge generate  specs/<name>.yml   # render Terraform + Ansible
forge guardrail specs/<name>.yml   # invariant gate before spend
forge deploy    specs/<name>.yml   # build the live lab
```

The reconciliation in `lab-spec` is the payoff: `intentional_gaps_auto` +
`on_conflict: exclude-control` (both set by `from-exercise`) force each selected
vuln's `neutralized_by` gap to stay open even under the defensive baseline — so
the manifest *proves* the lab stays vulnerable to the exercise's techniques.

## Files here

| File | What |
|---|---|
| `schema/lab-spec.schema.json` | the spec contract (JSON Schema, versioned) |
| `example-exercise.json` | example technique list for `forge from-exercise` |
| `winrm-validate-lab.yml`, `mssql-weak-sa-lab.yml` | committed smoke-test specs |
