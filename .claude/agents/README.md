# PurpleForge — sistema de agentes

Este directorio implementa PurpleForge como un **sistema de agentes** montado
sobre lo que ya existe (spec-driven, catálogo, `scripts/forge.py`). No sustituye
el modelo spec-driven: lo envuelve. Las *skills* de `.claude/skills/` siguen
siendo el cuerpo de conocimiento; cada agente **posee una fase** del ciclo de
vida, con su propia ventana de contexto y sus herramientas, y **delega la lógica
determinista a `forge.py`** — nunca la reimplementa (lo prohíbe `CLAUDE.md`).

## Por qué agentes y no solo skills

- **Aislamiento de contexto**: los cientos de líneas de output de `terraform
  apply` no contaminan la ventana del diseñador de topología.
- **Paralelismo**: topología, población y diseño ofensivo son independientes y
  editan bloques disjuntos del mismo `specs/<lab>.yml`.
- **Puertas humanas claras**: hay un punto único, obligatorio, antes de gastar
  dinero (deploy) y antes de destruir.

## Roster

| Agente | Fase | Escribe | Modelo |
|---|---|---|---|
| `forge-orchestrator` | conductor (hilo principal) | — | opus |
| `topology-architect` | diseño: infra + topología AD | `specs/<lab>.yml` | opus |
| `domain-designer` | diseño: población/temática | `specs/<lab>.yml`, `catalog/themes/*` | sonnet |
| `redteam-designer` | diseño: selección de vulns + cadena de ataque | `specs/<lab>.yml` | opus |
| `catalog-author` | autoría de catálogo (fuera del ciclo) | `catalog/**` | opus |
| `spec-compiler` | puerta determinista | `generated/<lab>/lab-manifest.json` | haiku |
| `policy-guardrail` | puerta de invariantes | reporte PASS/FAIL | sonnet |
| `deploy-operator` | ejecución: deploy + teardown | `generated/**`, cloud | sonnet |
| `purple-validator` | ejecución: validación | resultados | sonnet |
| `report-writer` | ejecución: reporte | `generated/<lab>/lab-report.md` | sonnet |

Mapa a las 8 funcionalidades pedidas: (1) nuevas vulns/hardening/configs →
`catalog-author`; (2) topología → `topology-architect`; (3) usuarios/grupos/OUs
→ `domain-designer` (+ `scripts/population.py`, determinista); (4) selección de
vulns → `redteam-designer`; (5) cadenas de ataque → `redteam-designer`; (6)
despliegue → `deploy-operator`; (7) validación → `purple-validator`; (8) reporte
→ `report-writer`.

> **Nota de consolidación**: selección (4) y cadena (5) están fusionadas en
> `redteam-designer` porque una cadena necesita objetos de población concretos y
> compartir contexto reduce handoffs. Si prefieres separarlos, divide este
> agente en `vuln-selector` + `attack-chain-designer`.

## Contratos y estado compartido

1. Los agentes de **diseño solo escriben `specs/<lab>.yml`** (fuente de verdad
   editable y revisable por humano). No tocan `generated/`.
2. **`spec-compiler` es el único** que produce `lab-manifest.json`. Todos los
   demás lo consumen; nadie relee el YAML crudo.
3. Los agentes de **ejecución solo actúan desde `generated/` + manifest**.
4. El handoff es **por fichero**, no por contexto pasado a mano.

## Flujo del ciclo de vida

```
/new-lab "<descripción NL>"
  └─ orchestrator → DISEÑO en paralelo:
        topology-architect ─┐
        domain-designer     ─┤→ convergen en specs/<lab>.yml
        redteam-designer    ─┘  (selección solo si el user no fijó vulns)
  └─ spec-compiler   → lab-manifest.json   (valida + reconcilia + IPs + coste)
  └─ policy-guardrail → PASS/FAIL invariantes
  ═══ PUERTA HUMANA: revisar spec + coste + reconciliación, aprobar ═══
/deploy    → deploy-operator  (hardening → vulns → EDR → SNAPSHOT limpio)
/validate  → purple-validator → report-writer  (matriz PREVENIDO/DETECTADO/NO VISTO)
/destroy   → deploy-operator (forge.py destroy → coste cero)
```

`catalog-author` corre **fuera** de este ciclo: produce contenido reutilizable
("añade una vuln ESC8"), no despliega nada.

## Dónde vive la seguridad

- La lógica peligrosa/determinista está en `forge.py`, no en prompts
  (reconciliación, plan de IPs, coste, `destroy` con verificación de coste cero).
- `policy-guardrail` es puerta **obligatoria** antes de `deploy`; el orchestrator
  no invoca a `deploy-operator` si falla.
- Herramientas mínimas por agente: solo `deploy-operator` y `purple-validator`
  tienen credenciales cloud y terraform/ansible; los de diseño no.
- Puerta humana antes de gastar y antes de destruir. La aprobación no se hereda
  entre labs.

## Estado de implementación

Ya existen (skills + `forge.py`): lab-spec, network-topology, infra-azure,
ad-topology, ad-theming, vuln-injection, defensive-controls; y en `forge.py`:
`lab-spec`, `generate`, `destroy`, `ad-inventory`.

La skill `purple-validation` ya existe, con su parte determinista en
`forge.py validate` (matriz PREVENIDO/DETECTADO/NO VISTO *predicha* desde el
manifest + checklist de Atomic/BloodHound a confirmar en vivo). La fase en vivo
(SharpHound/BloodHound, PingCastle, Atomic sobre el túnel) la ejecuta el agente
siguiendo la skill; aún no hay subcomando que la orqueste end-to-end.

Siguen sin existir: `detection-lab` (SIEM+telemetría) e `infra-aws` (solo hay
Azure). Los agentes ya apuntan a ese flujo; construir esas piezas es el siguiente
paso.
