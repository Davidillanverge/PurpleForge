# PurpleForge — sistema de agentes

PurpleForge se orquesta desde el **hilo principal** (los comandos `/new-lab`,
`/deploy`, `/validate`, `/destroy`), que enruta el trabajo a un roster mínimo de
agentes especialistas y **delega toda la lógica determinista a
`scripts/forge.py`** — nunca la reimplementa (lo prohíbe `CLAUDE.md`). Las
*skills* de `.claude/skills/` son el cuerpo de conocimiento que los agentes
envuelven.

## Por qué tan pocos agentes

Un agente solo se justifica cuando **aísla contexto ruidoso** (p. ej. cientos de
líneas de `terraform apply`) o cuando **posee credenciales cloud**. El diseño
(topología + población + ofensiva) es edición coordinada de UN fichero
`specs/<lab>.yml`, así que va en un solo agente en vez de tres arrancando en
frío. Las puertas deterministas (compilar, invariantes) son comandos de
`forge.py` que corre el hilo principal — no necesitan agente.

## Roster (4 agentes)

| Agente | Fase | Escribe | Modelo |
|---|---|---|---|
| `lab-designer` | diseño completo: infra+topología, población/temática, selección de vulns + cadena | `specs/<lab>.yml`, `catalog/themes/*` | sonnet |
| `deploy-operator` | ejecución: deploy + teardown (único con credenciales cloud) | `generated/**`, cloud | sonnet |
| `purple-validator` | ejecución: validación (aplicada+explotable) + `lab-report.md` | `generated/<lab>/*` | sonnet |
| `catalog-author` | autoría de catálogo (fuera del ciclo) | `catalog/**` | sonnet |

Las 8 funcionalidades pedidas: (1) nuevas vulns/hardening/configs →
`catalog-author`; (2) topología, (3) usuarios/grupos/OUs, (4) selección de vulns,
(5) cadenas de ataque → **`lab-designer`** (+ `scripts/population.py`,
determinista); (6) despliegue → `deploy-operator`; (7) validación y (8) reporte →
**`purple-validator`**.

## Qué corre el hilo principal (sin agente)

- **Compilar**: `python3 scripts/forge.py lab-spec specs/<lab>.yml` → el único
  productor de `generated/<lab>/lab-manifest.json` (valida + reconcilia + IPs +
  coste).
- **Guardrail**: `python3 scripts/forge.py guardrail specs/<lab>.yml` → PASS/FAIL
  determinista de las reglas invariantes (#1 aislamiento, #2 acoplamiento purple,
  #3 reconciliación, #4 coste/estado). El #6 (uso autorizado) lo imprime como
  REVIEW para el juicio humano/LLM. Si sale FAIL, el hilo principal NO despliega.

## Contratos y estado compartido

1. El diseño **solo escribe `specs/<lab>.yml`** (fuente de verdad editable y
   revisable por humano). No toca `generated/`.
2. `forge.py lab-spec` es el **único** que produce `lab-manifest.json`; todo lo
   demás lo consume, nadie relee el YAML crudo.
3. La ejecución **solo actúa desde `generated/` + manifest**.
4. El handoff es **por fichero**, no por contexto pegado a mano.

## Flujo del ciclo de vida

```
/new-lab "<descripción NL>"
  └─ hilo principal → lab-designer  → converge specs/<lab>.yml
  └─ forge.py lab-spec              → lab-manifest.json (valida + reconcilia + IPs + coste)
  └─ forge.py guardrail             → PASS/FAIL invariantes (+ REVIEW #6)
  ═══ PUERTA HUMANA: revisar spec + coste + reconciliación, aprobar ═══
/deploy    → deploy-operator  (hardening → vulns → EDR → SNAPSHOT limpio)
/validate  → purple-validator (por vuln: aplicada + explotable → validation-report.md → lab-report.md)
/destroy   → deploy-operator  (forge.py destroy → coste cero)
```

`catalog-author` corre **fuera** de este ciclo: produce contenido reutilizable
("añade una vuln ESC8"), no despliega nada.

## Dónde vive la seguridad

- La lógica peligrosa/determinista está en `forge.py`, no en prompts
  (reconciliación, plan de IPs, coste, `guardrail`, `destroy` con verificación de
  coste cero).
- El **guardrail es obligatorio** antes de `deploy`; el hilo principal no invoca
  a `deploy-operator` si `forge.py guardrail` sale FAIL.
- Herramientas mínimas por agente: solo `deploy-operator` y `purple-validator`
  tocan la infra viva; `lab-designer` y `catalog-author` no tienen credenciales.
- Puerta humana antes de gastar y antes de destruir. La aprobación no se hereda
  entre labs.

## MCP

`mcp/azure.json` (symlink desde `.mcp.json`) añade el Azure MCP Server oficial:
`lab-designer` verifica `vm_size`/región/quota antes de escribir el spec y
`deploy-operator` comprueba quota antes de gastar y coste-cero tras `destroy`.
Ver `mcp/README.md`.

## Aún sin construir

`detection-lab` (SIEM+telemetría) e `infra-aws` (hoy solo Azure). La validación
NO es una matriz de detección — eso sería `detection-lab`.
