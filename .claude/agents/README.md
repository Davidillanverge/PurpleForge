# PurpleForge — sistema de agentes

El **hilo principal** (comandos `/new-lab`, `/deploy`, `/validate`, `/destroy`)
orquesta y delega toda la lógica determinista a `scripts/forge.py` — nunca la
reimplementa (lo prohíbe `CLAUDE.md`). Las *skills* de `.claude/skills/` son el
cuerpo de conocimiento que los agentes envuelven.

Un agente solo se justifica si **aísla contexto ruidoso** (p. ej. `terraform
apply`) o **posee credenciales cloud**. El diseño completo es edición de UN
fichero `specs/<lab>.yml`, así que va en un solo agente. Las puertas
deterministas (compilar, guardrail) las corre el hilo principal.

## Roster (4 agentes, todos sonnet)

| Agente | Fase | Escribe |
|---|---|---|
| `lab-designer` | diseño: infra+topología, población/temática, vulns + cadena | `specs/<lab>.yml`, `catalog/themes/*` |
| `deploy-operator` | deploy + teardown (único con credenciales cloud) | `generated/**`, cloud |
| `purple-validator` | validación (aplicada+explotable) + `lab-report.md` | `generated/<lab>/*` |
| `catalog-author` | autoría de catálogo (fuera del ciclo) | `catalog/**` |

## Qué corre el hilo principal (sin agente)

- **Compilar**: `forge.py lab-spec specs/<lab>.yml` → único productor de
  `lab-manifest.json` (valida + reconcilia + IPs + coste).
- **Guardrail**: `forge.py guardrail specs/<lab>.yml` → PASS/FAIL de las
  invariantes #1–#4; imprime #6 (uso autorizado) como REVIEW para juicio
  humano. FAIL ⇒ el hilo principal NO despliega.

## Contratos

1. El diseño **solo escribe `specs/<lab>.yml`**. No toca `generated/`.
2. `forge.py lab-spec` es el **único** productor de `lab-manifest.json`; todo lo
   demás lo consume, nadie relee el YAML crudo.
3. La ejecución **solo actúa desde `generated/` + manifest**.
4. El handoff es **por fichero**, no por contexto pegado a mano.

## Flujo

```
/new-lab "<descripción NL>"
  └─ lab-designer      → converge specs/<lab>.yml
  └─ forge.py lab-spec → lab-manifest.json
  └─ forge.py guardrail→ PASS/FAIL (+ REVIEW #6)
  ═══ PUERTA HUMANA: revisar spec + coste + reconciliación, aprobar ═══
/deploy    → deploy-operator  (hardening → vulns → EDR → snapshot limpio)
/validate  → purple-validator (por vuln: aplicada + explotable → report)
/destroy   → deploy-operator  (forge.py destroy → coste cero)
```

`catalog-author` corre **fuera** del ciclo: produce contenido reutilizable, no
despliega.

## Seguridad

- Lo peligroso/determinista vive en `forge.py`, no en prompts (reconciliación,
  IPs, coste, guardrail, destroy con verificación de coste cero).
- **Guardrail obligatorio** antes de `deploy`.
- Solo `deploy-operator` y `purple-validator` tocan infra viva; `lab-designer`
  y `catalog-author` no tienen credenciales.
- Puerta humana antes de gastar y antes de destruir. La aprobación no se hereda
  entre labs.

## MCP

`mcp/azure.json` (symlink desde `.mcp.json`) añade el Azure MCP Server:
`lab-designer` verifica `vm_size`/región/quota antes de escribir el spec;
`deploy-operator` comprueba quota antes de gastar y coste-cero tras `destroy`.
Ver `mcp/README.md`.

## Aún sin construir

Ingeniería de detección (SIEM + telemetría + Sigma) e `infra-aws` (hoy Azure +
Proxmox). El harness cubre PREVENT/RESPOND; la validación NO es una matriz de
detección.
