# PurpleForge — CLAUDE.md

PurpleForge is a specification-driven harness that turns a declarative `lab-spec.yml`
into complete automation (Terraform + Ansible + PowerShell) for deploying
Purple-Team-instrumented Active Directory labs on AWS or Azure. It wraps and reuses
mature upstream projects (`vendor/`: GOAD, Splunk Attack Range, BadBlood,
Vulnerable-AD, ansible-lockdown) rather than reinventing Windows/AD deployment or
hardening. See `DISENO-purpleforge.md` for the full design and `PROMPT-claude-code.md`
for the build brief this repo was generated from.

## Reglas invariantes

1. **Aislamiento por construcción.** Ningún host vulnerable tiene IP pública ni
   RDP/WinRM abierto a `0.0.0.0/0`. Todo acceso pasa SIEMPRE por un jump
   host WireGuard/bastión en la subred de gestión. Los NSG/SG son
   deny-by-default.
2. **Purple = ataque ∧ defensa.** Toda vulnerabilidad del catálogo DEBE declarar
   `detect` + `mitigate` + `neutralized_by`. El laboratorio se despliega siempre
   junto con el stack defensivo (`defense:`) definido en el spec — nunca solo la
   parte ofensiva.
3. **Reconciliación hardening ⟷ vulnerabilidades.** Antes de generar artefactos,
   el hardening seleccionado se cruza con las vulnerabilidades seleccionadas
   (vía `neutralized_by`) y los conflictos se resuelven según `on_conflict`
   (`warn` | `exclude-control` | `fail`). Nunca se aplica en silencio un control
   que anule una vulnerabilidad seleccionada por el spec.
4. **Coste y ciclo de vida como código.** Todo despliegue lleva `auto_shutdown`
   y `budget_alert_usd`. `terraform destroy` debe dejar coste cero. El estado
   Terraform vive en backend remoto con locking (S3+DynamoDB / Azure Storage),
   nunca en local.
5. **Determinismo.** `population.seed` se propaga a todo poblado/theming.
   Los playbooks de Ansible son idempotentes (ejecutables repetidamente sin
   efectos secundarios).
6. **Uso autorizado.** PurpleForge genera laboratorios aislados para pruebas
   autorizadas (formación, purple teaming, investigación defensiva). No genera
   payloads, infraestructura ni automatización dirigida a sistemas de terceros
   sin autorización explícita.

## Orden de despliegue (`/deploy`)

```
infra → topología AD → poblado/temática → baseline de hardening →
inyección selectiva de vulns (gaps) → EDR + telemetría →
SNAPSHOT del estado limpio (antes de cualquier ataque)
```

El hardening se aplica ANTES de inyectar las vulnerabilidades intencionadas
(los "gaps" ya han sido reconciliados en el spec), y el snapshot del estado
limpio se toma ANTES de que `/validate` dispare cualquier técnica de ataque.

## Convenciones del repositorio

- `specs/` es la única fuente de verdad editada a mano; todo lo que cuelga de
  `generated/<lab>/` es derivado y reproducible (regenerable desde el spec) —
  no se edita a mano y no se versiona.
- `vendor/` son git submodules con versión/tag fijado. No se edita contenido de
  `vendor/` directamente; se envuelve desde `templates/` y las skills.
- Añadir una vulnerabilidad = añadir un `.yml` en `catalog/vulnerabilities/`
  con `detect`, `mitigate`, `neutralized_by` y `mitre_attack` válido — no
  requiere tocar código del generador.
- Los secretos generados (credenciales, `lab-manifest.json`) nunca se
  commitean; ver `.gitignore`.
