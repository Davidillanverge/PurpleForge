# PurpleForge — CLAUDE.md

PurpleForge is a specification-driven harness that turns a declarative `lab-spec.yml`
into complete automation (Terraform + Ansible + PowerShell) for deploying
Purple-Team-instrumented Active Directory labs on AWS or Azure. It wraps and reuses
mature upstream projects (`vendor/`: GOAD, Splunk Attack Range, BadBlood,
Vulnerable-AD, ansible-lockdown) rather than reinventing Windows/AD deployment or
hardening. `README.md` documents usage; `.claude/agents/README.md` describes the
agent system; `scripts/forge.py` holds the deterministic logic (compile,
reconcile, IP plan, cost, guardrail, destroy).

## Reglas invariantes

1. **Aislamiento por construcción.** Ningún host vulnerable tiene IP pública ni
   RDP/WinRM abierto a `0.0.0.0/0`. Todo acceso pasa SIEMPRE por un jump
   host WireGuard/bastión en la subred de gestión. Los NSG/SG son
   deny-by-default.
2. **Purple = ataque ∧ defensa.** Toda vulnerabilidad del catálogo DEBE declarar
   `mitigate` + `neutralized_by`. El laboratorio se despliega siempre junto con
   el stack defensivo (`defense:`) definido en el spec — nunca solo la parte
   ofensiva. (El harness cubre PREVENT/RESPOND: hardening + Defender AV +
   deception. No despliega SIEM ni telemetría — la ingeniería de detección es
   trabajo a más largo plazo, fuera del alcance actual.)
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

Este orden es determinista y sin IA: `forge.py generate` emite `deploy.sh`
(y `teardown.sh`) en `generated/<lab>/`, y `forge.py deploy` los ejecuta tras
la puerta `guardrail`. `site.yml` fija el orden hardening→vulns; `deploy.sh`
encadena secretos de infra (`ensure_secrets`: mintea admin/ansible si es un
share sin regenerar) → backend de estado → auto-sizing (SKU más barato sin
restricción, override `PF_VM_SIZE`) → `terraform apply` → túnel WireGuard →
`site.yml`. La validación es `forge.py validate --run` y el desmontaje a coste
cero es `forge.py teardown`.

## Convenciones del repositorio

- `specs/` es la única fuente de verdad editada a mano. Todo lo que cuelga de
  `generated/<lab>/` es el **resultado de usar el harness**, no parte de él:
  derivado, reproducible y regenerable desde el spec con `forge.py generate`.
  `generated/` está gitignored por completo — nunca se versiona; se regenera.
  Compartir un lab = compartir su `specs/<lab>.yml` (el determinismo garantiza
  que cualquiera reproduzca artefactos idénticos, ver regla invariante #5).
- `vendor/` son git submodules con versión/tag fijado. No se edita contenido de
  `vendor/` directamente; se envuelve desde `templates/` y las skills.
- Añadir una vulnerabilidad = añadir un `.yml` en `catalog/vulnerabilities/`
  con `detect`, `mitigate`, `neutralized_by` y `mitre_attack` válido — no
  requiere tocar código del generador.
- **Independencia de cuenta/suscripción.** La generación no hornea ningún
  `subscription_id`/`tenant`; la suscripción se resuelve en tiempo de
  despliegue (`ARM_SUBSCRIPTION_ID` o el login de `az`), el estado remoto usa
  una storage account acuñada por-desplegador, y región/SKU se sobreescriben
  con `PF_REGION`/`PF_VM_SIZE`/`PF_TFSTATE_RG` sin editar el spec. El mismo lab
  despliega en cualquier cuenta.
- **Secretos por ciclo de vida** (`ansible/inventory/group_vars/all/`): las
  contraseñas de los usuarios de población son deterministas a partir de
  `population.seed` (`population-secrets.yml`), así que `generate` las reproduce
  idénticas en cada regeneración — el deploy nunca las regenera. Las llaves de
  infra (admin de dominio + ansible WinRM) son por-desplegador y `deploy.sh`
  (`ensure_secrets`) las acuña al desplegar. Como `generated/` entero está
  gitignored, ningún secreto (`secrets.yml`, `secrets.auto.tfvars.json`,
  `lab-manifest.json`, `lab-report.md`) llega jamás a git.
