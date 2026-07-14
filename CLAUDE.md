# PurpleForge — CLAUDE.md

PurpleForge compila un `lab-spec.yml` declarativo en automatización completa
(Terraform + Ansible + PowerShell) para desplegar laboratorios de Active
Directory instrumentados para Purple Team, en **Azure o Proxmox** (AWS en
roadmap). Envuelve proyectos upstream fijados en `vendor/` (GOAD,
Vulnerable-AD, ansible-lockdown; BadBlood queda fijado pero ya sin usar) en
vez de reinventar despliegue/hardening de Windows.

- `README.md` — uso.
- `.claude/agents/README.md` — sistema de agentes.
- `scripts/forge/` — lógica determinista (compilar, reconciliar, plan de
  IPs, coste, guardrail, destroy), un paquete Python: `core` (constantes/
  utilidades), `catalog` (loaders), `planning` (validación/resolución/planes),
  `render` (planes→artefactos), `lifecycle` (deploy/teardown/destroy),
  `validate` (validación en vivo + ad-inventory) y `__init__` (CLI). **Nunca la
  reimplementes en prompts.**

## Reglas invariantes

1. **Aislamiento.** Ningún host vulnerable tiene IP pública ni RDP/WinRM a
   `0.0.0.0/0`. Todo acceso pasa por el bastión WireGuard en la subred de
   gestión. NSG/SG deny-by-default.
2. **Purple = ataque ∧ defensa.** Toda vuln del catálogo declara `mitigate` +
   `neutralized_by`. El lab se despliega siempre con su stack `defense:`, nunca
   solo la parte ofensiva. Alcance: PREVENT/RESPOND (hardening + Defender AV +
   deception). Sin SIEM ni telemetría — la ingeniería de detección queda fuera.
3. **Reconciliación hardening ⟷ vulns.** Antes de generar, el hardening se
   cruza con las vulns (vía `neutralized_by`) y los conflictos se resuelven
   según `on_conflict` (`warn` | `exclude-control` | `fail`). Nunca se aplica en
   silencio un control que anule una vuln seleccionada.
4. **Coste y ciclo de vida como código.** Todo despliegue lleva `auto_shutdown`
   y `budget_alert_usd`. `terraform destroy` deja coste cero. Estado Terraform
   en backend remoto con locking (Azure Storage; local en Proxmox, relajación
   documentada), nunca en local para Azure.
5. **Determinismo.** `population.seed` se propaga a todo poblado/theming.
   Playbooks idempotentes.
6. **Uso autorizado.** Solo labs aislados para pruebas autorizadas. No genera
   nada dirigido a terceros sin autorización.

## Orden de despliegue (`/deploy`)

```
infra → topología AD → poblado/temática → hardening →
inyección de vulns (gaps) → EDR → SNAPSHOT del estado limpio
```

Hardening ANTES de inyectar vulns (los gaps ya reconciliados en el spec);
snapshot limpio ANTES de que `/validate` dispare cualquier ataque.

Determinista y sin IA: `forge generate` emite `deploy.sh`/`teardown.sh` en
`generated/<lab>/`, y `forge deploy` los ejecuta tras la puerta `guardrail`.
`site.yml` fija el orden hardening→vulns. `deploy.sh` encadena: `ensure_secrets`
(mintea admin/ansible) → backend de estado → auto-sizing (SKU más barato,
override `PF_VM_SIZE`) → `terraform apply` → túnel WireGuard → `site.yml`.
Validación: `forge validate --run`. Desmontaje: `forge teardown`.

> Nota: el snapshot de estado limpio aún no está implementado (necesita un
> recurso de snapshot azurerm o equivalente Ansible). El orden es el mandato;
> el snapshot es un gap conocido — no asumas "reset entre ejercicios".

## Convenciones del repositorio

- **`specs/`** es la única fuente de verdad editada a mano. `generated/<lab>/`
  es el resultado del harness: derivado, gitignored, regenerable con `forge
  generate`. Compartir un lab = compartir su `specs/<lab>.yml` (el determinismo
  garantiza artefactos idénticos, invariante #5).
- **`vendor/`** son submodules con versión fijada. No se editan; se envuelven
  desde `templates/` y las skills.
- **Añadir una vuln** = un `.yml` en `catalog/vulnerabilities/` con `mitigate`,
  `neutralized_by` y `mitre_attack` válido (sin bloque `detect`: la detección
  queda fuera de alcance). Debe validar contra
  `catalog/schema/vulnerability.schema.json`. Sin tocar el generador.
- **Independencia de cuenta.** La generación no hornea `subscription_id`/`tenant`;
  se resuelven al desplegar (`ARM_SUBSCRIPTION_ID` o login `az`). Estado remoto
  en storage account por-desplegador; región/SKU vía `PF_REGION`/`PF_VM_SIZE`/
  `PF_TFSTATE_RG` sin editar el spec.
- **Secretos por ciclo de vida** (`ansible/inventory/group_vars/all/`): las
  passwords de población son deterministas del seed (`population-secrets.yml`),
  así que `generate` las reproduce idénticas. Las llaves de infra (admin de
  dominio + ansible WinRM) son por-desplegador, minteadas por `deploy.sh`
  (`ensure_secrets`). Como `generated/` está gitignored, ningún secreto llega a
  git.
