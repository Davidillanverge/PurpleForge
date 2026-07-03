# Prompt para Claude Code — Generar el harness "PurpleForge"

> Pega este prompt en Claude Code, en una carpeta vacía que será la raíz del repositorio. Ajusta el nombre del proyecto, el proveedor cloud por defecto y el stack defensivo si lo deseas.

---

## Rol y objetivo

Actúa como un ingeniero senior de detección/purple team y de infraestructura como código. Vas a construir **PurpleForge**, un *harness* dirigido por especificación que, a partir de un fichero declarativo `lab-spec.yml`, genera la automatización completa (Terraform + Ansible + PowerShell) para desplegar laboratorios de **Active Directory instrumentados para Purple Team** en **AWS o Azure**, incluyendo un **stack defensivo configurable** (SIEM, EDR, hardening) desplegado en las máquinas.

El harness NO reinventa el despliegue de Windows ni sus controles: **envuelve y reutiliza** proyectos maduros. Añádelos en `vendor/` como git submodules con versión fijada y estúdialos antes de escribir IaC propia:

**Ofensiva / IaC**
- **GOAD v3** (`github.com/Orange-Cyberdefense/GOAD`) — motor base: Terraform + Ansible con abstracción de proveedor (`aws`, `azure`) y presets. Motor de IaC + AD vulnerable primario.
- **Splunk Attack Range v5** (`github.com/splunk/attack_range`) — *referencia de diseño* para la capa de instrumentación/simulación (Atomic Red Team/PurpleSharp). No es un segundo motor de IaC.
- **BadBlood** (`github.com/davidprowe/BadBlood`) — poblado realista del dominio.
- **Vulnerable-AD** (`github.com/WazeHell/vulnerable-AD`) — primitivas PowerShell de inyección de vulnerabilidades.

**Defensa (stack "blue")**
- **SIEM:** Elastic Security (recomendado por defecto), Splunk, Wazuh, o Microsoft Sentinel (Azure).
- **EDR:** Microsoft Defender AV (integrado; línea base), Microsoft Defender for Endpoint (con licencia), **Elastic Defend**, **Wazuh agent**, **Velociraptor**, LimaCharlie.
- **Hardening (as code):** **ansible-lockdown** (`github.com/ansible-lockdown`, roles `Windows-2019-CIS`, `Windows-2022-CIS`, `Windows-2025-CIS`, `Windows-10-CIS`, `Windows-11-CIS`, y variantes `-STIG`), PowerSTIG (DSC), Microsoft Security Baselines.
- **NDR/deception (opcional):** Suricata/Zeek/Arkime; honey accounts, Canarytokens.

## Restricciones invariantes (críticas — codifícalas)

1. **Aislamiento por construcción:** ningún host vulnerable con IP pública ni RDP/WinRM abierto a `0.0.0.0/0`. Acceso SIEMPRE vía **jump host WireGuard/bastión** en subred de gestión. NSG/SG **deny-by-default**.
2. **Purple = ataque ∧ defensa:** toda vulnerabilidad DEBE traer `detect` + `mitigate` + `neutralized_by`. El laboratorio se despliega con el stack defensivo del spec.
3. **Reconciliación hardening ⟷ vulns:** antes de generar, cruza el hardening seleccionado con las vulnerabilidades y resuelve conflictos según `on_conflict`. Nunca apliques en silencio un control que anule una vuln seleccionada.
4. **Coste y ciclo de vida:** `auto_shutdown`, alerta de presupuesto, `terraform destroy` limpio, estado Terraform en **backend remoto** con locking (nunca local).
5. **Determinismo:** `seed` se propaga a todo; playbooks Ansible **idempotentes**.
6. **Uso autorizado:** laboratorios aislados y pruebas autorizadas; sin payloads ni infraestructura dirigida a terceros. Refléjalo en README y CLAUDE.md.

## Estructura a crear

```
purpleforge/
├── README.md   CLAUDE.md   .gitignore
├── .claude/
│   ├── settings.json
│   ├── commands/{new-lab,generate,deploy,validate,destroy}.md
│   └── skills/{lab-spec,network-topology,infra-aws,infra-azure,ad-topology,
│               ad-theming,vuln-injection,detection-lab,defensive-controls}/SKILL.md
├── specs/schema/lab-spec.schema.json
├── specs/examples/{medieval-2dom-azure.yml, corp-espionage-aws.yml}
├── catalog/
│   ├── vulnerabilities/{kerberoasting,asreproast,adcs-esc1,unconstrained-delegation,
│   │                    gpp-cpassword,dcsync-acl,passwords-in-description}.yml
│   ├── themes/{medieval-kingdom,corporate,space-station}.yml
│   ├── machine-profiles/{domain-controller,workstation,member-server,adcs,mssql}.yml
│   └── defense/
│       ├── profiles/{none,telemetry-only,realistic,hardened}.yml
│       ├── siem/{splunk,elastic,wazuh,sentinel}.yml
│       ├── edr/{defender-av,mde,elastic-defend,wazuh-agent,velociraptor,limacharlie}.yml
│       └── hardening/{cis-l1,cis-l2,stig,baseline-controls}.yml
├── templates/terraform/{aws,azure}/ · templates/ansible/{playbooks,roles,vulns,defense}/ · templates/powershell/
├── vendor/            # submodules: GOAD, attack_range, BadBlood, Vulnerable-AD, ansible-lockdown/Windows-*-CIS y -STIG
├── generated/         # salida por lab (gitignored)
└── scripts/{forge.py, preflight.sh, teardown.sh}
```

## El contrato del spec (`specs/schema/lab-spec.schema.json`)

Define un JSON Schema que valide un documento con estas secciones. Genera los dos ejemplos en `specs/examples/`.

```yaml
lab:            { name, theme, provider: [aws|azure], region, isolation: vpn-only, auto_shutdown, budget_alert_usd }
forest:         - { domain, netbios, functional_level, domain_controllers, trust?: { target, type } }
machines:       - { role: [domain-controller|member-server|workstation], os, domain, count, services?: [adcs|mssql|iis|sccm] }
population:     { users, density: [sparse|realistic|messy], seed }
vulnerabilities: [ <ids → catalog/vulnerabilities/*.yml> ]

defense:                                   # ← el stack defensivo desplegado en las máquinas
  profile: [none|telemetry-only|realistic|hardened]   # fija defaults; el resto son overrides
  siem:    { platform: [splunk|elastic|wazuh|sentinel|none], ship_sysmon, ship_wef, network_monitoring: [zeek|suricata|none] }
  edr:     - { product: [defender-av|mde|elastic-defend|wazuh-agent|velociraptor|limacharlie],
               mode: [enabled|detect|prevent], settings: {...}, targets: [all|<roles>] }
  hardening:
    baseline: [none|cis-l1|cis-l2|stig|baseline-controls]
    apply_to: [all|<roles>]
    controls: { laps, lsa_protection, credential_guard, smb_signing, ldap_signing,
                disable_llmnr_nbtns_mdns, protected_users_group: [...] }
    intentional_gaps_auto: true            # deriva exclusiones desde neutralized_by
  deception: { honey_accounts: <n>, canarytokens: [...] }

on_conflict:     [warn|exclude-control|fail]   # hardening ⟷ vulnerabilidades
detection_rules: auto
validation:     { bloodhound, pingcastle, atomic_red_team: [<TIDs>] }   # informe: PREVENIDO/DETECTADO/NO VISTO
```

## Responsabilidades de cada Skill

- **lab-spec** — Primera skill. Valida contra el schema, resuelve defaults (incluidos los del `profile` defensivo), expande `count`, asigna IPs, estima coste, avisa de expiración eval (180d), y ejecuta la **RECONCILIACIÓN** hardening⟷vulns (cruza `hardening` con `vulnerabilities` vía `neutralized_by`, aplica `on_conflict`). Emite `lab-manifest.json`.
- **network-topology** — VPC/VNet + subredes + jump host WireGuard/bastión + NSG/SG deny-by-default. Impone el aislamiento.
- **infra-aws / infra-azure** — Terraform fino reutilizando imágenes/sizing/WinRM de GOAD.
- **ad-topology** — DCs, forests/dominios, functional levels, trusts.
- **ad-theming** — OUs/grupos/usuarios temáticos sobre BadBlood, determinista vía `seed`.
- **vuln-injection** — Catálogo → playbooks (reutiliza Vulnerable-AD); registra rutas previstas; respeta las exclusiones de la reconciliación.
- **detection-lab** (VER) — SIEM elegido + Sysmon + WEF + NDR opcional + reglas base por vuln.
- **defensive-controls** (PREVENIR/RESPONDER) — Despliega agentes EDR del spec; aplica baseline de hardening vía ansible-lockdown (nivel + `skip_rule` según reconciliación); controles concretos (LAPS, LSA protection, SMB/LDAP signing, disable LLMNR/NBT-NS/mDNS, Protected Users); siembra deception.
- **purple-validation** — SharpHound→BloodHound (rutas) + PingCastle (postura) + Atomic clasificando cada técnica como **PREVENIDA/DETECTADA/NO VISTA** → `lab-report.md`.

## Formato del catálogo de vulnerabilidades (genera 7 semilla)

```yaml
id: <slug>
name: "..."
severity: [low|medium|high|critical]
attack: { mitre_attack: [Txxxx], requires_services: [...], intended_path: "..." }
inject: { type: [ansible|powershell], playbook|primitive: "...", params: {...} }   # reutiliza Vulnerable-AD
detect: { data_source: "...", signal: "...", siem_rule: "templates/detection/{siem}/<id>" }
neutralized_by:                     # ← controles de hardening que ROMPERÍAN la vuln (para la reconciliación)
  - hardening.controls.<control>
  - hardening.baseline: [cis-l2|stig]
mitigate: { summary: "..." }
validate: { bloodhound_edge?: "...", atomic?: "Txxxx" }
```

## Orden de despliegue (codifícalo en /deploy)

infra → topología AD → poblado/temática → **baseline de hardening** → **inyección selectiva de vulns (gaps)** → **EDR + telemetría** → **SNAPSHOT del estado limpio** (antes de cualquier ataque).

## Ejemplo trabajado obligatorio

Genera **end-to-end** (spec → artefactos, `--dry-run`, sin desplegar) `specs/examples/medieval-2dom-azure.yml`:
- 2 dominios (`kingdom.local` + `vassals.kingdom.local`, trust parent-child), 1 DC cada uno.
- 1 member-server con `adcs`+`mssql`; 2 workstations Win10. Tema `medieval-kingdom`, 300 usuarios, `seed: 1337`.
- Vulns: `kerberoasting`, `adcs-esc1`, `gpp-cpassword`, `dcsync-acl`.
- **defense.profile: realistic** con `siem.platform: elastic` (+ Sysmon + WEF + Zeek), `edr: [defender-av (asr audit), elastic-defend (prevent en DC+member-server)]`, `hardening.baseline: cis-l1` con `intentional_gaps_auto: true`, `deception.honey_accounts: 3`.
- `on_conflict: exclude-control`. Validación: BloodHound + PingCastle + Atomic `[T1558.003, T1552.006, T1649]`.

Deja en `generated/medieval-2dom-azure/`: Terraform de Azure (red aislada + VMs), inventario, playbooks Ansible (topología, theming, **hardening CIS L1 con las exclusiones derivadas**, inyección de las 4 vulns, **EDR + Elastic + Sysmon/WEF**, deception), y `lab-manifest.json` con las rutas previstas **y la lista de reglas de hardening excluidas y por qué**. Muestra el `terraform plan`.

## Orden de trabajo y criterios de aceptación

Trabaja por fases; para tras la Fase 1 para revisión.
1. Andamiaje: estructura, `.gitignore`, schema (con `defense:`), `CLAUDE.md` (reglas invariantes), skill `lab-spec` con reconciliación, 2 specs de ejemplo, submodules en `vendor/`.
2. Un dominio, un cloud: `network-topology` + `infra-azure` + `ad-topology` → `terraform plan` de 1 DC aislado solo-VPN.
3. Poblado + temática: `ad-theming` + BadBlood + tema medieval.
4. Vulnerabilidades: `vuln-injection` + los 7 ficheros de catálogo (con `neutralized_by`).
5. Detección (VER): `detection-lab` (Elastic o Splunk + Sysmon + WEF).
6. Controles (PREVENIR): `defensive-controls` (EDR + ansible-lockdown CIS L1 + controles + deception). Ejercita la reconciliación.
7. Validación: `purple-validation` con matriz PREVENIDO/DETECTADO/NO VISTO.
8. Multi-dominio + AWS: trusts, `infra-aws`, y el ejemplo trabajado completo.

**Criterios de aceptación:**
- `lab-spec` rechaza specs inválidos (colisión de nombres/IPs, vuln sin prerequisito).
- Ninguna plantilla de red abre RDP/WinRM a Internet; todo acceso pasa por el bastión/WireGuard.
- Toda vuln del catálogo tiene `detect`, `mitigate`, `neutralized_by` y un `mitre_attack` válido.
- **La reconciliación funciona:** dada una vuln + un baseline/control que la neutraliza, con `on_conflict: exclude-control` el generado excluye la regla concreta (`skip_rule`) y lo registra en `lab-manifest.json`; con `fail`, se detiene; con `warn`, avisa.
- El orden de `/deploy` aplica hardening ANTES de inyectar las vulns y toma snapshot ANTES de atacar.
- `/generate --dry-run` del ejemplo medieval produce `terraform plan` sin errores y un `lab-manifest.json` con rutas previstas y exclusiones de hardening.
- README explica el flujo `new-lab → generate → deploy → validate → destroy`, el bloque `defense:`, los perfiles, y la postura de uso autorizado/aislado.

Empieza ahora por la Fase 1. Antes de escribir Terraform/Ansible propio, inspecciona `vendor/GOAD` y `vendor/ansible-lockdown` y reutiliza lo que puedas. Explica brevemente tus decisiones a medida que avanzas.
