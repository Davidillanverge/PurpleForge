# PurpleForge — Diseño del harness generador de laboratorios de Active Directory para Purple Team

> Generador dirigido por IA (Claude Code) que, a partir de una **especificación declarativa** (dominios, máquinas, temática, catálogo de vulnerabilidades **y stack defensivo**), produce la **automatización completa** (Terraform + Ansible + PowerShell) para desplegar un laboratorio de Active Directory instrumentado en **AWS o Azure**, con las contrapartes defensivas (SIEM, EDR, hardening, detección + mitigación) que exige un entorno de Purple Team.

El nombre `purpleforge` es una sugerencia; sustitúyelo libremente.

---

## 1. Filosofía de diseño

Cinco principios gobiernan todo el proyecto:

1. **Reutilizar, no reinventar.** Desplegar Windows en la nube y sus controles (imágenes/WinRM, promoción de DC, trusts, agentes EDR, baselines CIS/STIG) es un pantano bien resuelto por proyectos maduros. El harness *genera entradas y capas finas* sobre esos proyectos en lugar de reescribir su Terraform/Ansible desde cero.
2. **Dirigido por especificación (spec-driven).** Una única `lab-spec.yml` es la fuente de verdad. Todo lo demás (Terraform, inventarios, scripts, informes) es *derivado y reproducible*. Cambiar el laboratorio = editar el spec y regenerar.
3. **Purple = ataque ∧ defensa, acopladas.** Cada vulnerabilidad viaja unida a su **detección** y su **mitigación**; y el laboratorio se despliega con un **stack defensivo configurable** (SIEM, EDR, hardening). Un laboratorio sin telemetría ni controles no es Purple Team.
4. **Ofensiva y defensa reconciliadas.** El hardening y las vulnerabilidades intencionadas *pueden entrar en conflicto*. El harness resuelve ese conflicto de forma explícita: entorno mayormente endurecido con *gaps* deliberados y específicos — el escenario más realista y valioso.
5. **Seguro por construcción.** Aislamiento de red (solo VPN), egress denegado por defecto, teardown y auto-apagado, y control de coste como *código*.

---

## 2. Proyectos base sobre los que se apoya

El harness es una capa de orquestación y generación. Estos son los proyectos "conocidos y mejores" que envuelve:

### Ofensiva e infraestructura
| Capa | Proyecto | Qué aporta |
|---|---|---|
| Motor AD vulnerable + IaC multi-cloud | **GOAD v3** (Orange Cyberdefense) | Terraform + Ansible con abstracción de proveedor (`aws`, `azure`, `proxmox`, `vmware`, `virtualbox`, `ludus`) y presets de laboratorio. El "DVWA de Active Directory". Motor primario. |
| Instrumentación + simulación | **Splunk Attack Range v5** | Patrón de plantillas YAML + API REST + simulación (Atomic Red Team / PurpleSharp / Caldera) para AWS/Azure/GCP. Referencia de diseño para la capa de detección. |
| Orquestación de rangos (opcional) | **Ludus** (Bad Sector Labs) | Gestor de rangos con blueprints (incluye GOAD y "AD + Elastic Security") y snapshots. |
| Poblado realista de AD | **BadBlood** (Secframe / @davidprowe) | Miles de objetos realistas (usuarios, grupos, OUs, ACLs, equipos), distintos en cada ejecución. |
| Inyección de vulnerabilidades | **Vulnerable-AD** (WazeHell) | Primitivas PowerShell: Kerberoast, AS-REP roast, DCSync, PtH, contraseñas en descripción, SMB signing off, ACLs. |
| Validación de rutas | **BloodHound / SharpHound** | Grafo de rutas de ataque para verificar las rutas previstas. |

### Defensa (el stack "blue")
| Capa | Opciones (todas open/lab-friendly salvo nota) | Qué aporta |
|---|---|---|
| SIEM / plataforma de logs | **Splunk** (Free/trial), **Elastic Security**, **Wazuh**, **Microsoft Sentinel** (Azure, de pago), **Security Onion**, Graylog | Ingesta, correlación y reglas de detección. |
| EDR / endpoint | **Microsoft Defender AV** (integrado), **Microsoft Defender for Endpoint** (con licencia), **Elastic Defend**, **Wazuh agent**, **Velociraptor**, **LimaCharlie** (free tier) | Prevención, detección y respuesta en host. |
| Hardening (as code) | **ansible-lockdown** (roles CIS y STIG para WS 2016/2019/2022/2025 y Win10/11), **PowerSTIG** (DSC), **Microsoft Security Baselines** | Baseline y controles preventivos reproducibles. |
| NDR / red | **Suricata / Snort** (IDS/IPS), **Zeek** (metadatos), **Arkime** (PCAP) | Visibilidad de red. |
| Deception | **honey accounts** (honeyuser con SPN), **Canarytokens**, honey shares | Cebos que delatan al atacante. |
| SOAR / respuesta (avanzado) | **Shuffle**, **TheHive + Cortex**, **Velociraptor** (live response) | Orquestación y gestión de incidentes. |

> **Recomendación de motor primario:** GOAD v3 como base de IaC + AD/vulns; Attack Range v5 como *patrón* de instrumentación; y para el stack defensivo por defecto, **Elastic Security + Elastic Defend** (SIEM + EDR gratis en un solo despliegue) o **Wazuh** si se prefiere agente propio con FIM/SCA/active-response. Splunk si el objetivo es detection engineering al estilo Attack Range. Sentinel si el laboratorio es Azure y se busca experiencia cloud-SIEM. No mantener dos motores de IaC en paralelo.

---

## 3. Arquitectura del harness

```
                     ┌──────────────────────────────────────────┐
                     │        Descripción en lenguaje natural     │
                     │  "2 dominios, medieval, ESC1+Kerberoast,   │
                     │   Azure, SIEM Elastic + Defender AV + CIS" │
                     └───────────────────┬──────────────────────┘
                                         │  /new-lab
                                         ▼
                     ┌──────────────────────────────────────────┐
                     │              lab-spec.yml                  │  ← fuente de verdad
                     │  (validado contra JSON Schema)             │     (incluye bloque defense:)
                     └───────────────────┬──────────────────────┘
                                         │  /generate  (Skills + reconciliación vuln⟷hardening)
       ┌──────────────┬──────────────────┼──────────────────┬──────────────────┐
       ▼              ▼                  ▼                  ▼                  ▼
  infra-*        ad-topology        vuln-injection     detection-lab     defensive-controls
 (Terraform)    + ad-theming      (con neutralized_by) (SIEM+telemetría) (EDR+hardening+deception)
       └──────────────┴──────────────────┴──────────────────┴──────────────────┘
                                         │
                                         ▼
     ┌────────────────────────────────────────────────────────────────────┐
     │                    generated/<lab>/  (artefactos desplegables)       │
     └───────────────────────────┬────────────────────────────────────────┘
                                 │  /deploy  (orden: infra→topología→theming→
                                 │            hardening→vulns→EDR/telemetría→SNAPSHOT limpio)
                                 ▼
     ┌────────────────────────────────────────────────────────────────────┐
     │   Laboratorio vivo en AWS/Azure  (VPN-only, endurecido con gaps)     │
     └───────────────────────────┬────────────────────────────────────────┘
                                 │  /validate
                                 ▼
     ┌────────────────────────────────────────────────────────────────────┐
     │  Rutas (BloodHound) · Postura (PingCastle) · Atomic → matriz         │
     │  por técnica: PREVENIDO / DETECTADO / NO VISTO  →  lab-report.md     │
     └────────────────────────────────────────────────────────────────────┘
```

### 3.1 Estructura de directorios

```
purpleforge/
├── README.md
├── CLAUDE.md
├── .gitignore                      # generated/, *.tfstate, lab-manifest.json, .venv
├── .claude/
│   ├── settings.json
│   ├── commands/{new-lab,generate,deploy,validate,destroy}.md
│   └── skills/
│       ├── lab-spec/               # parseo, validación, normalización, coste, RECONCILIACIÓN
│       ├── network-topology/       # VPC/VNet, subredes, bastión/WireGuard, NSG/SG
│       ├── infra-aws/  infra-azure/
│       ├── ad-topology/            # forests, dominios, DCs, trusts
│       ├── ad-theming/             # OUs/grupos/usuarios temáticos (sobre BadBlood)
│       ├── vuln-injection/         # catálogo → playbooks (con neutralized_by)
│       ├── detection-lab/          # SIEM + Sysmon + WEF + NDR + reglas   (VER)
│       └── defensive-controls/     # EDR + hardening (CIS/STIG) + deception (PREVENIR/RESPONDER)
├── specs/
│   ├── schema/lab-spec.schema.json
│   └── examples/{medieval-2dom-azure.yml, corp-espionage-aws.yml}
├── catalog/
│   ├── vulnerabilities/*.yml        # metadata+inject+detect+mitigate+neutralized_by+ATT&CK
│   ├── themes/*.yml
│   ├── machine-profiles/*.yml
│   └── defense/                     # NUEVO: catálogo defensivo
│       ├── profiles/{none,telemetry-only,realistic,hardened}.yml
│       ├── siem/{splunk,elastic,wazuh,sentinel}.yml
│       ├── edr/{defender-av,mde,elastic-defend,wazuh-agent,velociraptor,limacharlie}.yml
│       └── hardening/{cis-l1,cis-l2,stig,baseline-controls}.yml
├── templates/
│   ├── terraform/{aws,azure}/
│   ├── ansible/{playbooks,roles,vulns,defense}/
│   └── powershell/
├── vendor/            # submodules: GOAD, attack_range, BadBlood, Vulnerable-AD,
│                      #             ansible-lockdown/Windows-*-CIS, Windows-*-STIG
├── generated/         # SALIDA por lab (gitignored): terraform/, ansible/, lab-manifest.json, lab-report.md
└── scripts/{forge.py, preflight.sh, teardown.sh}
```

---

## 4. El `lab-spec` (entrada declarativa)

El corazón del sistema. El bloque `defense:` es la novedad: describe **qué herramientas defensivas se despliegan** en las máquinas.

```yaml
lab:
  name: shadow-keep
  theme: medieval-kingdom
  provider: azure                  # aws | azure
  region: westeurope
  isolation: vpn-only
  auto_shutdown: "20:00 Europe/Madrid"
  budget_alert_usd: 150

forest:
  - { domain: kingdom.local, netbios: KINGDOM, functional_level: 2016, domain_controllers: 1 }
  - { domain: vassals.kingdom.local, netbios: VASSALS, functional_level: 2016,
      domain_controllers: 1, trust: { target: kingdom.local, type: parent-child } }

machines:
  - { role: domain-controller, os: windows-server-2019, domain: kingdom.local, count: 1 }
  - { role: member-server, os: windows-server-2022, domain: kingdom.local,
      services: [adcs, mssql], count: 1 }
  - { role: workstation, os: windows-10-22h2, domain: kingdom.local, count: 2 }

population: { users: 300, density: realistic, seed: 1337 }

vulnerabilities:                   # los "gaps" deliberados
  - kerberoasting
  - adcs-esc1
  - gpp-cpassword
  - dcsync-acl

# ─── NUEVO: stack defensivo desplegado en las máquinas ───
defense:
  profile: realistic               # none | telemetry-only | realistic | hardened
  # 'profile' fija defaults; lo de abajo son overrides finos sobre el perfil.

  siem:
    platform: elastic              # splunk | elastic | wazuh | sentinel | none
    ship_sysmon: true              # Sysmon (config SwiftOnSecurity/Olaf) → SIEM
    ship_wef: true                 # Windows Event Forwarding → colector
    network_monitoring: [zeek]     # zeek | suricata | none

  edr:                             # 0..N agentes por conjunto de máquinas
    - product: defender-av         # defender-av | mde | elastic-defend | wazuh-agent
      mode: enabled                #             | velociraptor | limacharlie
      settings: { asr_rules: audit, tamper_protection: true, network_protection: true }
      targets: all
    - product: elastic-defend
      mode: prevent                # detect | prevent
      targets: [domain-controller, member-server]

  hardening:
    baseline: cis-l1               # none | cis-l1 | cis-l2 | stig | baseline-controls
    apply_to: all
    controls:                      # controles concretos on/off (togglables)
      laps: true
      lsa_protection: true         # RunAsPPL
      credential_guard: false      # (choca con algunas técnicas de robo de credenciales)
      smb_signing: enforce
      ldap_signing: enforce
      disable_llmnr_nbtns_mdns: true
      protected_users_group: [KINGDOM\\da-treasury]
    # Reglas que se EXCLUYEN a propósito para dejar viva una vuln (ver §7.3).
    intentional_gaps_auto: true    # el harness deriva las exclusiones desde neutralized_by

  deception:
    honey_accounts: 3              # honeyusers con SPN atractivo, alertados
    canarytokens: [docx, aws-keys] # cebos que delatan al atacante

on_conflict: warn                  # warn | exclude-control | fail  (hardening ⟷ vulns)

detection_rules: auto              # instala reglas base por cada vuln inyectada

validation:
  bloodhound: true
  pingcastle: true
  atomic_red_team: [T1558.003, T1552.006, T1649]
  # el informe reporta, por técnica: PREVENIDO / DETECTADO / NO VISTO
```

**Validaciones que impone `lab-spec`:** colisiones de nombres/IPs, prerequisitos de vulns (p. ej. `adcs-esc1` exige servicio `adcs`), coherencia de trusts, estimación de coste, expiración de imágenes Windows eval (180 días), y **reconciliación hardening ⟷ vulnerabilidades** (§7.3): detecta si un baseline/control seleccionado neutraliza una vuln seleccionada y actúa según `on_conflict`.

---

## 5. Las Skills (Claude Agent Skills)

Cada skill es una carpeta con `SKILL.md` + recursos, cargada de forma progresiva.

**`lab-spec`** — Primera skill siempre. Parsea/valida contra el schema, resuelve defaults (incluidos los del perfil defensivo), expande `count`, asigna rangos IP, estima coste, y ejecuta la **reconciliación** entre `hardening` y `vulnerabilities` produciendo la lista de exclusiones o los avisos. Emite `lab-manifest.json`.

**`network-topology`** — VPC/VNet + subredes + subred de gestión con jump host WireGuard/bastión + NSG/SG deny-by-default. Los hosts vulnerables nunca se exponen a Internet.

**`infra-aws` / `infra-azure`** — Terraform *fino* de cómputo+red reutilizando imágenes, sizing y bootstrap WinRM de GOAD.

**`ad-topology`** — Ansible/DSC para promover DCs, forests/dominios, functional levels y trusts.

**`ad-theming`** — OUs/grupos/usuarios/equipos temáticos sobre BadBlood + capa de renombrado según el tema. Determinista vía `seed`.

**`vuln-injection`** — Motor dirigido por catálogo: por cada vuln, verifica prerequisitos, emite el playbook (reutilizando Vulnerable-AD) y registra la ruta prevista. Respeta las exclusiones de hardening derivadas de la reconciliación.

**`detection-lab`** (capa **VER**) — SIEM elegido (Splunk siguiendo Attack Range, Elastic, Wazuh o Sentinel), **Sysmon** + **WEF** hacia el colector, **NDR** opcional (Zeek/Suricata), y las reglas de detección base mapeadas a cada vuln inyectada.

**`defensive-controls`** (capa **PREVENIR/RESPONDER**) — Despliega los **agentes EDR** del spec (Defender AV/ASR, MDE onboarding, Elastic Defend, Wazuh agent, Velociraptor, LimaCharlie), aplica el **baseline de hardening** vía ansible-lockdown (CIS/STIG, nivel y `skip_rule` según reconciliación) y los **controles concretos** (LAPS, LSA protection, SMB/LDAP signing, deshabilitar LLMNR/NBT-NS/mDNS, Protected Users), y siembra la **deception** (honey accounts, Canarytokens).

**`purple-validation`** — SharpHound→BloodHound (rutas), PingCastle (postura), y dispara técnicas Atomic clasificando cada una como **PREVENIDA / DETECTADA / NO VISTA**. Emite `lab-report.md`.

---

## 6. El catálogo de vulnerabilidades

Cada vuln es un `.yml` autocontenido. La novedad es el campo **`neutralized_by`**: los controles de hardening que anularían la vuln, para que la reconciliación (§7.3) sepa qué excluir del baseline.

```yaml
# catalog/vulnerabilities/adcs-esc1.yml
id: adcs-esc1
name: "AD CS ESC1 - plantilla de certificado con SAN suplantable"
severity: critical
attack:
  mitre_attack: [T1649]
  requires_services: [adcs]
  intended_path: >
    Usuario de bajo privilegio solicita certificado con plantilla vulnerable
    especificando un SAN de Domain Admin → autentica como DA (PKINIT).
inject:
  type: ansible
  playbook: templates/ansible/vulns/adcs_esc1.yml
  params: { template_name: "KingdomUser", enrollee_supplies_subject: true, grant_enroll_to: "Domain Users" }
detect:
  data_source: "AD CS / Security 4886,4887; Sysmon"
  signal: "Emisión de certificado con SAN que no coincide con el solicitante"
  siem_rule: templates/detection/{siem}/adcs_esc1
neutralized_by:                    # ← controles que ROMPERÍAN esta vuln
  - hardening.controls.adcs_template_hardening
  - hardening.baseline: [cis-l2]   # (ejemplo) un baseline que endurece plantillas AD CS
mitigate:
  summary: "Quitar ENROLLEE_SUPPLIES_SUBJECT o restringir enrollment; exigir aprobación del manager; mapeo fuerte de certificados."
validate:
  bloodhound_edge: "ADCSESC1"
  atomic: null
```

Añadir una vulnerabilidad = añadir un `.yml`. Sin tocar código del generador.

---

## 7. Capa defensiva (blue stack): SIEM, EDR y hardening

Esta es la dimensión que pediste añadir. La descripción del laboratorio ahora indica **qué herramientas defensivas se despliegan** en las máquinas. Se organiza como un menú (para decidir), unos perfiles (para no elegir 20 toggles), y un modelo de reconciliación (para que hardening y vulns coexistan).

### 7.1 Menú de opciones (guía de decisión)

**SIEM / plataforma de logs** — elige **una** como principal:
- **Splunk** (Free ≤500 MB/día, o trial de Enterprise) — integración nativa con el patrón Attack Range; estándar de facto para detection engineering.
- **Elastic Security** — SIEM + **Elastic Defend** (EDR gratis, sensor de kernel, ML) en un solo despliegue; blueprint listo en Ludus. *Recomendado por defecto para labs.*
- **Wazuh** — XDR+SIEM open source con agente propio (FIM, SCA, rootcheck, active response); cero licencia, muy lab-friendly.
- **Microsoft Sentinel** — SIEM nativo de Azure (KQL); ideal si el lab es Azure y quieres experiencia cloud-SIEM; de pago por ingesta.
- **Security Onion** — distribución todo-en-uno (Elastic + Suricata + Zeek + Wazuh + herramientas); "blue team en una caja".

**EDR / endpoint** — 0..N por conjunto de máquinas:
- **Microsoft Defender Antivirus** (integrado, gratis) — la **línea base realista**: ASR rules, tamper protection, network protection, cloud-delivered. Casi siempre presente en entornos reales; su modo `audit`/`prevent` es un excelente experimento Purple.
- **Microsoft Defender for Endpoint (MDE)** — con licencia M365/Azure; onboarding por GPO/Intune/script. Máximo realismo empresarial.
- **Elastic Defend** — EDR gratis (prevención + respuesta) integrado con Elastic Security.
- **Wazuh agent** — HIDS/XDR con active response.
- **Velociraptor** — visibilidad/hunting/DFIR estilo EDR con VQL y live response; excelente para labs y respuesta.
- **LimaCharlie** — SecOps cloud con sensor EDR y free tier.

**Hardening / controles preventivos (as code)**:
- **ansible-lockdown** — roles Ansible **CIS** y **STIG** para Windows Server 2016/2019/2022/2025 y Windows 10/11, con niveles **L1/L2**, `skip_rule` por regla y auditoría con Goss. La vía recomendada para aplicar baseline como código.
- **PowerSTIG** — enforcement de STIG vía DSC. **Microsoft Security Baselines** — GPOs de baseline.
- **Controles concretos togglables:** LAPS (Windows LAPS), ASR rules, LSA protection (RunAsPPL), Credential Guard, SMB signing, LDAP signing + channel binding, deshabilitar NTLMv1/LLMNR/NBT-NS/mDNS, grupo Protected Users, modelo de admin por *tiers*, AppLocker/WDAC.

**NDR / red (opcional):** Suricata/Snort (IDS/IPS), Zeek (metadatos), Arkime (PCAP).
**Deception (opcional):** honey accounts (honeyuser con SPN atractivo, alertado), Canarytokens, honey shares.
**SOAR / respuesta (avanzado):** Shuffle, TheHive+Cortex, Velociraptor (live response).

### 7.2 Perfiles defensivos

Para no obligar a configurar cada herramienta, el spec ofrece perfiles (`defense.profile`) que fijan defaults sensatos; luego se afinan con overrides:

| Perfil | Qué despliega | Para qué |
|---|---|---|
| `none` | Nada | Práctica puramente ofensiva. |
| `telemetry-only` | Sysmon + WEF + SIEM, **sin** prevención | Detection engineering puro: ver todo, bloquear nada. |
| `realistic` | Defender AV (ASR audit) + **CIS L1** (con gaps intencionados) + SIEM + 1 EDR | El escenario más representativo de una empresa media. |
| `hardened` | **CIS L2/STIG** + EDR en `prevent` + ASR enforce + LAPS + Credential Guard, gaps mínimos | Estrés de evasión y de detección; entorno "difícil". |

### 7.3 El modelo de reconciliación (hardening ⟷ vulnerabilidades) — clave

El hardening y las vulnerabilidades intencionadas se pisan: un baseline CIS puede cerrar justo el agujero que querías practicar. En vez de ignorarlo, el harness lo gestiona:

1. **Orden de aplicación** (en `/deploy`): infraestructura → topología AD → poblado/temática → **baseline de hardening** ("estándar corporativo") → **inyección selectiva de vulns** (los *gaps*) → **EDR + telemetría** → **snapshot del estado limpio**.
2. **Detección de conflictos:** cada vuln declara `neutralized_by`. En tiempo de spec, `lab-spec` cruza `hardening` (baseline + controls) con las `vulnerabilities` y encuentra los choques.
3. **Resolución según `on_conflict`:**
   - `exclude-control` → excluye la regla concreta del baseline (`skip_rule`) para dejar viva la vuln (con `intentional_gaps_auto: true` esto es automático). *Resultado: entorno endurecido con gaps específicos — el más realista.*
   - `warn` → aplica todo y avisa de qué vulns podrían quedar neutralizadas (útil para ver qué controla el baseline).
   - `fail` → detiene la generación y pide resolver el conflicto en el spec.
4. **Validación en 3 estados:** con EDR/hardening desplegados, algunas técnicas Atomic se **bloquean** (prevención) en vez de solo detectarse. `lab-report.md` es una matriz por técnica ATT&CK: **PREVENIDO / DETECTADO / NO VISTO**. Eso convierte el laboratorio en una medición real de cobertura defensiva, no solo en una diana.

---

## 8. Integración con Claude Code

### 8.1 `CLAUDE.md` (raíz) — reglas invariantes
```markdown
## Reglas invariantes
1. Ningún host vulnerable tiene IP pública ni RDP/WinRM abierto a 0.0.0.0/0.
   Acceso SIEMPRE vía WireGuard/bastión en la subred de gestión.
2. Todo despliegue lleva auto_shutdown y alerta de presupuesto.
3. Toda vulnerabilidad inyectada DEBE tener detect + mitigate + neutralized_by.
4. El stack defensivo (SIEM/EDR/hardening) se reconcilia con las vulns antes de
   generar: se respeta on_conflict; nunca se aplica un control que anule en silencio
   una vuln seleccionada.
5. Estado Terraform en backend remoto (S3+DynamoDB / Azure Storage), nunca local.
6. Harness para laboratorios aislados y pruebas autorizadas; no genera payloads ni
   infraestructura dirigida a terceros.
```

### 8.2 Slash commands
- **/new-lab `<descripción>`** — NL → `specs/<name>.yml` validado (pregunta por el perfil/stack defensivo si no se indica).
- **/generate `<lab>` [--dry-run]** — Skills + reconciliación → `generated/<lab>/`.
- **/deploy `<lab>`** — preflight → apply → playbooks en orden (§7.3) → snapshot limpio.
- **/validate `<lab>`** — `purple-validation` → matriz PREVENIDO/DETECTADO/NO VISTO → `lab-report.md`.
- **/destroy `<lab>`** — `terraform destroy` + verificación de coste cero.

### 8.3 Flujo end-to-end
```
/new-lab "2 dominios medieval, ESC1+Kerberoast, Azure, Elastic + Defender AV + CIS L1"
/generate shadow-keep --dry-run
/generate shadow-keep
/deploy shadow-keep          # aplica hardening, luego inyecta gaps, luego EDR, luego snapshot
/validate shadow-keep        # ¿la ruta existe? ¿el ataque se previene/detecta? → lab-report.md
/destroy shadow-keep
```

---

## 9. Recomendaciones

**Arquitectura y reutilización** — Fija versiones de upstreams en `vendor/` (submodules con commit fijado). Un solo motor de IaC (GOAD v3). Terraform fino que consuma módulos/AMIs upstream. Para hardening, apóyate en ansible-lockdown en lugar de escribir GPOs a mano.

**Stack defensivo** — Empieza con el perfil `realistic` y **Elastic Security + Elastic Defend** (SIEM+EDR gratis en un despliegue) o **Wazuh**; añade Sentinel solo si el lab es Azure y quieres cloud-SIEM. Mantén **Defender AV siempre presente** (aunque sea en `audit`): es lo que hay en la realidad y su modo audit/prevent es un gran experimento Purple.

**Reconciliación** — Usa `on_conflict: exclude-control` + `intentional_gaps_auto: true` como default: entornos mayormente endurecidos con gaps específicos son mucho más valiosos que cajas completamente abiertas. Documenta en el `lab-report.md` qué controles se excluyeron y por qué.

**Determinismo y coste** — `seed` a todo; playbooks idempotentes; `auto_shutdown` + budget alerts; instancias spot donde sea seguro; `terraform destroy` disciplinado.

**Seguridad y estado** — Ingress solo-VPN, egress denegado por defecto; estado Terraform remoto con locking; credenciales generadas en `lab-manifest.json` (gitignored) o SSM/Key Vault. Recuerda la expiración de imágenes eval a 180 días.

**Snapshots** — Snapshot del estado limpio tras provisionar y **antes** de atacar, para resetear entre ejercicios.

**Rigor Purple** — Mapea vulns a ATT&CK y controles a D3FEND. El `lab-report.md` como matriz técnica → ¿ruta existe? → PREVENIDO/DETECTADO/NO VISTO → mitigación.

**Testing del generador** — Validación de schema en CI; `--dry-run` con `terraform plan` + `ansible --check`; smoke test que genere los `specs/examples/` en cada PR, incluyendo un test de la reconciliación (una vuln + un control que la neutraliza → verifica la exclusión).

---

## 10. Roadmap de implementación por fases

1. **Fase 0 — Andamiaje.** Estructura, `lab-spec.schema.json` (con bloque `defense:`), `CLAUDE.md`, skill `lab-spec` con reconciliación, 2 specs de ejemplo. Salida: `lab-manifest.json` validado.
2. **Fase 1 — Un dominio, un cloud.** `network-topology` + `infra-azure` + `ad-topology`. Meta: 1 DC limpio, solo-VPN, con `/deploy`/`/destroy`.
3. **Fase 2 — Poblado y temática.** `ad-theming` + BadBlood + 1 tema.
4. **Fase 3 — Vulnerabilidades.** `vuln-injection` + 5–7 vulns clave con `neutralized_by`.
5. **Fase 4 — Detección (VER).** `detection-lab`: SIEM (Elastic/Splunk/Wazuh) + Sysmon + WEF + reglas base.
6. **Fase 5 — Controles (PREVENIR).** `defensive-controls`: EDR (Defender AV/Elastic Defend/…) + hardening ansible-lockdown (CIS L1) + controles concretos + deception. Aquí se ejercita la reconciliación.
7. **Fase 6 — Validación Purple.** `purple-validation` con matriz PREVENIDO/DETECTADO/NO VISTO → `lab-report.md`.
8. **Fase 7 — Multi-dominio, multi-cloud, API.** Trusts, `infra-aws`, y opcionalmente API/CLI al estilo Attack Range.

---

## 11. Referencias (upstreams)

**Ofensiva / IaC:** GOAD (`github.com/Orange-Cyberdefense/GOAD`) · Splunk Attack Range (`github.com/splunk/attack_range`) · Ludus (`docs.ludus.cloud`) · BadBlood (`github.com/davidprowe/BadBlood`) · Vulnerable-AD (`github.com/WazeHell/vulnerable-AD`) · BloodHound/SharpHound.

**Defensa:** Elastic Security + Elastic Defend · Wazuh · Splunk · Microsoft Sentinel · Microsoft Defender AV / Defender for Endpoint · Velociraptor · LimaCharlie · Security Onion · ansible-lockdown (`github.com/ansible-lockdown`, roles Windows-*-CIS / Windows-*-STIG) · PowerSTIG · Microsoft Security Baselines · Suricata / Zeek / Arkime · Canarytokens · PingCastle / Purple Knight · Atomic Red Team / PurpleSharp / Caldera.
