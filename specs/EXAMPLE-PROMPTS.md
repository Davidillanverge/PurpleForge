# PurpleForge — prompts de ejemplo por caso de uso

Prompts en lenguaje natural para **`/new-lab`** (que invoca `lab-designer` →
compila con `forge lab-spec` → puerta `guardrail`). Cada uno ejercita un conjunto
distinto de capacidades; al final están el "todo incluido", el caso
`/lab-from-exercise` y el ciclo de vida.

Reglas que el guardrail exige siempre, aunque no las menciones:
- `auto_shutdown` + `budget_alert_usd` obligatorios (coste como código).
- Aislamiento `vpn-only`: ningún host vulnerable con IP pública ni RDP/WinRM a Internet.
- Toda vuln se despliega con su contraparte defensiva (invariante #2).
- Las credenciales de telemetría/BAS **nunca** van en el spec: se pasan en deploy-time.

Superficie de opciones (resumen): proveedores `aws|azure|proxmox`; roles
`domain-controller|member-server|workstation`; OS Server 2016/2019/2022/2025 y
Win10-22h2/Win11-23h2; servicios `adcs|mssql|iis|ftp|wsus|sccm`; apps `jenkins`;
defensa `none|realistic|hardened` + baseline `cis-l1|cis-l2|stig|baseline-controls`
+ controles (LAPS, LSA protection, Credential Guard, firma SMB/LDAP, NTLMv2-only,
Protected Users, mssql/iis hardening) + Defender AV (`enabled|detect|prevent`);
telemetría `edr: elastic|microsoft-defender`, `siem: elastic`, `swg: cloudflare`;
BAS `caldera`; `attack_chain.mode: independent|ctf`; `on_conflict: warn|exclude-control|fail`;
temas en `catalog/themes/`.

---

## 1. CTF ofensivo puro (cadena encadenada, sin defensa)

> `/new-lab` Monta un CTF estilo Piratas del Caribe en AWS (eu-west-1). Un solo
> dominio `isla.local`, 1 DC + 1 member-server. Quiero una cadena de ataque
> **encadenada** (modo CTF) donde explotar una cosa sea requisito de la
> siguiente: AS-REP roasting → kerberoasting → DCSync por ACL hasta Domain
> Admin. Sin hardening ni EDR, y sin ruido de ACLs para que la señal sea limpia.
> Población pequeña (10 usuarios), apagado a las 20:00 Europe/Madrid, alerta de
> presupuesto 30 $.

Ejercita: `attack_chain: ctf`, `defense.profile: none`,
`population.include_noise_acls: false`, tema.

---

## 2. Purple team realista (defensa + deception + Defender AV)

> `/new-lab` Laboratorio corporativo realista en Azure (eastus), dominio
> `contoso.local`, 1 DC + 1 member-server + 1 workstation (Windows 11). Perfil de
> defensa **realistic**: Defender AV en modo *detect* con tamper protection y
> reglas ASR en audit, más cuentas honey de deception. Inyecta kerberoasting, GPP
> cPassword, unconstrained delegation y una GPO editable. Que los conflictos
> hardening↔vuln solo avisen (`on_conflict: warn`), no los excluya. 25 usuarios,
> densidad realista.

Ejercita: `defense.profile: realistic`, `edr: defender-av` (detect + settings),
deception, `on_conflict: warn`.

---

## 3. Endurecido / showcase de reconciliación

> `/new-lab` Quiero un lab para probar la reconciliación hardening↔vulns en
> Proxmox (nodo `pve-01`), dominio `banco.local`, 1 DC + 1 member-server Windows
> Server 2022. Aplica baseline **CIS L2** a todas las máquinas y activa
> explícitamente LAPS, LSA protection, Credential Guard, firma SMB y LDAP,
> NTLMv2-only y Protected Users. Pide igualmente SMB-signing-disabled,
> LDAP-signing-not-required y kerberoasting: donde un control anule una vuln,
> **excluye el control** (`on_conflict: exclude-control`) y que el informe lo deje
> claro.

Ejercita: `hardening.baseline: cis-l2` + `controls.*`, `on_conflict: exclude-control`.

---

## 4. Bosque multidominio con trusts

> `/new-lab` Bosque multidominio en Azure para practicar movimiento entre
> dominios. Raíz `empire.local` (1 DC) y un hijo `corp.empire.local` (1 DC) con
> trust parent-child, más un dominio externo `partner.local` (1 DC) con trust
> **external** hacia la raíz. Tema Star Wars. Mete unconstrained delegation en un
> member del dominio raíz y RBCD mal configurada en el hijo. Functional level
> 2016, 30 usuarios.

Ejercita: `forest[]` multidominio + `trust` (parent-child / external).

---

## 5. Vulns de servicio y de app no-AD (ADCS, MSSQL, IIS, FTP, Jenkins, web)

> `/new-lab` Lab centrado en vulnerabilidades de servicios y aplicaciones en AWS,
> dominio `acme.local`. 1 DC y tres member-servers: uno con **ADCS** (ESC1), uno
> con **MSSQL** (sa débil + xp_cmdshell) y uno con **IIS** (WebDAV con
> credenciales débiles + app pool como LocalSystem). Añade un member con **FTP**
> anónimo que expone credenciales y escribe en el webroot, y una workstation con
> **Jenkins** (consola de script anónima). Súmale una app web ASP.NET con
> inyección SQL contra el MSSQL. Tema the-office, defensa realista.

Ejercita: `machines[].services` (adcs/mssql/iis/ftp), `applications: [jenkins]`,
vulns de servicio y de webapp.

---

## 6. DETECT — telemetría Elastic (EDR+SIEM) + Cloudflare WARP, o MDE

> `/new-lab` Lab para ingeniería de detección en AWS, dominio `soc.local`, 1 DC +
> 1 member-server + 1 workstation. Instala agentes de telemetría: **Elastic
> Agent** haciendo EDR (Elastic Defend) y SIEM (winlog) en todos los hosts, y
> **Cloudflare WARP** como SWG en la workstation. Inyecta kerberoasting,
> machine-account-quota y shadow credentials para generar señal. Defensa realista
> con Defender AV en detect. (Yo aporto Fleet/Zero Trust en deploy-time).

Variante MDE:

> …en vez de Elastic para EDR, usa **Microsoft Defender for Endpoint**
> (`telemetry.edr: microsoft-defender`) en el DC y el member; yo paso el paquete
> de onboarding con `MDE_WIN_ONBOARDING_PATH` al desplegar.

Ejercita: `telemetry.edr/siem/swg`. Nota: `edr` admite un solo proveedor
(elastic **o** microsoft-defender); SIEM Elastic y WARP conviven con cualquiera.
Deploy-time: `PF_FLEET_*` / `PF_CLOUDFLARE_*` / `MDE_WIN_ONBOARDING_PATH`.

---

## 7. BAS — emulación de adversario (Caldera)

> `/new-lab` Lab de breach-and-attack-simulation en Azure, dominio
> `redteam.local`, 1 DC + 2 member-servers. Despliega el beacon **sandcat de
> MITRE Caldera** en todos los hosts como agente latente (el servidor C2 lo pongo
> yo, Kali local por el túnel). Inyecta kerberoasting, unconstrained delegation y
> SeImpersonate para que las operaciones tengan algo que tocar. Defensa realista
> con deception.

Ejercita: `bas.caldera`. Deploy-time: `PF_CALDERA_SERVER` / `PF_CALDERA_GROUP`.

---

## 8. Mismo lab, cambiando de proveedor (portabilidad del spec)

> `/new-lab` El mismo laboratorio pequeño (1 DC + 1 member, kerberoasting + GPP
> cPassword, tema football) pero dame tres versiones: una en **AWS** (eu-west-1),
> una en **Azure** (westeurope) y una en **Proxmox** (nodo `pve-01`). Igual todo
> lo demás.

Ejercita: `provider`/`region`. Región/SKU también son override en deploy-time
(`PF_REGION`/`PF_VM_SIZE`/…) sin editar el spec.

---

## 9. "Todo incluido" (casi todos los knobs)

> `/new-lab` Laboratorio purple team completo en AWS (us-east-1), tema
> medieval-kingdom, dominio `kingdom.local` con functional level 2016. Topología:
> 1 DC, 2 member-servers (uno con **ADCS**, uno con **MSSQL**+**IIS**) y 1
> workstation Windows 11. Población: 40 usuarios, densidad *messy*, seed fija
> 1337, con ruido de ACLs activado.
> Ofensiva (modo **ctf**, cadena encadenada): asreproast → kerberoasting → ADCS
> ESC1 → DCSync por ACL hasta DA, más SeImpersonate y unquoted-service-path para
> privesc local en la workstation, e inyección SQL en una app web ASP.NET contra
> el MSSQL.
> Defensa: perfil **hardened** con baseline **CIS L1**, LAPS + LSA protection +
> Credential Guard + firma SMB/LDAP, Defender AV en modo *prevent* con ASR en
> audit y tamper protection, y deception. Reconciliación `exclude-control`.
> DETECT: **Elastic Agent** (EDR+SIEM) en todo. BAS: beacon de **Caldera** latente
> en todos los hosts.
> Validación: BloodHound y PingCastle activados, y comprueba las técnicas ATT&CK
> T1558.003 y T1649.
> Apagado 20:00 Europe/Madrid, alerta de presupuesto 80 $.

Nota: no pidas MDE **y** Elastic como EDR a la vez — `edr` admite un solo
proveedor. SIEM Elastic + WARP sí conviven con el EDR que elijas.

---

## 10. Generar desde un ejercicio BAS (`/lab-from-exercise`)

Aquí **no describes el lab**: lo dirige una capa ATT&CK Navigator (el inverso de
`/new-lab`). El traductor convierte cada técnica del `.json` en la vuln del
catálogo que la reproduce y rellena el envoltorio de infra con los flags.

```
/lab-from-exercise exercises/mi-ejercicio.layer.json --provider aws --theme corporate --region eu-west-1 --users 20
```

---

## 11. Ciclo de vida (lab ya generado — no es diseño)

Comandos deterministas sobre un spec ya creado:

```
forge deploy    specs/<lab>.yml             # infra + túnel + AD + hardening + vulns + snapshot
forge validate  specs/<lab>.yml --run       # confirma cada vuln aplicada + explotable
forge stop      specs/<lab>.yml             # pausar (apagado ordenado), sin tocar el estado TF
forge start     specs/<lab>.yml             # reanudar: encender + túnel + chequeo, sin re-apply
forge reset     specs/<lab>.yml             # re-ejecutar Ansible al estado limpio del spec
forge reset     specs/<lab>.yml --snapshot  # rollback al snapshot limpio
forge restart   specs/<lab>.yml             # reiniciar VMs colgadas (reboot, no rollback)
forge teardown  specs/<lab>.yml             # destruir a coste cero (confirma el nombre, o --force)
```
