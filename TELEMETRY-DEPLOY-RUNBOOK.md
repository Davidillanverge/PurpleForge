# TELEMETRY (DETECT) — deploy runbook

How to deploy and validate the DETECT-pillar telemetry **agents** (SWG + EDR +
SIEM) on a PurpleForge lab. Sibling of AWS/AZURE/PROXMOX-DEPLOY-RUNBOOK.md.

**Division of labor.** PurpleForge installs + enrolls the *agents* on the lab
hosts. **You (the operator) configure the backends** — the Elastic deployment +
Fleet policy + detection rules, and the Cloudflare Zero Trust org + Gateway +
device-enrollment policy. Backend credentials are **deploy-time env vars, never in
the spec** (the one deliberate exception to account-independence, invariant #2).

Live-validated 2026-10-04 on AWS (Windows Server 2022): Elastic Agent EDR+SIEM
Healthy+Connected to Fleet, Cloudflare WARP SWG Connected. See the
`telemetry-live-validation` memory for the war story.

---

## 1. Opt in: the `telemetry:` spec block

```yaml
telemetry:
  swg:  { provider: cloudflare, enabled: true }   # WARP client
  edr:  { provider: elastic,    enabled: true }   # Elastic Agent (Defend)
  siem: { provider: elastic,    enabled: true }   # Elastic Agent (winlog) — SAME agent as edr
```
One `elastic-agent` serves both `edr` and `siem` (the Fleet policy you build
decides which integrations run). `swg` is the WARP client. Omit a layer to skip it.

`edr` can instead be **Microsoft Defender for Endpoint** — a separate, Windows-only
agent (NOT the elastic-agent), onboarded from your Windows package:

```yaml
telemetry:
  edr: { provider: microsoft-defender, enabled: true }   # MDE Sense sensor
```
`siem`/`swg` are independent and may still be set alongside it. MDE is mutually
exclusive with `edr: elastic` (one `edr` provider per lab).
Agents install AFTER vuln-injection, BEFORE the clean snapshot (part of the
defended baseline). Each agent runs in block/rescue, so one failing layer does not
abort the others.

## 2. Deploy-time env vars

```bash
# Elastic (edr/siem)
export PF_FLEET_URL="https://<fleet-host>:443"          # Fleet Server host URL
export PF_FLEET_ENROLLMENT_TOKEN="<agent-policy enrollment token>"
export PF_ELASTIC_AGENT_VERSION="9.5.4"                 # MUST match your stack version
# export PF_FLEET_INSECURE=true                         # only if self-hosted w/ self-signed CA

# Cloudflare (swg)
export PF_CLOUDFLARE_TEAM="<your-team-slug>"            # <team>.cloudflareaccess.com
export PF_CLOUDFLARE_ENROLL_CLIENT_ID="<hex>.access"    # service token Client ID
export PF_CLOUDFLARE_ENROLL_CLIENT_SECRET="cfast_..."   # service token Client Secret

# Microsoft Defender for Endpoint (edr: microsoft-defender)
export MDE_WIN_ONBOARDING_PATH="/path/to/WindowsDefenderATPOnboardingScript.cmd"
# the Windows onboarding .cmd from the Defender portal (Settings -> Endpoints ->
# Onboarding -> Windows Server / Local Script). deploy.sh stages it into the
# gitignored generated/<lab>/ansible/files/mde/ so the pf-ansible container can
# copy it to each host — it is NEVER written into the generated playbook.
```
`deploy.sh` (AWS/Azure/Proxmox) validates the ones the selected layers need and
passes them to `site.yml` as extra-vars. Keep them out of the repo (e.g. a file you
`source`, 0600, outside the tree).

## 3. Operator backend setup (YOUR half)

### 3a. Elastic (EDR + SIEM)
1. An Elastic deployment (Elastic Cloud trial, or self-hosted ES+Kibana+Fleet).
2. Kibana → **Fleet**: note the **Fleet Server host URL** → `PF_FLEET_URL`.
3. **Fleet → Agent policies → Create** a policy; add integrations:
   **Elastic Defend** (EDR) + **Windows** (winlog/Sysmon → SIEM).
4. **Fleet → Enrollment tokens**: the policy's token → `PF_FLEET_ENROLLMENT_TOKEN`.
5. `PF_ELASTIC_AGENT_VERSION` = your stack version (agent must match).

### 3b. Cloudflare WARP (SWG) — the fiddly part
1. **Access controls → Service Auth → Service Tokens → Create** → note the
   **Client ID** (`<hex>.access`) + **Client Secret** → the `PF_CLOUDFLARE_*` vars.
2. **Access controls → Policies → Add a policy**:
   - **Action: `Service Auth`** (NOT Allow; stored as `decision: non_identity`)
   - **Include → Selector: `Service Token` → Value: the token from step 1**
     (new dashboard uses the Service Token selector, NOT the old
     `non_identity@<team>.cloudflareaccess.com` email).
3. **Attach** it: **Team & Resources → Devices → Device profiles → Management →
   Device enrollment → Device enrollment permissions → Manage → Policies tab →
   add the policy from step 2.** (Creating it is not enough — it must be attached.)
4. **Critical:** the service token in the policy MUST be the SAME token whose
   Client ID is in the mdm (`PF_CLOUDFLARE_ENROLL_CLIENT_ID`). A policy references a
   token by `token_id` (UUID) while the mdm uses the `Client ID` (`<hex>.access`) —
   two IDs of the same token, easy to mismatch.
5. Gateway: a default policy is enough (classifies/logs egress).
6. Split-tunnel: the lab's `10.x` range is in WARP's default RFC1918 exclude, so
   the WinRM/WireGuard management path is safe — just don't switch to Include mode.

### 3c. Microsoft Defender for Endpoint (MDE)

1. Microsoft Defender portal → **Settings → Endpoints → Onboarding**.
2. OS = the lab's Windows (e.g. **Windows Server 1803+/2019/2022**), method =
   **Local Script** → **Download onboarding package**; unzip to get
   `WindowsDefenderATPOnboardingScript.cmd` → point `MDE_WIN_ONBOARDING_PATH` at it.
3. The role runs the script (writes the tenant blob, starts the **Sense** service),
   then health-checks: `Sense` running + auto-start, `OnboardingState = 1`, and
   `Get-MpComputerStatus` real-time protection. Devices appear under **Assets →
   Devices** a few minutes later; device groups / policies / detections are yours.
4. Windows-only by design — the role skips/guards non-Windows hosts (every current
   lab host is Windows). The local-script onboarding is for servers/VMs; at scale
   you would normally use Intune/GPO, out of scope here.

## 4. Deploy

```bash
source <your telemetry env file>
forge generate specs/<lab>.yml     # only when NOT mid-deploy — never on a live lab
forge deploy   specs/<lab>.yml
```
If the first run dies at `wg-quick up failed` (bastion cloud-init race), just
re-run `forge deploy` (idempotent) — do NOT `forge generate` again (it orphans the
Terraform state; manual cleanup by tag required if you do).

## 5. Verify

- **Elastic**: Kibana → **Fleet → Agents** → each host **Healthy**. (On-host:
  `elastic-agent status` → `(HEALTHY) Connected`.)
- **WARP**: on-host `warp-cli status` → **Connected**; device appears in Zero Trust.
- **MDE**: on-host `Get-Service Sense` → **Running**, registry `OnboardingState=1`; device appears in the Defender portal (Assets → Devices).

## 6. Troubleshooting (all seen live)

| Symptom | Cause / fix |
|---|---|
| WARP MSI `1603` at `ConfigureServiceCA` | Server lacks WLAN AutoConfig. Role enables `Wireless-Networking` + reboot on Server. WARP is officially Win10/11; native there. |
| `C:\setup does not exist` (WARP-only run) | Role now creates its own setup dir. |
| `registration new` opens a browser | Don't use it (interactive). Enrollment is automatic from mdm on service start. |
| `Is Service Auth allowed in Device Enrollment Rules?` (in `C:\ProgramData\Cloudflare\cfwarp_service_log.txt`) | The Service Auth policy isn't granting: wrong action (Allow vs Service Auth), wrong selector (email vs Service Token), not attached, or token mismatch. See 3b. |
| `Invalidated(ApiMismatch)` | Stale local registration. Role runs `warp-cli registration delete` before the service restart. |
| Elastic agent verify false-negative | 9.x prints `(HEALTHY)` uppercase; role matches case-insensitively. |
| Teardown prints `FAIL ... resource(s) still exist` | Known `resourcegroupstaggingapi` lag false-positive; verify cost-zero by hand (describe-instances/volumes/vpcs). |

## Out of scope (later rounds)
- Detection-coverage feedback loop (validate → pull alerts → applied+exploitable+
  **detected** matrix); the vuln schema's `detect`/`siem_rule` stays forbidden until then.
- Alternative stacks: Zscaler (SWG), MDE (EDR), Sentinel (SIEM).
