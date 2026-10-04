# BAS (adversary emulation) — deploy runbook

How to deploy and enroll the BAS-pillar **agent** — the MITRE **Caldera** `sandcat`
beacon — on a PurpleForge lab. Sibling of TELEMETRY-DEPLOY-RUNBOOK.md and the
AWS/AZURE/PROXMOX deploy runbooks.

**Division of labor.** PurpleForge installs + enrolls the *agent* on the lab hosts
and persists it (at-boot SYSTEM scheduled task). **You (the operator) stand up the
Caldera server and drive the emulation** — the adversary profiles, abilities and
operations. Server credentials are **deploy-time env vars, never in the spec** (the
same deliberate exception to account-independence as the DETECT telemetry layer,
invariant #2).

**Order.** The agent installs *after* vuln-injection and telemetry, *before* the
clean snapshot — the dormant beacon is part of the defended baseline the snapshot
captures (like the EDR). The Caldera **operations are attacks** and must be run
*after* the snapshot, the same way `/validate` fires its exploits after it.

> ⚠️ Not yet exercised live. The sandcat download headers and agent flags track
> Caldera's current `sandcat` plugin; verify against your server version. Treat the
> `pf_caldera_agent` role with the same caution the Elastic role carried before its
> 2026-10-04 live test.

---

## 1. Opt in: the `bas:` spec block

```yaml
bas:
  caldera: { enabled: true, targets: all }   # sandcat beacon on all hosts
```
`targets` defaults to `all`; narrow it to a role list (e.g. `[member-server]`) to
beacon from only some hosts. Omit the block to skip BAS entirely.

## 2. Deploy-time env vars

```bash
export PF_CALDERA_SERVER="http://<caldera-host>:8888"   # base URL incl. scheme+port
export PF_CALDERA_GROUP="red"                            # sandcat group to join
# export PF_CALDERA_API_KEY="..."                        # ONLY if your download
#                                                        # endpoint is auth-gated
```
`deploy.sh` (AWS/Azure/Proxmox) validates `PF_CALDERA_SERVER` + `PF_CALDERA_GROUP`
when the lab selects Caldera and passes them to `site.yml` as extra-vars. Keep them
out of the repo (e.g. the gitignored `.env` you `source`).

## 3. Operator backend setup (YOUR half)

### 3a. Stand up a Caldera server — pick ONE

**Cloud Caldera** (a VM/container you run somewhere routable):
1. `git clone https://github.com/mitre/caldera.git --recursive && cd caldera`
2. `python server.py --insecure` (lab/testing) — serves the UI + agent download on
   `:8888`.
3. `PF_CALDERA_SERVER` = that server's public/routable URL. The lab's Windows
   agents reach it by **egress through the WireGuard bastion** (the bastion is the
   NAT instance for the private subnets), so no inbound rule to the vulnerable
   hosts is needed — invariant #1 holds.

**Local Kali Caldera** (run it on the same Kali box that holds the WireGuard
tunnel — the common case):
1. Run Caldera on Kali (native or Docker) listening on `:8888`.
2. The agents cannot reach Kali's LAN/`localhost` — they reach it **over the
   WireGuard tunnel**. Find the Kali address the lab subnets can route to:
   ```bash
   ip -4 addr show pf-lab          # the WireGuard interface added by deploy.sh
   ```
   Use that tunnel IP: `PF_CALDERA_SERVER="http://<pf-lab-ip>:8888"` (NOT
   `127.0.0.1` and NOT Kali's public/LAN IP).
3. Bind Caldera to the tunnel (or all interfaces) so it accepts the agents'
   connections, and allow `:8888` on Kali's host firewall for the `pf-lab`
   interface. The lab egress SG already lets the private hosts reach the bastion/
   tunnel; confirm nothing blocks `:8888` back to Kali.

### 3b. Create the agent group
In the Caldera UI the group is just a label the agent self-reports — set
`PF_CALDERA_GROUP` to whatever you'll target operations at (e.g. `red`). No
server-side pre-creation is required for the default `sandcat` plugin.

## 4. Deploy

Same as any lab — `forge deploy <spec>` (or run `generated/<lab>/deploy.sh`). With
the env vars set, `site.yml` runs `bas-provisioning.yml` after telemetry and before
the snapshot. Each host:
1. downloads `sandcat.exe` from `<PF_CALDERA_SERVER>/file/download`,
2. registers it as the at-boot SYSTEM task `PFCalderaSandcat` (survives reboot →
   captured in the clean snapshot),
3. starts it immediately and verifies the `sandcat` process is running.

Each host runs in block/rescue: a host that fails to reach the server surfaces
`PF-BAS-FAILED` and the others continue (same fault isolation as telemetry).

## 5. Verify

- **Caldera UI → Agents**: the lab hosts appear in `PF_CALDERA_GROUP`, beaconing.
- **On a host**: `Get-ScheduledTask PFCalderaSandcat` and `Get-Process sandcat`.
- If an agent never checks in: the server URL is wrong/unreachable (local-Kali:
  almost always the `127.0.0.1`-vs-tunnel-IP mistake in §3a), the Kali firewall is
  dropping `:8888`, or the download endpoint is auth-gated (set
  `PF_CALDERA_API_KEY`).

## 6. Run operations (post-snapshot — these are the attacks)

Drive adversary profiles/operations from the Caldera server **after** the clean
snapshot, exactly as the purple-team exercise intends. Between exercises,
`forge reset <spec>` restores the clean snapshot (the dormant beacon comes back
with it; the operations' effects are rolled off).
