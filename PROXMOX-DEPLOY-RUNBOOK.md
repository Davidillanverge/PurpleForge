# Proxmox VE deploy runbook

Checklist from a **fresh Proxmox install** to a live PurpleForge lab.

> **Not yet validated against a live Proxmox deploy.** Steps 0–2 (host prep) are
> standard Proxmox admin and solid. Steps 3+ are the harness's documented behavior,
> not battle-tested — expect to hit and fold back a few gotchas, as the Azure
> runbook was. Design details: `infra-proxmox/SKILL.md`, `IMAGES-AND-TEMPLATES.md`.

## 0. Deploy-host prerequisites (one-time)

The deploy host runs `deploy.sh`; it need not be the Proxmox host, only
network-reachable to it. Same tools as Azure minus `az`:

```bash
which terraform wg openssl curl python3 docker ssh || echo "install whichever is missing"
docker run --rm python:3.10-slim python3 --version   # confirm docker + pre-pull
curl -sk https://<proxmox-host>:8006/api2/json/version   # expect a JSON "version" blob
```

`ssh` must be a real OpenSSH client (the deploy reaches the bastion over SSH).
`ansible-core` is NOT installed on the host — it runs in the `pf-ansible` container.

**Nested virtualization** (if Proxmox runs inside another hypervisor): pass through
VT-x/AMD-V or the Windows/bastion VMs won't boot (or crawl in emulation).
VirtualBox: *Settings → System → Processor → Enable Nested VT-x/AMD-V*. Confirm on
the Proxmox host: `grep -E 'vmx|svm' /proc/cpuinfo | head -1` (non-empty = OK).

## 1. Prepare the Proxmox host (once, standard admin)

**1a. Two network bridges:**

| Bridge | Purpose |
|---|---|
| `vmbr0` (usually exists) | **Management** — routable; the host IP + the bastion's external address |
| `vmbr1` (new) | **Lab** — isolated, no uplink; every Windows VM here, VLAN-tagged per domain. Create via Datacenter → node → Network → Create → Linux Bridge, **Bridge ports empty**. |

One bridge only if you deliberately don't isolate (breaks invariant #1 — not
recommended). Confirm: `ip link show type bridge`.

**1b. Enable Snippets on storage** (first-boot scripts upload as snippets):
Datacenter → Storage → `local` → Edit → Content → check **Snippets**. Or:
`pvesh set /storage/local --content backup,iso,vztmpl,snippets`.

**1c. API token:** Datacenter → Permissions → API Tokens → Add. Uncheck Privilege
Separation for a first pass (scope down later once you know which privileges
`bpg/proxmox` uses: VM create/clone/start/stop, pool, snippet upload, firewall).
Copy the full token string (shown once):

```bash
export PROXMOX_VE_ENDPOINT="https://<proxmox-host>:8006/"
export PROXMOX_VE_API_TOKEN="purpleforge@pve!purpleforge=xxxxxxxx-...."
export PROXMOX_VE_INSECURE=true    # self-signed cert (default)
# verify:
curl -sk -H "Authorization: PVEAPIToken=$PROXMOX_VE_API_TOKEN" "$PROXMOX_VE_ENDPOINT/api2/json/nodes" | python3 -m json.tool
```

**1d. Note the node name:** `pvesh get /nodes` (needed for `node_name`).

## 2. Build the two templates (before writing the spec — you need the vm_ids)

**2a. Bastion (Ubuntu 22.04+ cloud-init):**

```bash
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qm create 9000 --name ubuntu-2204-cloudinit-template --memory 1024 --cores 1 --net0 virtio,bridge=vmbr0
qm importdisk 9000 jammy-server-cloudimg-amd64.img local-lvm
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --ide2 local-lvm:cloudinit --boot c --bootdisk scsi0 --serial0 socket --vga serial0 --agent enabled=1
qm template 9000     # record 9000 as bastion_template_id
```

**2b. Windows template** (full checklist in `IMAGES-AND-TEMPLATES.md`):

1. Install Windows Server (any `os` you'll use) as a normal VM.
2. Add the **VirtIO driver ISO** (disk/net under KVM).
3. Install **cloudbase-init**, default plugin set (includes `UserDataPlugin` — the
   one thing the bootstrap depends on).
4. Generalize (`sysprep /generalize /oobe /shutdown`), power off, `qm template <vmid>`.
5. Record the vm_id under the matching `os` in `template_map`.

**Do NOT** install WinRM, create accounts, or set passwords in the template —
`windows-bootstrap.ps1.tpl` does that at first boot. Repeat per `os`.

## 3. Write + validate the spec

Use `lab.provider: proxmox`. Start from `specs/<lab>.yml`
(one DC, no vulns) for the first live deploy.

```bash
forge lab-spec specs/<lab>.yml
```

## 4. Generate + fill the host binding

```bash
forge generate specs/<lab>.yml
cp generated/<lab>/terraform/proxmox/host.auto.tfvars.example.json \
   generated/<lab>/terraform/proxmox/host.auto.tfvars.json
```

Edit the copy (gitignored, never commit):

| Key | Value |
|---|---|
| `node_name` | step 1d |
| `datastore_id` | VM disk store, e.g. `local-lvm` |
| `snippets_datastore_id` | the store from 1b, e.g. `local` |
| `mgmt_bridge` / `lab_bridge` | `vmbr0` / `vmbr1` |
| `template_map` | `{"windows-server-2019": 9001, ...}` — step 2b |
| `bastion_template_id` | step 2a (e.g. `9000`) |
| `jumpbox_external_ip`/`_prefix`/`_gateway` | bastion's static address on `vmbr0` |

## 5. Deploy

```bash
./generated/<lab>/deploy.sh
```

Order (per `deploy-proxmox.sh.j2`): preflight → infra secrets → `terraform
init/apply` (local state) → WireGuard tunnel → `pf-ansible` container → wait for
WinRM → `site.yml` → best-effort `auto_shutdown` cron. Watch it run (unvalidated
path) — see the symptom table for what to check.

## 6. Verify + teardown

```bash
forge validate specs/<lab>.yml --run
./generated/<lab>/teardown.sh
```

No per-hour billing, but `teardown.sh` still removes the pool/VMs/firewall rules +
local Terraform state.

## Known limitations

- `auto_shutdown` is best-effort cron on the **deploy host** (fires only while it's
  up), unlike Azure's native schedule.
- Bastion per-domain VLAN sub-interfaces are reasserted each `deploy.sh` run but not
  persistent across a bastion reboot.
- Multi-domain trust routing through the bastion isn't yet run live.

## Symptom → cause

| Symptom | Cause | Fix |
|---|---|---|
| `api2/json/version` hangs/refuses | Network/firewall to Proxmox | Fix routing first |
| VMs won't start / crawl | No nested virtualization | Enable VT-x/AMD-V passthrough (step 0) |
| `terraform apply` token/permission errors | API token missing a privilege | Step 1c; simplest: un-scope the token |
| Snippet upload fails | Snippets content type not enabled | Step 1b |
| VM clone fails, template not found | Wrong vm_id, or source never `qm template`'d | Step 2, confirm `qm list` |
| WireGuard tunnel never comes up | `jumpbox_external_ip`/`_gateway` wrong, or bastion didn't boot | Step 4 values, then bastion console |
| WinRM never comes up on a guest | cloudbase-init/UserDataPlugin not enabled | Check `C:\pf-bootstrap.log` in-guest; redo step 2b.3 |
| Windows VM won't network | Missing VirtIO net driver | Step 2b.2 |

## Deploying to a CLOUD-hosted Proxmox from a REMOTE machine

The provider assumes a bare-metal Proxmox on the same LAN as the deploy host. If
Proxmox itself runs on a cloud VM (e.g. an Azure VM, nested-virt-capable size)
and you deploy from elsewhere over the internet, a few host/topology items are
NOT auto-generated (they're per-host, like `host.auto.tfvars.json`):

- **Nested virt**: the cloud VM size must expose VT-x to the guest (Azure Dsv3+).
  Confirm `/dev/kvm` exists on the Proxmox host.
- **Disk**: use a fast disk (Azure Premium SSD, not Standard) — nested Windows on
  a slow disk crawls. Clones are now LINKED by default (`full_clone=false`), so a
  disk big enough for the templates + thin clones suffices.
- **Firewall/NSG**: open inbound **UDP 51820** (WireGuard) and **TCP 2222**
  (bastion SSH via DNAT) to the Proxmox host, plus 22/8006 for admin.
- **Host NAT/DNAT** (so a remote deploy host reaches the internal bastion):
  `iptables -t nat -A PREROUTING -i <wan> -p udp --dport 51820 -j DNAT --to <bastion-ip>:51820`,
  same for `tcp --dport 2222 -> <bastion-ip>:22`, plus a `POSTROUTING ... -o vmbr0
  -d <bastion-ip> -p tcp --dport 22 -j MASQUERADE` so the bastion's deny-by-default
  firewall sees the host IP (it only opens 51820 to the world otherwise). Persist
  with `netfilter-persistent`.
- **deploy.sh from a remote host**: point the WireGuard endpoint + bastion SSH at
  the Proxmox host's PUBLIC ip and port 2222 — set `BASTION_IP` to the public IP
  in `wg_up`/`route_lab` and add `-p 2222` to the bastion `ssh`.
- **bpg SSH to the node** (snippet uploads): the API token isn't enough — bpg SSHes
  to the node. On a cloud host the node reports its INTERNAL ip, unreachable from
  a remote deploy host, so override it in `terraform/proxmox/versions.tf`:
  `provider "proxmox" { ssh { node { name = "<node>" address = "<public-ip>" } } }`
  and export `PROXMOX_VE_SSH_USERNAME=root` + `PROXMOX_VE_SSH_PRIVATE_KEY` (add
  your key to the node's `/root/.ssh/authorized_keys`, `PermitRootLogin prohibit-password`).

## Windows template account hygiene (avoids a DC-promotion failure)

`windows-bootstrap.ps1.tpl` creates the `purpleforge` + `ansible` accounts at
first boot, and GOAD's `domain_controller` role RENAMES `purpleforge` -> the
domain `Administrator` at promotion. So the template must NOT leave a second
account already named `Administrator` enabled, and cloudbase-init must NOT create
its own extra admin (set `username` in `cloudbase-init.conf` to `purpleforge`,
not `Admin`). If the built-in Administrator is enabled in your golden image,
disable or rename it before `qm template`, or promotion fails with
`Rename-LocalUser : The name Administrator is already in use`.
