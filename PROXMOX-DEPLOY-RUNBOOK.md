# Proxmox VE deploy runbook

A procedural, copy-pasteable checklist for taking a **fresh Proxmox VE
install** (nothing configured beyond the hypervisor itself) to a live,
fully-configured PurpleForge lab. Unlike `AZURE-DEPLOY-RUNBOOK.md` (written
after a real end-to-end Azure deploy), this file has **not yet been
validated against a live Proxmox deploy** — iteration 1/2 delivered and
`terraform validate`-checked the Terraform layer + deploy scripts, but no
one has run `deploy.sh` against a real PVE host yet (iteration 3). Treat
steps 0-2 (host prep) as solid — they're standard Proxmox administration,
independent of PurpleForge. Treat steps 3 onward as the harness's own
documented behavior, not yet battle-tested; expect to hit and fix a few
real gotchas the way the Azure runbook did, and fold them back into this
file once found.

For the underlying design (why cloudbase-init, why a local Terraform
backend, the networking model), see
[`.claude/skills/infra-proxmox/SKILL.md`](.claude/skills/infra-proxmox/SKILL.md)
and [`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md) — this file is the
short, ordered version.

---

## 0. Prerequisites on the deploy host (one-time per machine)

The **deploy host** is wherever you run `./generated/<lab>/deploy.sh` from —
it does NOT need to be the Proxmox host itself, only network-reachable to
it. Same tool sets as Azure, minus `az`:

```bash
which terraform wg openssl curl python3 docker ssh || echo "install whichever is missing"
docker run --rm python:3.10-slim python3 --version   # confirms docker works, pre-pulls the image
```

`wg` is `wireguard-tools`; `ssh` needs to be a real OpenSSH client (the
deploy reaches the bastion over SSH to bring up the tunnel, unlike Azure
which only needs `az`). `ansible-core` itself is **not** installed on the
host — same reasoning as Azure (GOAD pins `ansible-core==2.12.6`, Python
3.8-3.10 only); Ansible runs inside the `pf-ansible` Docker container
`deploy.sh` manages, not on the host.

Confirm you can reach the Proxmox API and that you'll be able to reach the
bastion once it exists:

```bash
curl -sk https://<proxmox-host>:8006/api2/json/version   # -k for self-signed certs
# expect a JSON blob with a "version" key, even unauthenticated
```

If this hangs or refuses, fix routing/firewalling before anything else —
nothing past this point works without it.

**Nested virtualization, if Proxmox itself runs inside another
hypervisor** (VirtualBox, VMware, another Proxmox/KVM host, a cloud VM):
Proxmox's own VMs (the Windows templates, the bastion) need real
virtualization extensions passed through, or they won't boot at all or will
run in unusably slow software emulation. In VirtualBox: the Proxmox VM's
*Settings → System → Processor → "Enable Nested VT-x/AMD-V"* must be
checked. Equivalent settings exist for VMware (Virtualize Intel
VT-x/EPT) and other hypervisors. Confirm from inside Proxmox before
building anything:

```bash
# on the Proxmox host itself (SSH or console)
cat /proc/cpuinfo | grep -E 'vmx|svm' | head -1   # non-empty = CPU flags are visible
```

A definitive check is starting any VM (once you have one — e.g. the bastion
template in step 2a, before you `qm template` it) and confirming it actually
boots to a login/console rather than hanging or timing out.

---

## 1. Prepare the Proxmox host itself

Everything in this step is done **once**, via the Proxmox web UI (or `pvesh`/
API equivalents), and is completely independent of PurpleForge — a normal
Proxmox admin would recognize all of it.

### 1a. Network bridges

You need **two** bridges (or one, if you're deliberately not isolating the
lab network from management — not recommended, breaks CLAUDE.md invariant
#1):

| Bridge | Purpose | How to create |
|---|---|---|
| `vmbr0` (usually exists already) | **Management** — routable, where the Proxmox host's own IP lives and where the bastion gets its external address | Already created by the Proxmox installer in almost all cases |
| `vmbr1` (new) | **Lab** — isolated, no physical port, no uplink; every AD/Windows VM lives here, VLAN-tagged per domain | Datacenter → *node* → System → Network → Create → Linux Bridge. Leave "Bridge ports" **empty** — it must not reach any physical NIC or the outside world. |

Confirm both exist: `ip link show type bridge` on the Proxmox host, or
Datacenter → *node* → Network in the web UI.

### 1b. Storage: enable the Snippets content type

The cloudbase-init/WireGuard first-boot scripts are uploaded as Proxmox
*snippets*, which needs a storage backend with that content type enabled
(usually the default `local` storage, which supports it but doesn't enable
it by default):

Datacenter → Storage → `local` → Edit → Content → check **Snippets** → OK.

```bash
# equivalent via pvesh, if you'd rather not use the UI:
pvesh set /storage/local --content backup,iso,vztmpl,snippets
```

### 1c. API token

Datacenter → Permissions → API Tokens → Add:

- **User**: an existing user (e.g. `root@pam`) or create a dedicated
  `purpleforge@pve` user first (Datacenter → Permissions → Users).
- **Token ID**: anything, e.g. `purpleforge`.
- **Privilege Separation**: uncheck for a first pass (the token inherits the
  user's full rights) — scope it down later once you know exactly which
  privileges the `bpg/proxmox` provider actually exercises (VM
  create/clone/start/stop, pool management, snippet upload, firewall rule
  management).

Copy the **full token string** shown once (`user@realm!tokenid=uuid`) — it
is not retrievable again.

```bash
export PROXMOX_VE_ENDPOINT="https://<proxmox-host>:8006/"
export PROXMOX_VE_API_TOKEN="purpleforge@pve!purpleforge=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export PROXMOX_VE_INSECURE=true    # only if the PVE cert is self-signed (it is, by default)
```

Verify the token works before going further:

```bash
curl -sk -H "Authorization: PVEAPIToken=$PROXMOX_VE_API_TOKEN" \
  "$PROXMOX_VE_ENDPOINT/api2/json/nodes" | python3 -m json.tool
```

Expect a JSON list with your node in it. An empty/error response here means
the token or its permissions are wrong — fix it now, not after `terraform
apply` fails opaquely.

### 1d. Note your node name

```bash
pvesh get /nodes
# or: hostname   (run on the Proxmox host)
```

You'll need this exact string for `host.auto.tfvars.json`'s `node_name`.

---

## 2. Build the two templates

Both are one-time per Proxmox host (or per OS version you want to offer).
**Do this before writing the spec** — you need the resulting `vm_id`s.

### 2a. Bastion template (Ubuntu 22.04+, cloud-init) — the easy one

Standard Proxmox cloud-init image import, no GUI install needed:

```bash
# on the Proxmox host
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
qm create 9000 --name ubuntu-2204-cloudinit-template --memory 1024 --cores 1 --net0 virtio,bridge=vmbr0
qm importdisk 9000 jammy-server-cloudimg-amd64.img local-lvm
qm set 9000 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-9000-disk-0
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --boot c --bootdisk scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1              # qemu-guest-agent, required
qm template 9000
```

Record `9000` (or whatever vm_id you used) as `bastion_template_id`.

### 2b. Windows template — the real lift

Full checklist already written in
[`IMAGES-AND-TEMPLATES.md`](IMAGES-AND-TEMPLATES.md#building-a-minimal-template-checklist).
Summary:

1. Install Windows Server (2019/2022 — whichever `machines[].os` you'll
   use) as a normal VM in Proxmox, from an ISO.
2. During/after install, add the **VirtIO driver ISO**
   ([Fedora's virtio-win](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/))
   so disk/network work under KVM at all.
3. Install **cloudbase-init** ([cloudbase.it](https://cloudbase.it/cloudbase-init/)),
   keeping the default plugin set (includes `UserDataPlugin` — do not
   disable it; it's the ONE thing this whole bootstrap depends on).
4. Generalize the image (`sysprep /generalize /oobe /shutdown`, or
   cloudbase-init's own "Run Sysprep" checkbox at first boot before
   shutdown) and power off.
5. Convert to a template:
   ```bash
   qm template <vmid>
   ```
6. Record the `vm_id` under the matching `os` key for
   `host.auto.tfvars.json`'s `template_map` (e.g.
   `"windows-server-2019": 9001`).

**Do NOT** install WinRM, create an `ansible`/`purpleforge` account, or set
any passwords in the template — `windows-bootstrap.ps1.tpl` does all of
that at first boot, and doing it in the template just adds drift risk.

Repeat for every `os` your specs will use (a lab can mix, e.g. a
2019 DC + a Windows 11 workstation both need their own template).

---

## 3. Write and validate the spec

Use `lab.provider: proxmox`. Start from
[`specs/examples/single-dc-proxmox.yml`](specs/examples/single-dc-proxmox.yml)
(smallest possible: one domain, one DC, no vulns) for the very first live
deploy — prove the pipeline works before adding population/vulns/hardening.

```bash
python3 scripts/forge.py lab-spec specs/examples/single-dc-proxmox.yml
```

Fix any schema/reconciliation errors before continuing.

---

## 4. Generate, then fill the host binding

```bash
python3 scripts/forge.py generate specs/examples/single-dc-proxmox.yml
cp generated/single-dc-proxmox-test/terraform/proxmox/host.auto.tfvars.example.json \
   generated/single-dc-proxmox-test/terraform/proxmox/host.auto.tfvars.json
```

Edit the copy with what you gathered in steps 1-2:

| Key | Value |
|---|---|
| `node_name` | from step 1d |
| `datastore_id` | where VM disks live, e.g. `local-lvm` |
| `snippets_datastore_id` | the storage from step 1b, e.g. `local` |
| `mgmt_bridge` | `vmbr0` |
| `lab_bridge` | `vmbr1` |
| `template_map` | `{"windows-server-2019": 9001, ...}` — from step 2b |
| `bastion_template_id` | from step 2a (e.g. `9000`) |
| `jumpbox_external_ip` / `_prefix` / `_gateway` | the bastion's static address on `vmbr0` — pick a free IP on that subnet, its CIDR prefix, and the gateway your management network actually uses |

This file is gitignored (per-deployer) — never commit it. `host.auto.tfvars.example.json`
(committed) documents the shape for the next person.

---

## 5. Deploy

```bash
./generated/single-dc-proxmox-test/deploy.sh
```

What it does, in order (per `templates/deploy-proxmox.sh.j2`): preflight
(checks `PROXMOX_VE_ENDPOINT`/`_API_TOKEN` are set and `host.auto.tfvars.json`
exists) → infra secrets → `terraform init/apply` (local state — no remote
backend to wire up, unlike Azure) → WireGuard tunnel to the bastion → bring
up the `pf-ansible` Docker container → wait for WinRM on every host → run
`site.yml` → (best-effort) install the `auto_shutdown` cron.

Since this exact path is unvalidated against a real host as of this
writing, expect to actually watch it run rather than trusting it blindly —
watch for:

- **terraform apply errors mentioning the API token/permissions** → back to
  step 1c, the token most likely lacks a required privilege (pool
  management, snippet write, or VM clone on the template's own path).
- **VM clone failures** → the template's vm_id in `host.auto.tfvars.json`
  doesn't exist, or isn't actually marked as a template (`qm template
  <vmid>` must have been run).
- **WireGuard tunnel never comes up** → `jumpbox_external_ip` isn't actually
  reachable from the deploy host (wrong subnet/gateway in step 4, or a
  firewall between the two), or the bastion VM failed to boot (check its
  console in the Proxmox UI).
- **WinRM never comes up on a Windows host** → check
  `C:\pf-bootstrap.log` inside the guest via the Proxmox console — if it's
  empty/missing, cloudbase-init's `UserDataPlugin` isn't enabled in the
  template (back to step 2b.3).

---

## 6. Verify, then teardown when done

```bash
python3 scripts/forge.py validate specs/examples/single-dc-proxmox.yml --run
./generated/single-dc-proxmox-test/teardown.sh
```

Proxmox has no per-hour billing to verify to zero the way Azure does, but
`teardown.sh` still removes the pool/VMs/firewall rules and the local
Terraform state so the lab leaves no trace on the host.

---

## Known limitations (carry these into iteration 3's findings)

- `auto_shutdown` is a best-effort cron on the **deploy host** (not the
  Proxmox host) hitting the API — it only fires while the deploy host is
  up, unlike Azure's native DevTest schedule.
- The bastion's per-domain VLAN sub-interfaces (`route_lab` step) are
  reasserted on every `deploy.sh` run but are not persistent across a
  bastion **reboot** on its own.
- Multi-domain trust routing through the bastion has not been exercised on
  a live deploy.
- This whole file is pre-first-deploy documentation — update it (steps 5-6
  especially) with whatever actually breaks on the first real run, the same
  way `AZURE-DEPLOY-RUNBOOK.md` was written from real scar tissue.

---

## Quick-reference: symptom → cause

| Symptom | Cause | Fix |
|---|---|---|
| `curl .../api2/json/version` hangs or refuses | Network/firewall between deploy host and Proxmox | Fix routing before anything else |
| Proxmox VMs won't start / start but crawl | No nested virtualization | Enable VT-x/AMD-V passthrough in the outer hypervisor (step 0) |
| `terraform apply` fails on token/permission errors | API token missing a privilege | Re-check step 1c; simplest fix is un-scoping the token (no Privilege Separation) |
| Snippet upload fails | Snippets content type not enabled on the target storage | Step 1b |
| VM clone fails, template not found | Wrong `vm_id` in `template_map`/`bastion_template_id`, or source VM was never `qm template`'d | Step 2, confirm with `qm list` |
| WireGuard tunnel never comes up | `jumpbox_external_ip`/`_gateway` wrong, or bastion never booted | Step 4 values, then check bastion console |
| WinRM never comes up on a Windows guest | cloudbase-init/UserDataPlugin not enabled in the template | Check `C:\pf-bootstrap.log` in-guest; redo step 2b.3 |
| Windows VM won't network at all | Missing VirtIO network driver in the template | Step 2b.2 |
