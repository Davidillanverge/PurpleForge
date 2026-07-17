# Images & templates: customising what backs each VM

Which OS image/template a lab's Windows VMs boot from, and how to change it without
editing the spec or regenerating — both providers (Azure marketplace/custom,
Proxmox template clones) plus the Proxmox first-boot bootstrap.

One-liner: to redeploy an already-built lab on a newer image, export a `PF_*`
variable and re-run `deploy.sh`:

```bash
PF_OS=windows-server-2022 ./generated/<lab>/deploy.sh          # Azure, stock image
PF_IMAGE_ID=/subscriptions/.../versions/1.0.0 ./generated/<lab>/deploy.sh   # Azure, custom
PF_TEMPLATE_ID=9002 ./generated/<lab>/deploy.sh                # Proxmox, different template
```

## Mental model: `os` ≠ image ≠ hardening

| Concept | Drives | Set at |
|---|---|---|
| **`machines[].os`** | the ansible-lockdown role + OS-specific Ansible behavior | spec (generate) |
| **backing image** | which bits boot (marketplace SKU / managed image / Proxmox template) | spec pin **or** deploy-time `PF_*` |
| **hardening baseline** | which CIS/STIG rules apply | `defense.hardening` (generate) |

**Swapping the image does NOT change the hardening baseline** — `os` still selects
the ansible-lockdown role regardless of image. `PF_OS=windows-server-2022` on a lab
generated for 2016 boots a 2022 image but applies the 2016-targeted baseline. For a
different baseline, change `machines[].os`/`defense.hardening` and regenerate (not a
deploy-time knob by design — reconciliation is computed at generate time, invariant
#3). Same reason `image_id`/`template_id` keep `os` required.

## Two ways to customise

**1. Per-machine pin in the spec (generate time)** — baked into the generated lab,
survives sharing. Use when the image is part of the lab (e.g. a golden EDR-baked
workstation).

```yaml
machines:
  - role: workstation
    os: windows-11-23h2        # still required
    domain: kingdom.local
    count: 2
    image_id: "/subscriptions/<sub>/.../galleries/<g>/images/<def>/versions/<ver>"   # Azure
    # template_id: 9020        # Proxmox: a specific template vm_id instead
```

Azure `image_id` = a managed image or SIG version (`infra-azure` swaps in
`source_image_id`, mutually exclusive with the marketplace reference). Proxmox
`template_id` = a specific template to clone instead of the `os`→`template_map`
lookup. Field is provider-agnostic for a future AWS AMI.

**2. Deploy-time override (no regenerate)** — swaps the image for **every** Windows
VM. `deploy.sh` turns `PF_*` into a gitignored `*.auto.tfvars.json` overlay over the
committed `terraform.tfvars.json` (same idiom as `PF_REGION`/`PF_VM_SIZE`); unset +
re-run reverts.

Azure:

| Variable | Effect |
|---|---|
| `PF_OS=<key>` | stock key: `windows-server-2016\|2019\|2022\|2025`, `windows-10-22h2`, `windows-11-23h2` |
| `PF_IMAGE_ID=<resource-id>` | managed image / SIG version; **wins over `PF_OS`** |
| `PF_IMAGE_PUBLISHER`+`PF_IMAGE_OFFER`+`PF_IMAGE_SKU` | a marketplace image with no built-in key (set all three) |
| `PF_IMAGE_VERSION=<ver>` | pin the marketplace version (default `latest`) |

Proxmox: `PF_TEMPLATE_ID=<vmid>` clones every Windows VM from that template
(overriding `template_map`). Template still needs cloudbase-init.

**Precedence** (most specific wins):

```
Azure image_id : machines[].image_id (spec) > PF_IMAGE_ID
Azure os       : PF_OS > machines[].os (spec)   (a resolved image_id always wins over any os)
Proxmox template: machines[].template_id (spec) > PF_TEMPLATE_ID > template_map[os]
```

Overlays are gitignored and re-derived each run — never commit them.

## Azure image reference (`local.os_image_map` in `windows.tf`)

| `os` key | publisher / offer / sku |
|---|---|
| `windows-server-2016` | MicrosoftWindowsServer / WindowsServer / `2016-datacenter-gensecond` |
| `windows-server-2019` | MicrosoftWindowsServer / WindowsServer / `2019-datacenter-gensecond` |
| `windows-server-2022` | MicrosoftWindowsServer / WindowsServer / `2022-datacenter-g2` |
| `windows-server-2025` | MicrosoftWindowsServer / WindowsServer / `2025-datacenter-g2` |
| `windows-10-22h2` | MicrosoftWindowsDesktop / Windows-10 / `win10-22h2-pro-g2` |
| `windows-11-23h2` | MicrosoftWindowsDesktop / Windows-11 / `win11-23h2-avd` |

`PF_IMAGE_PUBLISHER`/`OFFER`/`SKU` merge a new entry at deploy time
(`custom_os_images`). Gotchas baked into these choices (see `windows.tf`):

- **All server SKUs are Gen2** (`-gensecond` 2016/2019, `-g2` 2022/2025) — newer
  size families (Fasv7) are Gen2-only. The suffix isn't consistent across versions.
- **NVMe:** Fasv7/Dsv7/Esv7 are NVMe-only; 2019/2022/2025 + client SKUs support it,
  **2016 does not** (SCSI only) — a 2016 DC can't run on an NVMe-only size.
- **Client OS (Win 10/11)** needs a marketplace agreement, accepted automatically
  (`azurerm_marketplace_agreement.client_os`) for the effective os.
  `windows-11-23h2` → `-avd` deliberately (`-pro` has zero published versions);
  still deploys as an ordinary VM.
- Custom `PF_IMAGE_ID` skips all of the above — you own gen/NVMe/agreement.

## Proxmox templates + first-boot bootstrap

No marketplace, no VM extension — VMs are **cloned from templates you maintain**
(`var.template_map` by `os`).

**The ONE prerequisite: cloudbase-init** (with `UserDataPlugin` enabled). Needed to
apply the static IP AND run the first-boot user-data. **WinRM and the `ansible`
account are NOT baked in** — `windows-bootstrap.ps1.tpl` (uploaded once as a
snippet, referenced by every VM, run as SYSTEM at first boot) creates the
`purpleforge`/`ansible` local admins + passwords, stands up a WinRM HTTPS 5986
listener (self-signed cert, Basic auth — matching the inventory), and opens a
firewall rule for 5986 scoped to the lab supernet. It's:

- **Idempotent** — a legacy template with WinRM pre-baked still deploys unchanged.
- **Fully offline** — the lab bridge has no uplink, so WinRM setup is inlined, not
  downloaded (unlike Azure's `ConfigureRemotingForAnsible.ps1`).

**Why cloudbase-init is an unavoidable floor:** a guest with zero in-guest agents
exposes no channel to configure it (cloud-init drive needs cloudbase-init,
`guest-exec` needs qemu-guest-agent, network mgmt needs WinRM up). A QEMU/Windows
reality. cloudbase-init is the lightest floor that also carries the static IP. (The
`autounattend.xml`/Packer ISO alternative is the path the project deliberately
skips — heavier, still bakes WinRM.)

**Minimal template checklist** (manual, one-time per `os`):

1. Install Windows Server (any `os`) as a normal VM. A **SATA** system disk skips
   needing the VirtIO storage driver at install time.
2. Install **virtio drivers** + guest tools (disk/net under KVM; `qemu-guest-agent`
   too — it lets you salvage a stuck build with `qm guest exec`).
3. Install **cloudbase-init**, default plugins (incl. `UserDataPlugin`,
   `SetHostNamePlugin`, `SetUserPasswordPlugin`); metadata service →
   ConfigDrive/NoCloud. **The build VM needs internet here** (the MSI is
   downloaded) — on an isolated/no-DHCP bridge it gets APIPA `169.254.x.x` and the
   download silently fails; build on a bridge with uplink or set a static IP+DNS
   first (or pre-stage the MSI offline).
4. Generalize (sysprep `/generalize /oobe /shutdown /unattend:<path>`), then
   `qm template`. **sysprep rejects a `/unattend:` path containing spaces**
   ("Malformed command line ... no dash or slash present in option /") — copy the
   Unattend.xml to a no-space path (e.g. `C:\Windows\Temp\cbi-unattend.xml`) and
   point sysprep there.
5. Record its vm_id in `template_map` under the matching `os`.

No WinRM config, no `ansible` user, no manual PowerShell. **Account hygiene:** don't
leave a second enabled `Administrator` or an extra cloudbase-init admin in the golden
image — GOAD renames `purpleforge`→`Administrator` at DC promotion and a name clash
fails it (`cloudbase-init.conf` `username` = `purpleforge`, not `Admin`). See the
account-hygiene section in `PROXMOX-DEPLOY-RUNBOOK.md`.

*Eval-ISO note:* the WS2022 eval build 20348.169 predates Windows LAPS; the generator
probes and skips LAPS gracefully on such images, so no manual action is needed.

**Troubleshooting the bootstrap:**

- Transcript at **`C:\pf-bootstrap.log`** in-guest — first place to look if WinRM
  never comes up.
- `deploy.sh` waits ~6–7 min for WinRM before `site.yml`; a first boot finishes well
  inside that. Timeout → check the log via the Proxmox console.
- Nothing ran → `UserDataPlugin` disabled, or the metadata service isn't reading the
  Proxmox cloud-init drive (re-check step 3).
- `New-LocalUser`/`New-SelfSignedCertificate` need Server 2016+ / PS 5.1 (fine for
  every `os` in the schema).

## Where each thing lives

| Artifact | Purpose |
|---|---|
| `templates/terraform/azure/windows.tf` | `os_image_map`, effective-os/image resolution, `custom_os_images` merge |
| `templates/terraform/azure/variables.tf` | `os_overrides`, `image_id_overrides`, `custom_os_images`, `image_version_override` |
| `templates/deploy.sh.j2` → `pick_images()` | writes `images.auto.tfvars.json` from `PF_OS`/`PF_IMAGE_*` |
| `templates/terraform/proxmox/windows.tf` | template resolution, `windows_bootstrap` snippet + `user_data_file_id` |
| `templates/terraform/proxmox/variables.tf` | `template_id_overrides` |
| `templates/terraform/proxmox/cloudinit/windows-bootstrap.ps1.tpl` | first-boot WinRM + accounts bootstrap |
| `templates/deploy-proxmox.sh.j2` → `pick_template()` | writes `template.auto.tfvars.json` from `PF_TEMPLATE_ID` |

See also: `README.md`, `PROXMOX-DEPLOY-RUNBOOK.md`, `infra-azure/SKILL.md`,
`infra-proxmox/SKILL.md`.
