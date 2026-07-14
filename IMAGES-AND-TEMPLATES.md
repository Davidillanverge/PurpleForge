# Images & templates: customising what backs each VM

Everything about **which OS image or template a lab's Windows VMs boot from**,
and how to change it without editing the spec or regenerating. Covers both
providers (Azure marketplace/custom images, Proxmox template clones) and the
Proxmox first-boot bootstrap that removes the "golden template" requirement.

If you just want the one-liner: to redeploy an already-built lab on a newer
Windows image, export a `PF_*` variable and run `deploy.sh` — nothing else
changes.

```bash
PF_OS=windows-server-2022 ./generated/<lab>/deploy.sh          # Azure, stock image
PF_IMAGE_ID=/subscriptions/.../versions/1.0.0 ./generated/<lab>/deploy.sh   # Azure, custom image
PF_TEMPLATE_ID=9002 ./generated/<lab>/deploy.sh                # Proxmox, different template
```

---

## The mental model: `os` ≠ image ≠ hardening

Three things are deliberately decoupled:

| Concept | What it drives | Where it's set |
|---|---|---|
| **`machines[].os`** | the ansible-lockdown role + OS-specific Ansible behaviour | the spec (generate time) |
| **the backing image** | which bits actually boot (marketplace SKU / managed image / Proxmox template) | spec pin **or** deploy-time `PF_*` override |
| **the hardening baseline** | which CIS/STIG rules get applied | `defense.hardening` in the spec (generate time) |

The key consequence: **swapping the image does not change the hardening
baseline.** `os` still selects the ansible-lockdown role regardless of what
image backs the VM. So `PF_OS=windows-server-2022` on a lab generated for 2016
boots a 2022 image but still applies the *2016*-targeted baseline that was
resolved at generate time. If you want a different CIS/STIG baseline, change
`machines[].os` / `defense.hardening` in the spec and regenerate — that is not a
deploy-time knob by design (the reconciliation between hardening and the
injected vulnerabilities is computed at generate time; see CLAUDE.md invariant
#3).

This is the same reason `image_id`/`template_id` in the spec keep `os`
required: the image is "what backs the VM", `os` is "how Ansible treats it".

---

## Two ways to customise

### 1. Per-machine pin in the spec (generate time)

Point one machine group at a specific image, baked into the generated lab.
Survives sharing (it's in the committed `terraform.tfvars.json`). Use this when
the image is part of the lab's definition — e.g. a golden workstation with an
EDR agent pre-installed.

```yaml
machines:
  - role: workstation
    os: windows-11-23h2        # still required
    domain: kingdom.local
    count: 2
    image_id: "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/galleries/<g>/images/<def>/versions/<ver>"   # Azure
    # template_id: 9020        # Proxmox: a specific template vm_id instead
```

- Azure `image_id`: a managed image **or** a Shared Image Gallery version
  resource ID. `infra-azure` swaps in `source_image_id` for that group (mutually
  exclusive with the marketplace `source_image_reference`).
- Proxmox `template_id`: a specific template vm_id to clone for that group,
  instead of the `os`→`template_map` lookup.
- The field is provider-agnostic (`image_id`, not `azure_image_id`) so it can
  hold an AWS AMI id once `infra-aws` exists.

### 2. Deploy-time override (no regenerate)

Swap the backing image for **every** Windows VM at deploy time, without
touching the spec or the committed artifacts. `deploy.sh` turns the `PF_*`
variables into a gitignored `*.auto.tfvars.json` overlay that Terraform loads
over the committed `terraform.tfvars.json` — the same idiom already used for
`PF_REGION` / `PF_VM_SIZE`. Unset the variable and re-run and the overlay is
removed, reverting to the generate-time image.

#### Azure

| Variable | Effect |
|---|---|
| `PF_OS=<key>` | stock image key: `windows-server-2016\|2019\|2022\|2025`, `windows-10-22h2`, `windows-11-23h2` |
| `PF_IMAGE_ID=<resource-id>` | clone a managed image / Shared Image Gallery version; **wins over `PF_OS`** |
| `PF_IMAGE_PUBLISHER` + `PF_IMAGE_OFFER` + `PF_IMAGE_SKU` | a marketplace image with no built-in key (set **all three**; `PF_OS`, if also set, names the key) |
| `PF_IMAGE_VERSION=<ver>` | pin the marketplace image version (default `latest`) |

```bash
# same generated lab, on Windows Server 2022:
PF_OS=windows-server-2022 ./generated/<lab>/deploy.sh
# on a custom golden image (EDR pre-installed):
PF_IMAGE_ID=/subscriptions/.../galleries/g/images/win2022-edr/versions/1.0.0 ./generated/<lab>/deploy.sh
# on a marketplace image PurpleForge has no key for, pinned to a version:
PF_IMAGE_PUBLISHER=MicrosoftWindowsServer PF_IMAGE_OFFER=WindowsServer \
  PF_IMAGE_SKU=2022-datacenter-azure-edition PF_IMAGE_VERSION=20348.2113.231001 \
  ./generated/<lab>/deploy.sh
```

Under the hood these become `os_overrides`, `image_id_overrides`,
`custom_os_images`, and `image_version_override` in
`terraform/azure/images.auto.tfvars.json`.

#### Proxmox

| Variable | Effect |
|---|---|
| `PF_TEMPLATE_ID=<vmid>` | clone **every** Windows VM from this template vm_id, overriding the `os`→`template_map` lookup |

```bash
PF_TEMPLATE_ID=9002 ./generated/<lab>/deploy.sh
```

Becomes `template_id_overrides` in `terraform/proxmox/template.auto.tfvars.json`.
The template still needs cloudbase-init (see the Proxmox section below).

### Precedence

Most specific wins. A per-machine pin in the spec always beats a deploy-time
`PF_*` override, so a lab that deliberately pins one group's image can still be
bulk-redeployed on a different base image for everything else.

```
Azure image_id : machines[].image_id (spec)  >  PF_IMAGE_ID (per-role override)
Azure os       : PF_OS (per-role override)    >  machines[].os (spec)
                 └─ a resolved image_id always wins over any os (mutually exclusive)
Proxmox template: machines[].template_id (spec) > PF_TEMPLATE_ID > template_map[os]
```

The `*.auto.tfvars.json` overlays are gitignored (per-deployer, deploy-time
state) and re-derived on every run — never commit them.

---

## Azure image reference

`infra-azure` maps each `os` key to a first-party marketplace publisher/offer/
sku in `templates/terraform/azure/windows.tf`'s `local.os_image_map`:

| `os` key | publisher / offer / sku |
|---|---|
| `windows-server-2016` | MicrosoftWindowsServer / WindowsServer / `2016-datacenter-gensecond` |
| `windows-server-2019` | MicrosoftWindowsServer / WindowsServer / `2019-datacenter-gensecond` |
| `windows-server-2022` | MicrosoftWindowsServer / WindowsServer / `2022-datacenter-g2` |
| `windows-server-2025` | MicrosoftWindowsServer / WindowsServer / `2025-datacenter-g2` |
| `windows-10-22h2` | MicrosoftWindowsDesktop / Windows-10 / `win10-22h2-pro-g2` |
| `windows-11-23h2` | MicrosoftWindowsDesktop / Windows-11 / `win11-23h2-avd` |

`PF_IMAGE_PUBLISHER`/`OFFER`/`SKU` merge a new entry into this map at deploy
time (`custom_os_images`), so you can name any Windows image without editing the
file. Gotchas baked into these choices (verified on real deploys — see the long
comment in `windows.tf`):

- **Every server SKU is Hyper-V Gen2** (`-gensecond` for 2016/2019, `-g2` for
  2022/2025). Newer VM size families (Fasv7 etc., which restricted subscriptions
  are pushed onto) are Gen2-only and reject a Gen1 SKU. The Gen2 suffix is **not**
  consistent across versions — verify a new key against the live SKU listing.
- **NVMe:** the Fasv7/Dsv7/Esv7 families are NVMe-only, and the image must
  declare NVMe support. 2019/2022/2025 and the client SKUs do; **2016 does not**
  (SCSI only) — a 2016 DC can't run on an NVMe-only size. Pick 2019+ there.
- **Client OS (Windows 10/11)** needs a per-publisher/offer/plan
  `Microsoft.MarketplaceOrdering` agreement, which Terraform accepts
  automatically (`azurerm_marketplace_agreement.client_os`) — but only for the
  *effective* os, so a `PF_OS` swap onto a client SKU still accepts the right
  one. `windows-11-23h2` maps to the `-avd` SKU deliberately (the `-pro` SKU has
  zero published image versions); it still deploys as an ordinary standalone VM.
- Custom `PF_IMAGE_ID` (managed image / SIG) skips all of the above — you own
  the image's generation/NVMe/agreement correctness.

---

## Proxmox templates & the first-boot bootstrap

On Proxmox there is no marketplace and no VM extension, so Windows VMs are
**cloned from templates you maintain** (`var.template_map`, keyed by
`machines[].os`, in the per-host `host.auto.tfvars.json`).

### The ONE template prerequisite: cloudbase-init

A template must have exactly one thing baked in:

1. **cloudbase-init**, with its `UserDataPlugin` enabled (the default plugin
   set). It is needed to apply the static IP Terraform assigns **and** to run
   the first-boot user-data that does everything else.

**WinRM and the `ansible` account are NOT required in the template.** They are
bootstrapped at first boot by
`terraform/proxmox/cloudinit/windows-bootstrap.ps1.tpl`, which Terraform uploads
once as a Proxmox snippet (`proxmox_virtual_environment_file.windows_bootstrap`)
and references from every Windows VM's `initialization.user_data_file_id`.
cloudbase-init runs it as SYSTEM on first boot. It is the on-prem twin of the
Azure layer's `ConfigureRemotingForAnsible.ps1` CustomScriptExtension.

The script:

- creates the `purpleforge` (domain-admin-to-be) and `ansible` (WinRM
  automation) local admin accounts and sets their passwords;
- stands up a **WinRM HTTPS listener on 5986** with a **self-signed cert** and
  **Basic auth** — exactly what the Ansible inventory expects (`ansible_port:
  5986`, `ansible_winrm_transport: basic`, `ansible_winrm_server_cert_validation:
  ignore`);
- opens a firewall rule for 5986 scoped to the lab supernet only.

Two properties matter:

- **Idempotent** — a legacy template that *does* have WinRM + `ansible` baked in
  still deploys unchanged (the script re-asserts, it doesn't conflict).
- **Fully offline** — the lab bridge has no internet uplink, so the WinRM setup
  is inlined in the script, never downloaded (unlike Azure, whose VMs have
  outbound internet and fetch `ConfigureRemotingForAnsible.ps1` from GitHub).

### Why cloudbase-init is an unavoidable floor

You cannot go lower than "one baked-in agent". A Windows guest with **zero**
in-guest agents — no cloudbase-init, no qemu-guest-agent, no pre-enabled
WinRM/SSH — exposes no channel for the hypervisor or the network to configure
it: the cloud-init drive needs cloudbase-init to read it, `guest-exec` needs
qemu-guest-agent, and network management needs WinRM already up with
credentials. This is a QEMU/Windows reality, not a PurpleForge limitation. Of
the possible floors, cloudbase-init is the lightest that also carries the static
IP, so it's the one we require.

(The alternative — an `autounattend.xml` ISO install that bakes WinRM during
Windows setup — is the Packer/ISO path the project deliberately does not do; it
is heavier and still ends up baking WinRM.)

### Building a minimal template (checklist)

1. Install Windows Server (any `os` you'll reference) as a normal VM.
2. Install **virtio drivers** (disk/net) so it boots and networks under KVM.
3. Install **cloudbase-init**; keep the default plugin set (which includes
   `UserDataPlugin`, `SetHostNamePlugin`, `SetUserPasswordPlugin`). Point its
   metadata service at ConfigDrive/NoCloud (the Proxmox cloud-init drive).
4. Generalise (sysprep `/generalize /oobe` or cloudbase-init's own
   image-prep), shut down, and convert the VM to a **template**.
5. Record its `vm_id` in `host.auto.tfvars.json`'s `template_map` under the
   matching `os` key.

That's it — no WinRM config, no `ansible` user, no manual PowerShell.

### Troubleshooting the bootstrap

- The script writes a transcript to **`C:\pf-bootstrap.log`** inside the guest —
  the first place to look if WinRM never comes up.
- `deploy.sh` waits for WinRM (`win_ping`) for ~6–7 minutes before running
  `site.yml`; a first boot + cloudbase-init run normally finishes well inside
  that. If it times out, check the log via the Proxmox console.
- If nothing in the log ran: cloudbase-init's `UserDataPlugin` is disabled in
  the template, or its metadata service isn't reading the Proxmox cloud-init
  drive. Re-check step 3 above.
- `New-LocalUser` / `New-SelfSignedCertificate` require Windows Server 2016+ /
  PowerShell 5.1 — fine for every `os` in the schema, but not for pre-2016.

---

## Where each thing lives

| Artifact | Purpose |
|---|---|
| `templates/terraform/azure/windows.tf` | `os_image_map`, effective-os/image resolution, `custom_os_images` merge |
| `templates/terraform/azure/variables.tf` | `os_overrides`, `image_id_overrides`, `custom_os_images`, `image_version_override` |
| `templates/deploy.sh.j2` → `pick_images()` | writes `images.auto.tfvars.json` from `PF_OS`/`PF_IMAGE_*` |
| `templates/terraform/proxmox/windows.tf` | template resolution, the `windows_bootstrap` snippet + `user_data_file_id` |
| `templates/terraform/proxmox/variables.tf` | `template_id_overrides` |
| `templates/terraform/proxmox/cloudinit/windows-bootstrap.ps1.tpl` | the first-boot WinRM + accounts bootstrap |
| `templates/deploy-proxmox.sh.j2` → `pick_template()` | writes `template.auto.tfvars.json` from `PF_TEMPLATE_ID` |

See also: [`README.md`](README.md) (§ Custom machine images, § Proxmox VE),
[`PROXMOX-DEPLOY-RUNBOOK.md`](PROXMOX-DEPLOY-RUNBOOK.md) (preparing a fresh
Proxmox host end-to-end, including this template checklist in context),
[`.claude/skills/infra-azure/SKILL.md`](.claude/skills/infra-azure/SKILL.md),
[`.claude/skills/infra-proxmox/SKILL.md`](.claude/skills/infra-proxmox/SKILL.md).
