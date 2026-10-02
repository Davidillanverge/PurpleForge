---
name: infra-aws
description: >
  Renders the AWS compute + network layer for a lab: private-IP-only EC2 Windows
  VMs (DC/member-server/workstation) imaged per role via SSM public AMI
  parameters, a WireGuard bastion that is the only routable host AND the NAT
  instance for the private subnets, deny-by-default security groups, EventBridge
  Scheduler + Lambda auto-shutdown, and S3+DynamoDB remote state. The cloud
  sibling of infra-azure. Consumes network_plan, emits templates/terraform/aws/.
---

# infra-aws

## When to use

- `/generate`, when `lab.provider` is `aws`. `forge.py`'s
  `render_aws_terraform()` copies `templates/terraform/aws/` verbatim to
  `generated/<lab>/terraform/aws/` + writes `terraform.tfvars.json` (spec-derived,
  shareable) + `secrets.auto.tfvars.json` (gitignored) + `backend.hcl`. One root
  module, like Azure. It does NOT bake account/region specifics (resolved at
  deploy time).

> **Status:** rendered + `terraform plan`/`validate`-verified, but NOT yet
> exercised against a live AWS account (same caveat as `verify.yml`). See
> [`AWS-DEPLOY-RUNBOOK.md`](../../../AWS-DEPLOY-RUNBOOK.md).

## vs Azure (how each Azure concept maps to AWS)

| Concern | Azure | AWS |
|---|---|---|
| Grouping | resource group | **tags only** (`lab`/`project` default_tags in `main.tf`); auto-shutdown + teardown filter on `lab=<name>` |
| Windows image | marketplace publisher/offer/sku | **SSM public parameter** (`/aws/service/ami-windows-latest/...`) resolved at plan/apply; `image_id` override = an AMI id |
| WinRM bootstrap | CustomScriptExtension | **`user_data` `<powershell>`** block (EC2Launch runs it once) |
| Private host egress | default Azure outbound SNAT | **bastion as NAT instance** (`source_dest_check=false`, cloud-init MASQUERADEs the supernet) — no paid NAT Gateway (invariant #4) |
| Remote state | Azure Storage | **S3 bucket + DynamoDB lock** (invariant #4) |
| auto_shutdown | DevTest per-VM schedule | **EventBridge Scheduler + Lambda** (stops instances tagged `lab=<name>`) |

## What it generates (hashicorp/aws provider, one root module)

| File | Content |
|---|---|
| `versions.tf` | provider pins (`aws ~> 5.40`, `tls`, `archive`), partial `backend "s3" {}` |
| `main.tf` | `provider "aws"` with `default_tags { lab, project }` — no RG analog |
| `network.tf` | VPC, public mgmt subnet (route to IGW), private per-domain subnets (default route → bastion ENI), deny-by-default SGs: bastion admits only WireGuard UDP; domain admits only the bastion SG + same-domain (`self = true`) |
| `bastion.tf` | EC2 Ubuntu 22.04 (`data.aws_ami` Canonical) + EIP (only public IP), static-private ENI with `source_dest_check=false` (NAT), WireGuard cloud-init, SSH key → `ssh_keys/bastion.pem` |
| `windows.tf` | one `aws_instance` per host, private ENI on its domain subnet, AMI via SSM/`image_id`, WinRM bootstrap in `user_data` |
| `auto_shutdown.tf` | `archive_file` Lambda zip, Lambda + its IAM role (ec2:StopInstances scoped by tag), Scheduler + its IAM role, `aws_scheduler_schedule` (cron + IANA timezone) |
| `lambda/stop_instances.py` | boto3: stop every running instance tagged `lab=<name>` |
| `outputs.tf` | `bastion_public_ip` (named to match Azure so the deploy WireGuard step reads it identically), `windows_hosts`, `region` |

## `windows.tf` specifics

- **OS → AMI** (`local.os_ssm_map`): `machines[].os` → an SSM public-parameter
  path (`Windows_Server-2016/2019/2022/2025-English-Full-Base`), resolved by
  `data.aws_ssm_parameter` so the AMI is always region-correct without a baked
  ami-id. `os_ssm_overrides` (from `PF_IMAGE_SSM`) adds/overrides entries.
- **Client OS has NO stock EC2 AMI.** `windows-10-22h2`/`windows-11-23h2` map to
  `""`; a machine resolving to `""` with no `image_id` fails a `precondition`
  with a clear message. A real client workstation needs a **BYOL AMI** via
  `machines[].image_id` (or `image_id_overrides` / `PF_IMAGE_ID`). This is the
  AWS analogue of Azure's marketplace-agreement gate — but there's no agreement
  to accept, the image simply doesn't exist as a first-party AMI.
- **Custom AMI** (`machines[].image_id`): `coalesce`d ahead of the SSM lookup;
  `os` stays required (selects the hardening role). Provider-agnostic field
  shared with Azure.
- **Role → instance type** (`local.instance_type_map`): `t3.medium` all roles;
  override wholesale with `var.instance_type_overrides` (by role) /
  `PF_VM_SIZE`, never by hand-editing. Check on-demand vCPU quota first (new
  accounts cap low → `VcpuLimitExceeded`).
- **WinRM bootstrap**: `user_data` sets the built-in **Administrator (RID-500)**
  password to `admin_password` (the account the forest's domain-Administrator
  inherits at DCPromo — EC2 Windows ships RID-500 enabled, so unlike Azure/GOAD
  there is no `purpleforge→Administrator` rename), creates the dedicated local
  `ansible` WinRM account (`ansible_password`), runs
  `ConfigureRemotingForAnsible.ps1`, and opens WinRM to the lab supernet only.

## `terraform.tfvars.json` + remote state

`forge.py generate <lab>` writes `terraform.tfvars.json` (`lab_name`, `region`,
network_plan fields, flattened `machines`, the EventBridge cron +
**IANA timezone directly** — no Windows-tz translation Azure needs) +
`secrets.auto.tfvars.json` (gitignored) + `backend.hcl`. `versions.tf` declares
a partial `backend "s3" {}` (invariant #4), so `terraform init` needs
`-backend-config=backend.hcl`. `deploy.sh` mints one shared bucket
(`pf-tfstate-<account>-<region>`, stable per deployer) + lock table
(`purpleforge-tfstate-lock`) if absent and patches `backend.hcl`; the committed
placeholder bucket name won't be globally available. `-backend=false` is for
structural validation only.

## Live `apply` gotchas

See `AWS-DEPLOY-RUNBOOK.md` for the full symptom→cause table. The ones most
likely to bite first:

- **`VcpuLimitExceeded`** on `RunInstances` — on-demand vCPU quota; request an
  increase or lower `PF_VM_SIZE`.
- **Client-OS precondition failure** — supply a BYOL `image_id` (above).
- **WinRM never green** — the private hosts reach the internet (to fetch
  `ConfigureRemotingForAnsible.ps1`) only through the bastion NAT; if the
  bastion cloud-init hasn't finished, their bootstrap can't complete. `run_site`
  retries; give it time.
- **bastion SSH refused** — `bastion_ssh_allowed_cidrs` must include your public
  IP (the WireGuard key exchange SSHes in). `deploy.sh`'s `pick_sizes` sets it
  from `api.ipify.org`.

## Testing

```bash
cd generated/<lab>/terraform/aws && terraform init -backend=false && terraform validate
# plan needs creds (data.aws_ami/ssm/availability_zones read the API):
#   AWS creds set -> terraform plan   (with a local backend override, like run_terraform_plan)
```

`validate` needs no creds and is the credential-free bar. A dummy-cred `plan`
compiles the full graph and stops only at STS auth — confirming the HCL is
sound. Re-verify with a real `plan`/`apply` against an account with EC2 Windows
quota in the region.

## Do NOT

- Bake account id / region / ami-ids into committed files (resolved at deploy).
- Add a public IP (or a public subnet route) to any Windows host — only the
  bastion is routable (invariant #1); private hosts egress via the bastion NAT.
- Collapse the `ansible` WinRM account into `admin_username`/`admin_password`
  (same rule as Azure — they're deliberately separate).
- Narrow the domain SG to specific ports — isolation is enforced by *source*
  (bastion SG / same-domain only), not by destination port (same reasoning as
  the Azure NSG `allow-all-from-management` rule).
