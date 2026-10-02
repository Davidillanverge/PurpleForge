# AWS deploy runbook

Copy-pasteable checklist from `lab-spec.yml` to a live AWS lab, and the
symptom→cause table for the gotchas a real deploy hits. The AWS sibling of
`AZURE-DEPLOY-RUNBOOK.md`.

> **Status:** exercised end-to-end against a live AWS account on **2026-10-02**
> (`specs/aws-parity-lab.yml`, eu-west-1: DC + member-server/ADCS + workstation,
> 4 vulns). `site.yml` completed `failed=0`, the clean-state AMIs were taken, and
> the vulns were validated over the tunnel (asreproast + dcsync-acl + adcs-esc1 +
> unquoted-service-path). The first live run surfaced **five generator bugs**,
> all now fixed in the deploy files and committed — see **Live-deploy bugs
> found & fixed** below.

The deploy is deterministic and runs itself: `forge deploy specs/<lab>.yml`
(guardrail gate → the generated `deploy.sh`). The steps below are what that
script does, with the failure modes to expect.

## 0. Prerequisites (one-time)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r scripts/requirements.txt
which terraform aws docker wg openssl curl   # install whichever is missing
docker run --rm python:3.10-slim python3 --version   # confirm docker + pre-pull
```

- `aws` CLI: `sudo apt install awscli` (or the AWS v2 installer).
- `ansible-core` is **not** installed on the host — it runs in a container
  (step 5), GOAD pins `ansible-core==2.12.6` (needs Python 3.8–3.10).
- **Credentials:** any standard AWS SDK source works — an env block
  (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`), a profile
  (`export AWS_PROFILE=<name>`), or SSO (`aws sso login --profile <name>`).
  `deploy.sh` bakes nothing account-specific; it deploys into whatever
  `aws sts get-caller-identity` resolves.
- **IAM permissions:** EC2 + VPC (instances, SGs, subnets, EIP, ENIs), S3 +
  DynamoDB (remote state), IAM (create the 2 auto-shutdown roles), Lambda,
  EventBridge Scheduler, SSM (read public AMI parameters), and
  `resourcegroupstaggingapi:GetResources` (teardown verification).
  `PowerUserAccess` + `IAMFullAccess` (or a scoped role-creation policy) covers
  it; a dedicated `pf-deployer` principal is cleanest.
- **Quota:** the parity lab is 3 × `t3.medium` = 6 on-demand vCPUs. New accounts
  may have a low on-demand vCPU limit — request an increase, or export
  `PF_VM_SIZE` to a smaller type.

## 1. Validate + generate

```bash
forge lab-spec specs/<lab>.yml     # schema + semantic + reconciliation + cost
forge generate specs/<lab>.yml     # -> generated/<lab>/ (terraform/aws + ansible + scripts)
```

## 2. Deploy

```bash
forge deploy specs/<lab>.yml
# env overrides (optional):
PF_REGION=eu-west-1 PF_VM_SIZE=t3.small forge deploy specs/<lab>.yml
```

What `deploy.sh` does, in order (CLAUDE.md deploy order):
`infra → AD topology → population/theming → hardening → vuln injection → EDR →
clean snapshot`. The snapshot (one AMI per VM, `<lab>-<vm>-clean`) is the LAST
step — after hardening + vulns, before any attack.

## 3. Validate the live lab

```bash
forge validate specs/<lab>.yml --run      # injected vulns applied + exploitable
forge ad-inventory specs/<lab>.yml        # live domain matches the plan
```

## 4. Teardown (cost-zero)

```bash
forge teardown specs/<lab>.yml
```

`terraform destroy` + `verify_aws_teardown` (no resource tagged `lab=<name>`
remains in the region) + deregister the clean-state AMIs and delete their EBS
snapshots (they are created out of band by `deploy.sh`, so `destroy` alone
leaves them). The shared state bucket + lock table are per-deployer and kept.

## 5. Reset between exercises

```bash
forge reset specs/<lab>.yml        # swap every VM's root volume back to its clean AMI
```

---

## Live-deploy bugs found & fixed (2026-10-02, first live run)

All five surfaced deploying `specs/aws-parity-lab.yml` end-to-end against a real
account and are **fixed at source** in the deploy files (not worked around).
Same "the first live deploy finds the real bugs" pattern as the Proxmox path.

| # | Symptom | Root cause | Fix (file) | Commit |
|---|---|---|---|---|
| 1 | WireGuard step: `Permission denied (publickey)` → `bastion SSH never came up` | Deploy SSHed as `purpleforge@` (the Azure/Proxmox admin user), but the stock Canonical AMI's default user is `ubuntu` (where EC2 injects the key pair). | `templates/deploy-aws.sh.j2` (`wg_up` logs in as `ubuntu@`) | `8d00982` |
| 2 | `Install-Module ActiveDirectoryDSC` → `No match was found` (every PSGallery install fails on the DC) | DNS forwarder hardcoded to `168.63.129.16` (Azure's magic resolver). On AWS that IP is unreachable, so a promoted DC can't resolve public names. **Not** a TLS/egress issue (raw IP egress worked). | `templates/ansible/inventory/hosts.yml.j2` + `render.py` — provider-aware: VPC resolver (CIDR base + 2, e.g. `10.54.0.2`) on AWS. | `8d00982` |
| 3 | `member_server` DNS task → `No MSFT_NetAdapter objects found with property 'Name' equal to 'Ethernet'` | Primary NIC hardcoded as `domain_adapter: "Ethernet"`, but EC2 Windows AMIs (ENA driver) name it **`Ethernet 3`**. | `templates/ansible/inventory/hosts.yml.j2` + `render.py` — provider-aware: `Ethernet 3` on AWS. | `8d00982` |
| 4 | Clean snapshot creates a doubled-name AMI `aws-parity-lab-aws-parity-lab-bastion-clean` | `snapshot_clean` iterated every tagged instance incl. the bastion (whose Name tag already carries the lab prefix); the bastion is also disposable infra `reset` never restores. | `templates/deploy-aws.sh.j2` + `templates/reset-aws.sh.j2` — skip the bastion. | `8b25af5` |
| 5 | `adcs-esc1` enroll fails `ept_s_not_registered` (CA RPC unreachable) — the ESC1 template is published but not exploitable over the tunnel | A member server's Windows firewall blocks inbound RPC (EPM 135 + dynamic DCOM) + SMB 445 by default (a DC opens them at promotion; a member server does not), so the CA enrollment interface is unreachable from the bastion subnet — the only path in (invariant #1). | `templates/ansible/vulns/adcs-esc1.yml` opens 135/445/dynamic to the lab supernet (`pf_supernet`, exposed via `render.py` + `hosts.yml.j2`). | `8b25af5` |

Not a lab defect (environmental, documented for completeness): **adcs-esc1's final
PKINIT-to-DA** is gated by `KB5014754` strong certificate binding on a patched
2022 DC (cert has no SID → `Object SID mismatch`). The ESC1 enrollment primitive
itself is proven (a Domain User enrolled a cert impersonating Administrator); the
DC NTAuth cache refresh in `service-provisioning` works (otherwise PKINIT would
fail earlier with `KDC_ERR_CLIENT_NOT_TRUSTED`).

## Symptom → cause table

| Symptom | Cause / fix |
|---|---|
| `preflight: AWS credentials not usable` | No usable credentials in the SDK chain. `aws sts get-caller-identity` must succeed first (set env vars / `AWS_PROFILE` / `aws sso login`). |
| `create-bucket` fails `IllegalLocationConstraintException` | S3 create-bucket takes no `LocationConstraint` in `us-east-1` but requires it elsewhere — `deploy.sh` branches on this; if you hand-create the bucket, match the rule. |
| `terraform apply` → `InvalidClientTokenId` / `UnauthorizedOperation` | Credentials are missing a permission (step 0). The action named in the error tells you which. |
| `VcpuLimitExceeded` on `RunInstances` | On-demand vCPU quota too low for the region. Request an increase or lower `PF_VM_SIZE`. |
| Machine with `windows-10-*`/`windows-11-*` fails the precondition | AWS publishes no stock client-Windows AMI. Supply a BYOL AMI via `machines[].image_id` (or `PF_IMAGE_ID`). |
| `bastion SSH never came up` | `bastion_ssh_allowed_cidrs` doesn't include your current public IP — `pick_sizes` sets it from `api.ipify.org`; behind a changing/NATed IP, export it or re-run. |
| WinRM never goes green | Private domain subnets reach the internet only via the bastion NAT — if the bastion's cloud-init hasn't finished, the Windows `user_data` bootstrap (which fetches `ConfigureRemotingForAnsible.ps1`) can't complete. Give it time; `run_site` retries. |
| `reset.sh` skips a VM ("no clean-state AMI") | The deploy's `snapshot_clean` step didn't run or failed. Re-run it, or re-deploy. |
| Teardown leaves AMIs/snapshots | They are not in Terraform state by design — `teardown.sh`'s `sweep_amis` removes them. If you ran a bare `terraform destroy`, run `teardown.sh` or deregister them by hand. |

## Design notes specific to AWS

- **No resource group.** Everything is scoped by the `lab`/`project` default
  tags (set in `main.tf`), which is what auto-shutdown and teardown filter on.
- **Egress via the bastion as a NAT instance.** The Windows hosts are
  private-IP-only (invariant #1); their internet egress is NATed through the
  bastion ENI (`source_dest_check=false`), avoiding a paid NAT Gateway
  (invariant #4). The bastion is the single routable host.
- **auto_shutdown = EventBridge Scheduler + Lambda** (Azure's native per-VM
  schedule has no AWS equivalent). The Lambda stops instances tagged
  `lab=<name>`; `terraform destroy` removes it and its two IAM roles.
- **Remote state = S3 + DynamoDB lock**, one bucket/table per deployer, each lab
  a separate key (invariant #4).
