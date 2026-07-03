# Azure deploy runbook

A procedural, copy-pasteable checklist for taking a `lab-spec.yml` to a live,
fully-configured Azure lab. Written after the first real end-to-end deploy of
this harness (`the-office-lab`, 2026-07-03), which hit and fixed eight real
bugs — most now fixed at the source (see each step's "already fixed"
callouts), a few are genuine environment gotchas no code change can prevent.
Follow this in order and you should not have to rediscover any of them.

For *why* each gotcha exists, see the relevant skill's own SKILL.md
("Troubleshooting a real ... " sections) — this file is the short version,
optimized for speed, not explanation.

## 0. Prerequisites (one-time per machine)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r scripts/requirements.txt
which terraform az docker || echo "install whichever is missing"
docker run --rm python:3.10-slim python3 --version   # confirms docker works, pre-pulls the image
```

`ansible-core` itself is **not** installed on the host — GOAD pins
`ansible-core==2.12.6`, which requires Python 3.8–3.10 and crashes on 3.11+.
Rather than fighting your system Python, run Ansible inside a container (see
step 6) — this is faster and more reliable than a pyenv/venv dance.

**If `az vm ...`, `az network ... show-effective-...`, or `az group
show`/`az group list` subcommands throw a Python traceback (`KeyError:
'disks'`, `ModuleNotFoundError: No module named
'azure.mgmt.resource.resources.v20XX...'`, or similar)**, that's a broken
azure-cli command-loading path in some environments, unrelated to your
credentials — and it's exactly what makes `forge.py destroy`'s own
post-teardown verification untrustworthy (see step 8). Don't debug it —
every diagnostic in this runbook uses `az rest --method get/post <ARM REST
URL>` instead, which never hits that
code path.

## 1. Write and validate the spec

```bash
python3 scripts/forge.py lab-spec specs/examples/<your-lab>.yml
```

Fix any schema/reconciliation errors before continuing. Nothing below this
point touches the network.

## 2. Pick a region and VM size *before* generating — quota is the #1 blocker

Azure subscriptions (especially free/trial/sponsored ones) commonly cap
**Total Regional vCPUs** far below what a 3-4 host lab needs, and separately
restrict specific VM size families per-region. Check both, for a couple of
candidate regions, before you spend time on anything else:

```bash
SUB=<your-subscription-id>
for loc in eastus westeurope swedencentral; do
  echo "=== $loc ==="
  az rest --method get --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Compute/locations/$loc/usages?api-version=2023-07-01" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print([u for u in d['value'] if u['name']['localizedValue']=='Total Regional vCPUs'][0])"
done
```

If the cap is tight (e.g. 4 vCPUs total), you need every VM at 1 vCPU. Find
an **unrestricted** 1-vCPU SKU in that region (restrictions vary by region
even when the vCPU cap doesn't):

```bash
az rest --method get --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Compute/skus?api-version=2021-07-01" \
  | python3 -c "
import json,sys
data=json.load(sys.stdin)
for s in data['value']:
    if s['resourceType']!='virtualMachines': continue
    if 'eastus' not in [l.lower() for l in s.get('locations',[])]: continue
    caps={c['name']:c['value'] for c in s.get('capabilities',[])}
    if caps.get('vCPUs')=='1' and not s.get('restrictions'):
        print(s['name'], caps.get('MemoryGB'), 'GB, DiskControllerTypes=', caps.get('DiskControllerTypes'))
"
```

`Standard_F1as_v7` (1 vCPU, 4GB) was confirmed unrestricted in `eastus` on
the subscription this was tested against — a good first guess, but re-check,
restrictions change. Pick a region with **both** enough quota headroom and an
unrestricted small SKU; `swedencentral` and `eastus` are both known-good for
different reasons (see `infra-azure/SKILL.md`), but *this subscription's*
numbers are what matter, not last time's.

**`DiskControllerTypes` matters as much as `HyperVGenerations` for older
OSes.** `F*v7`-family sizes (including `Standard_F1as_v7`) only support
`NVMe`, and `windows-server-2016`'s image doesn't support NVMe regardless of
which SKU variant you use — VM creation fails with `"cannot boot with OS
image or disk ... check disk controller types"`, a different error from the
Hypervisor Generation one. If you're deploying an older OS (2016, possibly
2019) on an NVMe-only size, override just that role in
`vm_size_overrides` to a SCSI-compatible unrestricted 1-vCPU size instead —
`Standard_DC1s_v3` (confidential-compute series, but works as an ordinary
VM without opting into confidential-compute features; `DiskControllerTypes`
absent from its capabilities means classic/SCSI) was confirmed working for
a 2016 DC on the same subscription where every `F*v7` size failed for it.

Once you've picked, set `lab.region` in the spec and write a
`sizes.auto.tfvars.json` you'll drop into the generated Terraform dir in
step 4 (Terraform auto-loads `*.auto.tfvars.json` — no `-var` flags needed
on every command):

```json
{
  "bastion_size": "Standard_F1as_v7",
  "vm_size_overrides": {
    "domain-controller": "Standard_F1as_v7",
    "member-server": "Standard_F1as_v7",
    "workstation": "Standard_F1as_v7"
  }
}
```

*(Already fixed at the source: every `windows-server-*` now maps to its
Hypervisor-Generation-2 marketplace SKU, so it's compatible with newer
Gen2-only size families like Fasv7 out of the box — no separate action
needed here. Note the Gen2 suffix isn't consistent across versions
[`2016`/`2019` use `-gensecond`, `2022`/`2025` use `-g2`] — only relevant if
you're adding a new OS to `os_image_map`, see `infra-azure/SKILL.md`.)*

## 3. Generate

```bash
python3 scripts/forge.py generate specs/examples/<your-lab>.yml --plan
```

`--plan` runs `terraform init -backend=false`/`validate`/`plan` for a
structural check even without cloud credentials yet. If this errors, fix it
before touching Azure — every syntax/schema bug is cheaper to catch here.

## 4. Wire up remote state and apply

```bash
cd generated/<your-lab>/terraform/azure
cp /path/to/your/sizes.auto.tfvars.json .        # from step 2
```

Edit `backend.hcl`'s `storage_account_name` — the generated value is a
placeholder. If this subscription already has a bootstrapped state storage
account from a previous lab, reuse it (`az storage account list -g
purpleforge-tfstate-rg -o table`); otherwise bootstrap one per the README's
"Bootstrap remote Terraform state" section.

```bash
export ARM_SUBSCRIPTION_ID=... ARM_CLIENT_ID=... ARM_TENANT_ID=... ARM_CLIENT_SECRET=...
terraform init -backend-config=backend.hcl -input=false
terraform apply -auto-approve -input=false -refresh=false -parallelism=1
```

**`-refresh=false` and `-parallelism=1` are not optional style choices —
some subscriptions exhibit severe ARM read-after-write lag** (a GET
immediately after a successful PUT returns 404 for tens of minutes,
including on `azurerm_virtual_network`/`_network_security_group`/
`_network_interface`). With `-refresh=false`, Terraform trusts its own state
file instead of re-reading live state before planning, which avoids the
flaky read entirely for anything already in state. If `apply` still errors
with `"Provider produced inconsistent result"` or `"already exists — needs
to be imported"` for a resource that genuinely exists
(`az resource show --ids <id> --query provisioningState` will confirm
`Succeeded`), import it and re-apply:

```bash
terraform import <resource.address> "/subscriptions/$SUB/resourceGroups/<rg>/providers/<type>/<name>"
terraform apply -auto-approve -input=false -refresh=false -parallelism=1   # repeat until clean
```

This can take 2-4 retries on a bad subscription. Each retry makes real
progress (imported resources stay imported) — it is not spinning.

## 5. WireGuard tunnel

```bash
sudo apt-get install -y wireguard-tools     # once per machine
cd generated/<your-lab>/terraform/azure
wg genkey | tee ssh_keys/client_wg.key | wg pubkey > ssh_keys/client_wg.pub

# Extract the bastion SSH key straight from state (the in-VM local-exec
# provisioner that's supposed to write ssh_keys/bastion.pem doesn't always
# fire — importing a resource skips provisioners, and several imports were
# needed in step 4):
terraform show -json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d['values']['root_module']['resources']:
    if r['address']=='tls_private_key.bastion_ssh':
        print(r['values']['private_key_pem'])
" > ssh_keys/bastion.pem
chmod 600 ssh_keys/bastion.pem

BASTION_IP=$(terraform output -raw bastion_public_ip)
MY_IP=$(curl -s https://api.ipify.org)
```

SSH to the bastion is closed by default (`bastion_ssh_allowed_cidrs: []`) —
add your IP via the same `.auto.tfvars.json` file and re-apply, or a
one-off `-var 'bastion_ssh_allowed_cidrs=["'"$MY_IP"'/32"]'` on `apply`.

```bash
CLIENT_PUB=$(cat ssh_keys/client_wg.pub)
SERVER_PUB=$(ssh -i ssh_keys/bastion.pem purpleforge@$BASTION_IP "sudo cat /etc/wireguard/publickey")
ssh -i ssh_keys/bastion.pem purpleforge@$BASTION_IP \
  "sudo wg set wg0 peer $CLIENT_PUB allowed-ips 10.250.250.2/32 && sudo wg-quick save wg0"

sudo tee /etc/wireguard/pf-lab.conf > /dev/null <<EOF
[Interface]
PrivateKey = $(cat ssh_keys/client_wg.key)
Address = 10.250.250.2/32
[Peer]
PublicKey = $SERVER_PUB
Endpoint = $BASTION_IP:51820
AllowedIPs = 10.250.250.0/24, $(python3 -c "import json;print(json.load(open('terraform.tfvars.json'))['supernet'])")
PersistentKeepalive = 25
EOF
sudo wg-quick up pf-lab
```

## 6. Ansible over the tunnel — via Docker

```bash
docker run -d --name pf-ansible --network host \
  -v /path/to/PurpleForge:/repo -w /repo/generated/<your-lab>/ansible \
  python:3.10-slim sleep infinity
docker exec pf-ansible bash -c "pip install --quiet ansible-core==2.12.6 pywinrm rich psutil Jinja2 pyyaml ansible_runner"
docker exec pf-ansible bash -c "ansible-galaxy collection install ansible.windows:1.11.0 community.windows:1.11.0 chocolatey.chocolatey"
```

`community.general` (unpinned, per `vendor/GOAD/ansible/requirements.yml`)
**will fail to install** — its huge version list breaks `ansible-core
2.12.6`'s galaxy client (`KeyError` deep in `ansible/galaxy/api.py`, a real
client bug against the modern Galaxy API, not a network problem). Download
and install a pinned tarball directly instead:

```bash
docker exec pf-ansible python3 -c "
import urllib.request
urllib.request.urlretrieve('https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-6.6.2.tar.gz', '/tmp/cg.tar.gz')
"
docker exec pf-ansible ansible-galaxy collection install /tmp/cg.tar.gz
```

`--network host` is what lets the container see the `pf-lab` WireGuard
interface from step 5 — without it, the container can't reach the private
subnet at all.

## 7. Wait for WinRM, then run `site.yml`

```bash
docker exec -w /repo/generated/<your-lab>/ansible pf-ansible \
  ansible all -i inventory/hosts.yml -m ansible.windows.win_ping
```

**If this times out even though the NSG allows it and the target's WinRM
service is confirmed running**: this is almost certainly Windows Firewall's
built-in `Windows Remote Management (HTTP-In)` rule, whose **Public-profile
instance is scoped to `RemoteAddress: LocalSubnet`** — every Azure VM NIC
starts in the `Public` category, so this silently blocks WinRM from anything
outside the target's own subnet (i.e. from the bastion, which always lives
in a separate management subnet). *(Already fixed at the source: infra-azure
now adds a VNet-scoped firewall rule automatically. If you're on a lab
generated before that fix, or the fix didn't apply for some other reason,
add one by hand via Azure's `runCommand` API — bypasses WinRM entirely, uses
the VM agent instead — on each affected host.)*

Once `win_ping` succeeds everywhere:

```bash
docker exec -w /repo/generated/<your-lab>/ansible pf-ansible \
  ansible-playbook -i inventory/hosts.yml playbooks/site.yml
```

This runs AD promotion (with a reboot), BadBlood population, hardening, and
vuln injection in one pass, and can legitimately take 15-30+ minutes on a
small (1 vCPU) VM. If it fails partway, **re-running is safe and expected**
— every task is idempotent, and each retry picks up where the last one left
off. A few failure modes you may still hit even with all the fixes below in
place, because they're genuine platform/environment behavior, not bugs:

- **`ntlm: the specified credentials were rejected by the server` against
  a domain controller specifically**, with the same credentials confirmed
  correct via a local `Invoke-Command` test on that host. *(Already fixed:
  `ansible_winrm_transport` is `basic`, not `ntlm`, precisely because of
  this.)* If you still see it, re-verify the transport setting wasn't
  overridden somewhere.
- **A domain user account (`ansible`, or the renamed `Administrator`)
  intermittently fails WinRM auth right after a heavy step (BadBlood
  population, DC promotion) even though `Get-ADUser` shows it enabled,
  unlocked, correct bad-password count.** Not fully root-caused; a
  `Set-ADAccountPassword -Reset` to the known password plus retrying the
  play has resolved it every time it's been seen.
- **`pf_defender_av`'s tamper-protection task reports "failed" in its
  own debug message.** Expected on any non-Intune-managed VM — Microsoft
  platform limitation, not fixable from Ansible. Every other Defender
  control (real-time protection, network protection, ASR rules) is
  unaffected and will show as applied.

`site.yml` completing cleanly proves the AD objects for your
`vulnerabilities:` got created — it does NOT prove they're actually
exploitable. **If a Kerberos-ticket-based vuln (`kerberoasting`,
`asreproast`, `constrained-delegation`) gives `KDC_ERR_ETYPE_NOSUPP` when you
actually try it** (e.g. `nxc ldap <dc-ip> -d <domain> -u <user> -p <pass>
--kerberoasting out.txt --kdcHost <dc-fqdn>.<domain>`), and this happens for
*every* principal in the domain, not just your injected account — that's not
a spec/config problem, it's the same real-deploy finding as
`vuln-injection/SKILL.md` documents: a fully-patched KDC no longer treats
"unset `msDS-SupportedEncryptionTypes`" as RC4-crackable by default. Already
fixed at the source for new deploys; if you're validating a lab generated
before that fix, set it by hand on the affected account(s):
`Set-ADUser -Identity <account> -Replace @{'msDS-SupportedEncryptionTypes' = 28}`.

## 7b. Document the live domain: users, groups, NT hashes

`lab-report.md` (from step 3) is spec-time — it can't show BadBlood's actual
usernames/passwords, because BadBlood generates them randomly with
PowerShell's `Get-Random` on the DC during `site.yml` and never writes them
anywhere, not even internally. Once the domain is actually up, get the real,
current picture instead (from the same machine with the WireGuard tunnel up
— needs `ldap3`, already in `scripts/requirements.txt`, and `nxc`/`netexec`
for the NT hash dump via DCSync):

```bash
python3 scripts/forge.py ad-inventory specs/examples/<your-lab>.yml
# writes generated/<your-lab>/ad-inventory.md — every user (NT hash, group
# memberships, tagged VULN if it's one of the injected accounts, tagged PRIV
# if privileged) and every group (description, full member list)
```

Re-run it anytime — it always reflects live domain state, not what was
originally intended, so it's also useful mid-exercise to see what's changed
(new group memberships from a successful escalation, etc.). NT hashes are
pass-the-hash usable directly and crackable offline (`hashcat -m 1000`) —
this file is even more sensitive than `lab-report.md`, same gitignore
coverage (`generated/`).

## 8. Verify, then teardown when done

```bash
docker exec -w /repo/generated/<your-lab>/ansible pf-ansible \
  ansible-playbook -i inventory/hosts.yml playbooks/verify.yml
```

```bash
export ARM_SUBSCRIPTION_ID=... ARM_CLIENT_ID=... ARM_TENANT_ID=... ARM_CLIENT_SECRET=...
python3 scripts/forge.py destroy specs/examples/<your-lab>.yml --yes
```

**If `destroy` fails with `Cannot modify extensions in the VM when the VM is
not running` and/or `Operation 'powerOff' is not allowed on VM '...' since
the VM is either deallocated or marked to be deallocated`**: `lab.auto_shutdown`
(every lab has one — CLAUDE.md invariant #4) already fired and deallocated
the VMs before you got to `destroy`. Terraform's own destroy sequence
deletes each `azurerm_virtual_machine_extension` first (needs the VM
*running*) and powers off the Linux bastion explicitly (needs it *not
already* deallocated) — both fail outright on an already-deallocated VM,
it's not a retry-and-it-goes-away transient. Start every VM back up, wait
for `PowerState/running` on all of them, then retry `destroy` — it'll
complete cleanly the second time, same command:

```bash
SUB=<your-subscription-id>
RG=<your-lab>
for vm in <your-lab>-bastion dc01 mbr01 ws01; do   # your actual VM names, from lab-report.md
  az rest --method post --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$vm/start?api-version=2023-07-01"
done
# poll until every one reports PowerState/running (not "starting"), THEN:
python3 scripts/forge.py destroy specs/examples/<your-lab>.yml --yes
```

`forge.py destroy` independently confirms via the ARM REST API (`az rest`,
not `az group show`) that the resource group is actually gone, not just
that `terraform destroy` exited 0. *(Already fixed at the source: an
earlier version used `az group show`, which crashes with
`ModuleNotFoundError: No module named 'azure.mgmt.resource.resources.v20XX...'`
in some environments — the same broken azure-cli command-loading path as
the `az vm`/`az network` subcommands from step 0 — and printed a misleading
`OK: destroyed and verified` right after its own `warning: could not
confirm ...`. If you're on a checkout from before that fix, don't trust
that "OK"; confirm by hand instead:)*

```bash
SUB=<your-subscription-id>
az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/<your-lab>?api-version=2021-04-01"
# expect: ERROR ... "ResourceGroupNotFound" — that 404 IS the confirmation.
# Anything else (a 200 with provisioningState, or a different error) means
# it's not actually gone yet.
```

### Clean up local session state too

Nothing in Azure, but left dangling on your machine and easy to forget:

```bash
docker stop pf-ansible && docker rm pf-ansible   # the ansible-core container from step 6
sudo wg-quick down pf-lab                        # (or pf-office, whatever you named it in step 5)
```

Neither costs anything or blocks a future deploy if left running, but the
WireGuard interface will otherwise sit there pointing at a bastion IP that
no longer exists, and `docker ps` clutter is just confusing next time.

## Quick-reference: symptom → cause

| Symptom | Cause | Fix location |
|---|---|---|
| `SkuNotAvailable ... Capacity Restrictions` or `exceeding approved Total Regional Cores quota` | Subscription/region vCPU cap or SKU restriction | Step 2 — try another region/size, it's not always a dead end |
| `cannot boot Hypervisor Generation '1'` | Gen2-only size family + Gen1 image | Already fixed for 2016/2019/2022/2025 (`windows.tf`) — check the real SKU list before adding another OS, the Gen2 suffix isn't consistent |
| `cannot boot with OS image or disk ... check disk controller types` | NVMe-only size (`F*v7`) + an OS image (2016 confirmed) with no NVMe support — a different axis from Hypervisor Generation | Override just that role in `vm_size_overrides` to a SCSI-compatible size, e.g. `Standard_DC1s_v3` |
| `KDC_ERR_ETYPE_NOSUPP` kerberoasting/AS-REP-roasting/exploiting delegation, for EVERY principal in the domain | Fully-patched KDC no longer treats unset `msDS-SupportedEncryptionTypes` as RC4-crackable by default | Already fixed at the source (vuln-injection sets it to 28) — see `vuln-injection/SKILL.md` |
| `destroy` fails with `Cannot modify extensions ... VM is not running` / `powerOff ... VM is either deallocated` | `lab.auto_shutdown` already deallocated the VMs before you ran `destroy` | Start every VM, wait for `PowerState/running`, retry `destroy` — see step 8 |
| `Provider produced inconsistent result after apply` / spurious `already exists` | ARM read-after-write lag on this subscription | Step 4 — `-refresh=false`, import + retry |
| WinRM times out cross-subnet, works same-subnet | Windows Firewall Public-profile `LocalSubnet` scope | Already fixed (`windows.tf` bootstrap script) |
| `'add_route' is undefined` | Missing GOAD inventory default | Already fixed (`hosts.yml.j2`) |
| `domain_admin_user must be in domain\user format` | Bare `"Administrator"` username | Already fixed (`forge.py`) |
| `Could not find domain user ... named Administrator` / `user name or password is incorrect` on domain-join | Wrong password source for the real Administrator account | Already fixed (`forge.py` — see `ad-topology/SKILL.md`) |
| `found unknown escape character` parsing `hosts.yml` | Unescaped `\` in a double-quoted YAML scalar | Already fixed (`yaml_scalar()` in `forge.py`) |
| Tamper-protection task fails | Intune-only Windows platform limitation | Already fixed to fail gracefully, not fixable further |
| NTLM rejected against a DC only | Channel Binding Token mismatch | Already fixed (`ansible_winrm_transport: basic`) |
| `az vm ...` / `az network ... show-effective-...` / `az group show` crashes with a Python traceback | Broken azure-cli command-loading path (some environments) | Use `az rest` against the ARM REST API instead — already fixed at the source in `forge.py destroy`'s own verification |
