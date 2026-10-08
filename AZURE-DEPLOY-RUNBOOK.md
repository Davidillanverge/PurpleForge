# Azure deploy runbook

Copy-pasteable checklist from `lab-spec.yml` to a live Azure lab. The short
version — for *why* each gotcha exists, see the relevant SKILL.md's
"gotchas"/"Troubleshooting" section. Most are fixed at the source now (marked
*[fixed]*); a few are environment realities no code can prevent.

> **`az` CLI traceback?** If `az vm ...`, `az network ... show-effective-...`, or
> `az group show/list` throw a Python traceback (`KeyError: 'disks'`,
> `ModuleNotFoundError: azure.mgmt.resource...`), that's a broken command-loading
> path in some environments, unrelated to creds. Every diagnostic here uses
> `az rest --method get/post <ARM REST URL>` instead, which avoids it.

## 0. Prerequisites (one-time)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r scripts/requirements.txt
which terraform az docker || echo "install whichever is missing"
docker run --rm python:3.10-slim python3 --version   # confirm docker + pre-pull
```

`ansible-core` is **not** installed on the host — GOAD pins `ansible-core==2.12.6`
(needs Python 3.8–3.10, crashes on 3.11+). It runs in a container (step 6).

## 1. Validate the spec

```bash
forge lab-spec specs/<lab>.yml
```

Fix schema/reconciliation errors first. Nothing below touches the network.

## 2. Pick region + VM size — quota is the #1 blocker

Subscriptions commonly cap **Total Regional vCPUs** below what a 3–4 host lab
needs, and restrict specific size families per-region. Check both for a couple of
regions:

```bash
SUB=<sub-id>
for loc in eastus westeurope swedencentral; do
  echo "=== $loc ==="
  az rest --method get --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Compute/locations/$loc/usages?api-version=2023-07-01" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print([u for u in d['value'] if u['name']['localizedValue']=='Total Regional vCPUs'][0])"
done
```

If the cap is tight (e.g. 4 vCPUs), find an **unrestricted** 1-vCPU SKU in that
region (restrictions vary by region even when the cap doesn't):

```bash
az rest --method get --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Compute/skus?api-version=2021-07-01" \
  | python3 -c "
import json,sys
for s in json.load(sys.stdin)['value']:
    if s['resourceType']!='virtualMachines' or 'eastus' not in [l.lower() for l in s.get('locations',[])]: continue
    caps={c['name']:c['value'] for c in s.get('capabilities',[])}
    if caps.get('vCPUs')=='1' and not s.get('restrictions'):
        print(s['name'], caps.get('MemoryGB'),'GB, DiskControllerTypes=', caps.get('DiskControllerTypes'))
"
```

`Standard_F1as_v7` (1 vCPU, 4GB) was confirmed unrestricted in `eastus` on the
test subscription — re-check, restrictions change. **`DiskControllerTypes` matters
as much as `HyperVGenerations` for older OSes:** `F*v7` sizes are `NVMe`-only, and
`windows-server-2016`'s image has no NVMe support → `"cannot boot with OS image or
disk ... check disk controller types"`. For an old OS on NVMe-only, override that
role to a SCSI 1-vCPU size (`Standard_DC1s_v3` confirmed working for a 2016 DC).

Set `lab.region` in the spec, and write `sizes.auto.tfvars.json` for step 4
(Terraform auto-loads `*.auto.tfvars.json`):

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

*[fixed] every `windows-server-*` maps to its Gen2 SKU (compatible with Gen2-only
families like Fasv7). Suffix isn't consistent (`2016`/`2019` `-gensecond`,
`2022`/`2025` `-g2`) — only relevant when adding a new OS.*

## 3. Generate

```bash
forge generate specs/<lab>.yml --plan
```

`--plan` runs `terraform init -backend=false`/`validate`/`plan` (no creds needed).
Fix any error here — cheapest place to catch it.

## 4. Remote state + apply

```bash
cd generated/<lab>/terraform/azure
cp /path/to/sizes.auto.tfvars.json .        # from step 2
```

Edit `backend.hcl`'s `storage_account_name` (the generated value is a
placeholder). Reuse an existing bootstrapped account
(`az storage account list -g purpleforge-tfstate-rg -o table`) or bootstrap one
(see `infra-azure/SKILL.md`).

```bash
export ARM_SUBSCRIPTION_ID=... ARM_CLIENT_ID=... ARM_TENANT_ID=... ARM_CLIENT_SECRET=...
terraform init -backend-config=backend.hcl -input=false
terraform apply -auto-approve -input=false -refresh=false -parallelism=1
```

**`-refresh=false` and `-parallelism=1` are required, not style** — some
subscriptions have severe ARM read-after-write lag (a GET right after a PUT 404s
for tens of minutes). `-refresh=false` trusts local state instead of re-reading.
If `apply` still errors `"Provider produced inconsistent result"` or `"already
exists — needs to be imported"` for a resource that exists (`az resource show
--ids <id> --query provisioningState` = `Succeeded`), import + re-apply:

```bash
terraform import <resource.address> "/subscriptions/$SUB/resourceGroups/<rg>/providers/<type>/<name>"
terraform apply -auto-approve -input=false -refresh=false -parallelism=1   # repeat until clean
```

2–4 retries on a bad subscription; each makes real progress (it's not spinning).

## 5. WireGuard tunnel

```bash
sudo apt-get install -y wireguard-tools     # once
cd generated/<lab>/terraform/azure
wg genkey | tee ssh_keys/client_wg.key | wg pubkey > ssh_keys/client_wg.pub

# bastion SSH key from state (the in-VM provisioner doesn't fire on imported resources):
terraform show -json | python3 -c "
import json,sys
for r in json.load(sys.stdin)['values']['root_module']['resources']:
    if r['address']=='tls_private_key.bastion_ssh': print(r['values']['private_key_pem'])
" > ssh_keys/bastion.pem
chmod 600 ssh_keys/bastion.pem

BASTION_IP=$(terraform output -raw bastion_public_ip)
MY_IP=$(curl -s https://api.ipify.org)
```

SSH to the bastion is closed by default (`bastion_ssh_allowed_cidrs: []`) — add
your IP via `.auto.tfvars.json` and re-apply, or a one-off `-var
'bastion_ssh_allowed_cidrs=["'"$MY_IP"'/32"]'`.

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

## 6. Ansible over the tunnel (via Docker)

```bash
docker run -d --name pf-ansible --network host \
  -v /path/to/PurpleForge:/repo -w /repo/generated/<lab>/ansible \
  python:3.10-slim sleep infinity
docker exec pf-ansible bash -c "pip install --quiet ansible-core==2.12.6 pywinrm rich psutil Jinja2 pyyaml ansible_runner"
docker exec pf-ansible bash -c "ansible-galaxy collection install ansible.windows:1.11.0 community.windows:1.11.0 chocolatey.chocolatey"
```

`--network host` is what lets the container see the `pf-lab` interface.
**`community.general` (unpinned) fails to install** — its huge version list breaks
`ansible-core 2.12.6`'s galaxy client (`KeyError` in `galaxy/api.py`). Install a
pinned tarball instead:

```bash
docker exec pf-ansible python3 -c "import urllib.request; urllib.request.urlretrieve('https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-6.6.2.tar.gz','/tmp/cg.tar.gz')"
docker exec pf-ansible ansible-galaxy collection install /tmp/cg.tar.gz
```

## 7. Wait for WinRM, run `site.yml`

```bash
docker exec -w /repo/generated/<lab>/ansible pf-ansible \
  ansible all -i inventory/hosts.yml -m ansible.windows.win_ping
```

**Times out though the NSG allows it and WinRM is running?** Windows Firewall's
built-in `Windows Remote Management (HTTP-In)` Public-profile instance is scoped
`RemoteAddress: LocalSubnet`; every Azure NIC starts `Public`, blocking WinRM from
the bastion's subnet. *[fixed] infra-azure adds a VNet-scoped rule. On an old lab,
add one via Azure `runCommand` (bypasses WinRM) per host.*

```bash
docker exec -w /repo/generated/<lab>/ansible pf-ansible \
  ansible-playbook -i inventory/hosts.yml playbooks/site.yml
```

Runs AD promotion (with a reboot), population, hardening, vuln injection in one
pass — 15–30+ min on a 1-vCPU VM. **Re-running is safe** (idempotent). Failure
modes that are platform behavior, not bugs:

- **`ntlm: credentials rejected` against a DC only** — *[fixed] transport is
  `basic`.* If it recurs, re-verify the transport wasn't overridden.
- **A domain account (`ansible`/renamed `Administrator`) intermittently fails WinRM
  right after a heavy step** though `Get-ADUser` shows it fine — `Set-ADAccountPassword
  -Reset` to the known password + retry.
- **`pf_defender_av` tamper-protection reports "failed"** — expected on any
  non-Intune VM (platform limit). Every other Defender control is fine.

**`site.yml` completing proves AD objects exist, NOT that vulns are exploitable.**
If a Kerberos vuln gives `KDC_ERR_ETYPE_NOSUPP` for *every* principal (not just the
injected account), that's the RC4-deprecation finding — *[fixed] vuln-injection
sets `msDS-SupportedEncryptionTypes = 28`.* On an old lab:
`Set-ADUser -Identity <acct> -Replace @{'msDS-SupportedEncryptionTypes'=28}`.

## 7b. Verify the live domain (users, groups, NT hashes)

```bash
forge ad-inventory specs/<lab>.yml
# generated/<lab>/ad-inventory.md — every user (NT hash, memberships, VULN/PRIV tags) + group
```

Verification, not discovery (`lab-report.md` already has names/passwords ahead of
deploy). NT hashes are only recoverable live (via DCSync), pass-the-hash usable
and crackable (`hashcat -m 1000`). Same sensitivity as `lab-report.md`
(gitignored). Re-run anytime — always reflects live state.

## 8. Verify, then teardown

> **Scripted path (recommended).** The manual steps below explain what the
> generated scripts do. Day to day, use them:
> `forge stop` (graceful powerOff + deallocate, tfstate untouched) ·
> `forge start` (start + tunnel + reachability check, no `apply`) ·
> `forge reset` (re-run `site.yml`; `--snapshot` = OS-disk swap from the clean
> snapshot) · `forge teardown` (type the lab name or `--force`; starts
> deallocated VMs, destroys, sweeps snapshots, verifies the RG 404, purges local
> caches).

```bash
docker exec -w /repo/generated/<lab>/ansible pf-ansible \
  ansible-playbook -i inventory/hosts.yml playbooks/verify.yml

export ARM_SUBSCRIPTION_ID=... ARM_CLIENT_ID=... ARM_TENANT_ID=... ARM_CLIENT_SECRET=...
forge destroy specs/<lab>.yml --yes
```

**`destroy` fails with `Cannot modify extensions ... VM is not running` /
`powerOff ... deallocated`?** `auto_shutdown` already deallocated the VMs.
Terraform deletes extensions first (needs VM running) and powers off the bastion
(needs it not-already-deallocated). Start every VM, wait for `PowerState/running`,
retry:

```bash
SUB=<sub-id>; RG=<lab>
for vm in <lab>-bastion dc01 mbr01 ws01; do   # names from lab-report.md
  az rest --method post --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$vm/start?api-version=2023-07-01"
done
# poll until all PowerState/running, then:
forge destroy specs/<lab>.yml --yes
```

`forge destroy` confirms via ARM REST (`az rest`) that the RG is gone. Confirm
by hand if unsure:

```bash
az rest --method get --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<lab>?api-version=2021-04-01"
# expect ERROR "ResourceGroupNotFound" — that 404 IS the confirmation.
```

Clean up local state (nothing in Azure, but easy to forget):

```bash
docker stop pf-ansible && docker rm pf-ansible
sudo wg-quick down pf-lab
```

## Symptom → cause

| Symptom | Cause | Fix |
|---|---|---|
| `SkuNotAvailable`/`Capacity Restrictions`/`exceeding approved Total Regional Cores` | Subscription/region vCPU cap or SKU restriction | Step 2 — try another region/size |
| `cannot boot Hypervisor Generation '1'` | Gen2-only size + Gen1 image | *[fixed]* for 2016/2019/2022/2025 — check real SKU list before adding an OS (suffix inconsistent) |
| `cannot boot with OS image or disk ... check disk controller types` | NVMe-only size (`F*v7`) + OS with no NVMe (2016) | Override that role to a SCSI size, e.g. `Standard_DC1s_v3` |
| `KDC_ERR_ETYPE_NOSUPP` for EVERY principal | Patched KDC no longer treats unset enc-types as RC4-crackable | *[fixed]* vuln-injection sets it to 28 |
| `destroy`: `Cannot modify extensions ... not running` / `powerOff ... deallocated` | `auto_shutdown` deallocated VMs before destroy | Start VMs, wait `running`, retry — step 8 |
| `Provider produced inconsistent result` / spurious `already exists` | ARM read-after-write lag | Step 4 — `-refresh=false`, import + retry |
| WinRM times out cross-subnet, works same-subnet | Firewall Public-profile `LocalSubnet` scope | *[fixed]* (`windows.tf` bootstrap) |
| `'add_route' is undefined` | Missing GOAD inventory default | *[fixed]* (`hosts.yml.j2`) |
| `domain_admin_user must be in domain\user format` | Bare `"Administrator"` username | *[fixed]* (`forge`) |
| `user name or password is incorrect` on domain-join | Wrong password source for real Administrator | *[fixed]* (see `ad-topology/SKILL.md`) |
| `found unknown escape character` parsing `hosts.yml` | Unescaped `\` in a double-quoted YAML scalar | *[fixed]* (`yaml_scalar()`) |
| Tamper-protection task fails | Intune-only platform limit | *[fixed]* to fail gracefully |
| NTLM rejected against a DC only | Channel Binding Token mismatch | *[fixed]* (`ansible_winrm_transport: basic`) |
| `az vm`/`az network`/`az group show` Python traceback | Broken azure-cli command-loading (some envs) | Use `az rest` against ARM REST |
| `az ad sp create-for-rbac` works but Terraform gets 403/`AuthorizationFailed` | `create-for-rbac` without `--role`/`--scopes` assigns NO role | Add `--role Contributor --scopes /subscriptions/<id>`, or assign via ARM REST |
| `AADSTS700016: Application ... not found` on every call (but `az account show` works) | Stale cached credential / wrong tenant | `az login` as a real user in the subscription's tenant |
| Role assignment `RoleDefinitionDoesNotExist` for the Contributor GUID | Contributor `roleDefinitionId` is per-subscription | Look it up: `GET .../roleDefinitions?$filter=roleName eq 'Contributor'` |
| VM sizing/backend reverts after you fixed it | `generate` re-renders `terraform/` and drops hand-added files | Re-write `sizes.auto.tfvars.json` + `backend.hcl` after every `generate` |
| `terraform init` hangs on the azurerm backend | Fresh SP's Storage RBAC hasn't propagated | Bind by key: `export ARM_ACCESS_KEY=$(... listKeys ...)` before `init` |
| `destroy` clean but RG won't delete (`still contains Resources`) | Something created out-of-band (e.g. a manual snapshot) isn't in state | Delete the stray resource(s) first, then the RG |
| Validation LDAP tools fail `strongerAuthRequired` | Hardening enforces LDAP signing/channel binding | Use a signing-aware client (`nxc`/netexec); `--kdcHost <dc-ip>` when no DNS |
