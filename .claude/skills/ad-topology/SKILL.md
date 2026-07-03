---
name: ad-topology
description: >
  Generates the Ansible inventory and sequences vendor/GOAD's own AD roles
  (domain_controller, domain_controller_slave, child_domain, trusts,
  member_server, commonwkstn) to promote domain controllers, join member
  servers/workstations, and establish trusts — entirely by reusing GOAD's
  roles as-is. Runs after infra-azure/infra-aws's `terraform apply`, before
  ad-theming/vuln-injection.
---

# ad-topology

## When to use this skill

- During `/deploy`, right after infrastructure is up and WinRM is reachable
  (via the WireGuard tunnel), before population/theming.
- Whenever the inventory or playbook needs to change because `forest[]` or
  `machines[]` changed in the spec.

## Reuse, don't fork

Every task in `templates/ansible/playbooks/ad-topology.yml` delegates to a
role that already exists in `vendor/GOAD/ansible/roles/` — this skill's own
code is only the *sequencing* (which host group runs which role, in which
order) and the *inventory generation* (turning `lab-manifest.json` into
`generated/<lab>/ansible/inventory/hosts.yml`). Do not copy GOAD's role
`tasks/main.yml` files into `templates/ansible/roles/`; `ansible.cfg`'s
`roles_path` resolves `vendor/GOAD/ansible/roles` directly.

| Group | Role reused | What it does |
|---|---|---|
| `domain_controllers` (first DC per non-child domain) | `common`, `settings/hostname`, `domain_controller` | `win_domain` + `win_domain_controller` — creates the domain |
| `domain_controllers_additional` (2nd+ DC in any domain) | `common`, `settings/hostname`, `domain_controller_slave` | `win_domain_controller` only — domain already exists |
| `child_domain_controllers` (first DC of a `trust.type: parent-child` domain) | `common`, `settings/hostname`, `child_domain` | `Install-ADDSDomain -ParentDomainName` |
| `trust_anchors` (domains with `trust.type` in `external`/`forest`/`shortcut`) | `trusts` | `CreateTrustRelationship` between forests |
| `member_servers` | `common`, `settings/hostname`, `member_server` | `win_domain_membership` |
| `workstations` | `common`, `settings/hostname`, `commonwkstn` | `win_domain_membership` |

**Parent-child trusts need no separate trust-establishment step** — in
Windows AD, joining a child domain to a forest via `Install-ADDSDomain
-ParentDomainName` (the `child_domain` role) automatically creates a
transitive parent-child trust. The `trusts` role (forest trust relationship
over `System.DirectoryServices.ActiveDirectory`) is only invoked for
`external`/`forest`/`shortcut` trusts between otherwise-separate forests —
don't run it for `parent-child`, it's redundant and the role isn't even
designed for that case (it calls `CreateTrustRelationship` between two
independent forests, not a parent/child pair in the same forest).

## Host naming and per-host variables

`scripts/forge.py generate` assigns each machine a name — `dc01`, `mbr01`,
`ws01`, prefixed with a domain slug (`kingdom-dc01`) when the spec has more
than one domain — and computes the exact per-host variables each GOAD role
expects (they're inconsistent about it: `domain_controller`/`child_domain`
read `domain`, `domain_controller_slave` reads `domain_name` — forge.py sets
both to the same value on every host rather than relying on the reader to
remember which role wants which key). `source_dc` for `child_domain` must be
the parent DC's FQDN (`<root-dc-name>.<parent-domain>`), not just its
inventory alias — `Install-ADDSDomain -ReplicationSourceDC` needs a real DNS
name. `dns_domain` is set to the *inventory hostname* of the domain's root
DC (GOAD's roles read `hostvars[dns_domain].ansible_host` to find the DNS
server IP — it's a host reference, not a domain string, despite the name).

`domain_password` is `admin_password` (the VM's own local admin password),
not a separately-generated secret — **this was the single largest bug found
on a real deploy, correct it before trusting any older explanation**: Azure
forbids `"Administrator"` as a VM's `admin_username`, so every VM's real
local admin is `local_admin_username` (`purpleforge`). Promoting a domain's
first DC seeds the domain's actual RID-500 `Administrator` account from
*that* local account (ad-topology.yml's `pre_tasks` renames it to
`Administrator` right before promotion, since it's still a plain local
rename at that point, not a domain object rename) — its password is
therefore unchanged by promotion, i.e. `admin_password`, not a fresh secret.
GOAD's `domain_controller`/`domain_controller_slave` roles do read
`domain_password` as `safe_mode_password` (DSRM) too, but nothing requires
that to differ from the login password, and several PurpleForge-authored
roles (`ad_theming_overlay`, vuln-injection, `pf_controls`) read the exact
same `domain_username`/`domain_password` inventory vars to authenticate
against the *already-created* domain, where only the real login password
works — conflating the two breaks domain-join ("user name or password is
incorrect") and any later AD object management ("server has rejected the
client credentials") outright. The shared `ansible` WinRM automation account
password is a genuinely separate, freshly-generated secret. Both are
generated by `scripts/forge.py generate` and written only into
`generated/<lab>/ansible/inventory/hosts.yml` (gitignored) — never into the
spec or the catalog.

**Inventory values containing a literal backslash (`domain_username`,
`parent_domain_user`, `remote_admin` — all `NETBIOS\Administrator`) must be
single-quoted, not double-quoted, in `hosts.yml.j2`.** YAML double-quoted
scalars only recognize a fixed escape-sequence set; an unescaped `\A` (as in
`"DUNDERM\Administrator"`) is invalid and `yaml.safe_load` (and Ansible's own
inventory parser) reject the whole file outright — not a warning, a hard
parse failure. Verified on a real deploy: this broke *every* spec, not just
the one being deployed at the time, since the bug was in the shared
template. Single-quoted YAML scalars treat backslash as a literal character,
no escaping needed.

## Cloud vs. GOAD's Vagrant/VirtualBox assumptions

GOAD's roles were written for a dual-NIC Vagrant setup (a NAT adapter for
internet + a host-only/internal adapter for the lab network) and read
`two_adapters`/`nat_adapter`/`domain_adapter` accordingly. PurpleForge's Azure
VMs have a single NIC, so the generated inventory always sets
`two_adapters: false` (which skips every NAT-adapter task — see the `when:`
guards in `common`, `child_domain`, `member_server`, `commonwkstn`) and
`domain_adapter: "Ethernet"` (Azure Windows images' default adapter name).
`dns_server_forwarder` defaults to `168.63.129.16`, Azure's platform DNS
recursive resolver.

## Troubleshooting a real `ansible-playbook site.yml` run (learned from a live deploy, not theory)

- **WinRM (5985/5986) times out from the bastion/WireGuard tunnel to a
  freshly-created host, even though the NSG explicitly allows it and the
  target's WinRM service is confirmed running.** The built-in Windows
  Firewall rule `Windows Remote Management (HTTP-In)` ships as *two* rule
  instances scoped by network profile — the `Domain,Private` instance allows
  `RemoteAddress: Any`, but the **`Public` instance is scoped to
  `RemoteAddress: LocalSubnet`**. Every Azure VM's NIC comes up categorized
  `Public` (nothing promotes it to `Private`, and there's no AD domain yet at
  this point in the sequence to make it `Domain`), so this silently blocks
  WinRM from anything outside the target's own subnet — exactly the
  bastion's situation, since it always lives in a separate management
  subnet (see `network-topology`). No NSG or WinRM-service-level symptom at
  all; same-subnet WinRM (e.g. `dc01` → `mbr01`) works fine, which is what
  makes this confusing to diagnose. Fixed by having `infra-azure`'s
  `winrm_prep` `CustomScriptExtension` add a `New-NetFirewallRule` scoped to
  the lab's own `var.supernet` (not `Any` — WinRM still never reaches the
  internet) right after `ConfigureRemotingForAnsible.ps1` runs. If you hit
  this on a lab generated before that fix landed, running it by hand via
  Azure's `runCommand` API (bypasses WinRM entirely, uses the VM agent) on
  each host is the fastest unblock.
- **`ansible_winrm_transport: ntlm` gets "the specified credentials were
  rejected by the server" against a domain controller specifically, while
  the exact same credentials work fine over the same transport against
  member servers/workstations, AND work fine via a local
  `Invoke-Command -Credential` test run directly on the DC (i.e. the
  password is definitely correct).** This looks identical to a wrong
  password but isn't — verified on a real deploy. Suspected cause: NTLM's
  Channel Binding Token computation over HTTPS with a self-signed cert
  (`ansible_winrm_server_cert_validation: ignore`) behaves differently once
  the host is a DC. Fixed by setting `ansible_winrm_transport: basic`
  globally instead — Basic auth has no CBT step to mismatch, it's already
  confirmed enabled (`WSMan:\localhost\Service\Auth\Basic`), and this is
  still HTTPS inside the NSG-isolated management-subnet-only WinRM path, not
  Basic-over-HTTP.
- **GOAD's `common` role fails immediately with `'add_route' is undefined`**
  (`vendor/GOAD/ansible/roles/common/tasks/main.yml`'s "Add a network static
  route" task, gated on `when: add_route == "yes"`). GOAD's own inventories
  always set this var (used for its Vagrant dual-NIC setup); PurpleForge's
  single-NIC Azure inventory didn't. Fixed by adding `add_route: "no"`
  alongside `two_adapters: false` in `hosts.yml.j2`'s global vars.
- **A domain user literally named `ansible`, freshly domain-absorbed by the
  same promotion mechanism described above for `Administrator`, sometimes
  needs its password re-set with `Set-ADAccountPassword -Reset` even though
  `Get-ADUser` shows it enabled, unlocked, with `BadPwdCount: 0`.** Root
  cause not fully isolated on the one real deploy that hit it (possibly
  transient LSASS/Netlogon load from a heavy `BadBlood` run finishing right
  before); a `Set-ADAccountPassword -Reset` to the known
  `ansible_password` value plus retrying the play resolved it. If WinRM
  auth to a *specific* host regresses mid-`site.yml` run after previously
  working earlier in the same run, this account-absorption class of issue is
  the first thing to check, not a credentials typo.

## Testing this skill

No live Windows hosts in CI, so validate structurally:

```bash
cd generated/<lab>/ansible && ansible-playbook --syntax-check playbooks/ad-topology.yml
python3 -c "import yaml; yaml.safe_load(open('inventory/hosts.yml'))"  # inventory parses
```
