---
name: ad-topology
description: >
  Generates the Ansible inventory and sequences vendor/GOAD's own AD roles
  (domain_controller, domain_controller_slave, child_domain, trusts,
  member_server, commonwkstn) to promote DCs, join member servers/workstations,
  and establish trusts — reusing GOAD's roles as-is. Runs after infra-azure's
  `terraform apply`, before ad-theming/vuln-injection.
---

# ad-topology

## When to use

- `/deploy`, right after infra is up and WinRM is reachable (via the tunnel),
  before population/theming.
- When inventory/playbook must change because `forest[]`/`machines[]` changed.

## Reuse, don't fork

Every task in `ad-topology.yml` delegates to a role in
`vendor/GOAD/ansible/roles/`. This skill's own code is only the *sequencing* and
the *inventory generation* (`lab-manifest.json` → `inventory/hosts.yml`). Don't
copy GOAD role `tasks/` into `templates/`; `ansible.cfg`'s `roles_path` resolves
`vendor/GOAD/ansible/roles` directly.

| Group | Role reused | Does |
|---|---|---|
| `domain_controllers` (first DC per non-child domain) | `common`, `settings/hostname`, `domain_controller` | `win_domain` + `win_domain_controller` — creates the domain |
| `domain_controllers_additional` (2nd+ DC) | + `domain_controller_slave` | `win_domain_controller` only |
| `child_domain_controllers` (first DC of a `parent-child` domain) | + `child_domain` | `Install-ADDSDomain -ParentDomainName` |
| `trust_anchors` (`external`/`forest`/`shortcut` trusts) | `trusts` | `CreateTrustRelationship` between forests |
| `member_servers` | + `member_server` | `win_domain_membership` |
| `workstations` | + `commonwkstn` | `win_domain_membership` |

**Parent-child trusts need no separate step** — `Install-ADDSDomain
-ParentDomainName` auto-creates the transitive trust. The `trusts` role is only
for `external`/`forest`/`shortcut` between separate forests; don't run it for
`parent-child` (it's built for two independent forests, not a parent/child pair).

## Host naming and per-host vars

`forge.py generate` names each machine `dc01`/`mbr01`/`ws01`, domain-slug-prefixed
(`kingdom-dc01`) when >1 domain. GOAD roles are inconsistent about var keys
(`domain_controller`/`child_domain` read `domain`; `domain_controller_slave`
reads `domain_name`) — forge.py sets both to the same value. `source_dc` for
`child_domain` must be the parent DC's FQDN (`<root-dc>.<parent-domain>`), not the
inventory alias. `dns_domain` is set to the *inventory hostname* of the domain's
root DC (GOAD reads `hostvars[dns_domain].ansible_host` — a host reference,
despite the name).

**`domain_password` = `admin_password`** (the VM's local admin), NOT a separate
secret — the biggest bug found on a real deploy. Azure forbids `"Administrator"`
as `admin_username`, so every VM's real local admin is `purpleforge`; promoting
the first DC seeds the domain RID-500 `Administrator` from that account
(ad-topology.yml `pre_tasks` renames it right before promotion), so its password
stays `admin_password`. GOAD roles also read `domain_password` as DSRM
`safe_mode_password` (fine to be the same). PurpleForge roles
(`ad_theming_overlay`, vuln-injection, `pf_controls`) authenticate against the
already-created domain with the same `domain_username`/`domain_password`, where
only the real login password works — conflating the two breaks domain-join and AD
object management. The `ansible` WinRM account password is a separate generated
secret. Both are written only to `inventory/hosts.yml` (gitignored).

**Values with a literal backslash (`domain_username`, `parent_domain_user`,
`remote_admin` = `NETBIOS\Administrator`) must be SINGLE-quoted in
`hosts.yml.j2`.** A double-quoted YAML scalar with `\A` is an invalid escape and
`yaml.safe_load` (and Ansible's parser) reject the whole file — a hard parse
failure that broke *every* spec (shared template). Single quotes treat `\` as
literal.

## Cloud vs GOAD's Vagrant assumptions

GOAD roles assume dual-NIC Vagrant (`two_adapters`/`nat_adapter`/`domain_adapter`).
Azure VMs have one NIC, so the inventory always sets `two_adapters: false` (skips
NAT-adapter tasks) and `domain_adapter: "Ethernet"`. `dns_server_forwarder`
defaults to `168.63.129.16` (Azure platform DNS). Also set `add_route: "no"`
(GOAD's `common` route task is gated on it and errors `'add_route' is undefined`
otherwise).

## Live-run gotchas

- **WinRM (5985/5986) times out from the bastion to a fresh host though the NSG
  allows it and WinRM is running.** The built-in `Windows Remote Management
  (HTTP-In)` firewall rule's **Public-profile instance is scoped
  `RemoteAddress: LocalSubnet`**; every Azure NIC comes up `Public`, so WinRM is
  blocked from outside the target's subnet (i.e. the bastion). Same-subnet WinRM
  works, which makes it confusing. Fixed: `infra-azure`'s `winrm_prep` adds a
  `New-NetFirewallRule` scoped to `var.supernet`. On an old lab, run it by hand
  via Azure `runCommand` (bypasses WinRM).
- **`ntlm` transport → "credentials rejected" against a DC only**, same creds
  working on member servers and via local `Invoke-Command`. NTLM Channel Binding
  Token over HTTPS with a self-signed cert behaves differently on a DC. Fixed:
  `ansible_winrm_transport: basic` globally (no CBT step; still HTTPS inside the
  isolated management subnet).
- **A domain user literally named `ansible`, freshly domain-absorbed, sometimes
  needs `Set-ADAccountPassword -Reset`** even though `Get-ADUser` shows it
  enabled/unlocked/`BadPwdCount: 0`. Reset to the known password + retry. If
  WinRM auth to a specific host regresses mid-`site.yml` after working earlier,
  check this first, not a typo.

## Testing (structural — no live hosts)

```bash
cd generated/<lab>/ansible && ansible-playbook --syntax-check playbooks/ad-topology.yml
python3 -c "import yaml; yaml.safe_load(open('inventory/hosts.yml'))"
```
