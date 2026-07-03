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

Domain passwords (used as both the domain admin password and the DSRM/safe
mode password, matching GOAD's own convention) and the shared `ansible`
WinRM automation account password are generated fresh per lab by
`scripts/forge.py generate` and written only into
`generated/<lab>/ansible/inventory/hosts.yml` (gitignored) — never into the
spec or the catalog.

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

## Testing this skill

No live Windows hosts in CI, so validate structurally:

```bash
cd generated/<lab>/ansible && ansible-playbook --syntax-check playbooks/ad-topology.yml
python3 -c "import yaml; yaml.safe_load(open('inventory/hosts.yml'))"  # inventory parses
```
