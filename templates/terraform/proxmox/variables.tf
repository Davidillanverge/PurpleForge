# -----------------------------------------------------------------------------
# Spec-derived variables (set in the committed, shareable terraform.tfvars.json
# by scripts/forge.py — same values on any Proxmox host).
# -----------------------------------------------------------------------------

variable "lab_name" {
  description = "lab.name from the spec; used as the VM-name prefix and the Proxmox resource-pool id."
  type        = string
}

variable "supernet" {
  description = "Lab-wide /16 from lab-manifest.json network_plan.supernet. The WireGuard tunnel NATs toward this on the bastion."
  type        = string
}

variable "management_cidr" {
  description = "Management subnet CIDR (network_plan.management_subnet). Only the bastion's internal NIC lives here; the firewall allows lab hosts to be reached only from this CIDR."
  type        = string
}

variable "jumpbox_private_ip" {
  description = "Static private IP of the bastion's INTERNAL (lab-side) NIC (network_plan.jumpbox_ip). This is the tunnel's ingress into the lab, not how the operator reaches the bastion (that's jumpbox_external_ip)."
  type        = string
}

variable "domains" {
  description = "domain -> {subnet CIDR, VLAN tag, gateway IP}. One /24 + one VLAN id per forest[] entry, assigned deterministically by scripts/forge.py so vulnerable subnets are L2-isolated on the lab bridge. gateway_ip is the bastion's on-subnet address for that domain (the subnet's .254): Windows hosts default-route to it, and deploy.sh brings it up as a VLAN sub-interface on the bastion that routes the domain."
  type = map(object({
    subnet_cidr = string
    vlan_id     = number
    gateway_ip  = string
  }))
}

variable "machines" {
  description = "Flattened machine instances (name/domain/role/os/ip) from lab-manifest.json. template_id overrides the os->template lookup (var.template_map) for one host — e.g. a golden image with an EDR agent pre-installed. `os` still drives the downstream ansible-lockdown/OS behavior regardless of which template backs the VM."
  type = list(object({
    name        = string
    domain      = string
    role        = string # domain-controller | member-server | workstation
    os          = string # one of lab-spec.schema.json's machines[].os enum
    ip          = string
    template_id = optional(number) # per-host template override; null = use var.template_map[os]
  }))
}

variable "wireguard_port" {
  description = "UDP port the bastion's WireGuard interface listens on — the only inbound port the bastion firewall opens."
  type        = number
  default     = 51820
}

variable "wireguard_allowed_cidrs" {
  description = "Source CIDRs allowed to reach the WireGuard UDP port on the bastion's routable NIC. Defaults to any (VPN clients roam); this is NOT Windows/RDP/WinRM exposure — those stay private-only (CLAUDE.md invariant #1)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_username" {
  description = "Local administrator username baked into the Windows templates. Informational here (the templates already have it); surfaced for the lab report."
  type        = string
  default     = "purpleforge"
}

variable "admin_password" {
  description = "Local administrator password. Passed to cloud-init/cloudbase-init on the Windows clones if the template consumes it; generated per-lab, gitignored (secrets.auto.tfvars.json)."
  type        = string
  sensitive   = true
}

variable "ansible_password" {
  description = "Password for the dedicated `ansible` WinRM account baked into the Windows templates. Generated per-lab, gitignored — kept separate from admin_password, matching the Azure layer."
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Host-specific variables — this Proxmox cluster's node/bridges/datastore and
# the vm_ids of the templates the operator maintains. NOT baked at generate
# time (account/host independence): supplied per-deployer in a gitignored
# host.auto.tfvars.json. See host.auto.tfvars.example.json for a filled example.
# -----------------------------------------------------------------------------

variable "node_name" {
  description = "Proxmox VE node the lab's VMs are created on, e.g. \"pve\" (run `pvesh get /nodes`)."
  type        = string
}

variable "datastore_id" {
  description = "Datastore for VM disks, e.g. \"local-lvm\" or \"ceph-vm\"."
  type        = string
}

variable "snippets_datastore_id" {
  description = "Datastore that has the `snippets` content type enabled (the bastion cloud-init user-data is uploaded here). Often \"local\". Enable with: Datacenter > Storage > <ds> > Content > Snippets."
  type        = string
  default     = "local"
}

variable "mgmt_bridge" {
  description = "Routable Linux bridge the bastion's external NIC attaches to (e.g. \"vmbr0\") — this is how the operator running deploy reaches the bastion. Replaces Azure's public IP."
  type        = string
}

variable "lab_bridge" {
  description = "Isolated Linux bridge for the lab's internal AD traffic (e.g. \"vmbr1\", ideally with no internet uplink). Per-domain VLAN tags (var.domains.*.vlan_id) separate the subnets on it. If you only have one bridge, set it equal to mgmt_bridge — the per-domain VLAN tags still isolate the lab, but prefer a dedicated bridge."
  type        = string
}

variable "template_map" {
  description = "os value (machines[].os) -> Proxmox template vm_id to clone. Only the os values used by this lab need an entry. Each template must have the WinRM + `ansible` local admin baked in, plus cloudbase-init (Windows) / cloud-init (bastion) for static-IP injection."
  type        = map(number)
}

variable "bastion_template_id" {
  description = "vm_id of an Ubuntu 22.04+ cloud-init template for the WireGuard bastion (cloud-init + qemu-guest-agent installed)."
  type        = number
}

variable "jumpbox_username" {
  description = "SSH/login username for the WireGuard bastion (the Ubuntu template's cloud-init user)."
  type        = string
  default     = "purpleforge"
}

variable "jumpbox_external_ip" {
  description = "Static IPv4 (no prefix) for the bastion's routable NIC on mgmt_bridge, e.g. \"192.168.1.50\". The operator reaches WireGuard here."
  type        = string
}

variable "jumpbox_external_prefix" {
  description = "CIDR prefix length for jumpbox_external_ip on mgmt_bridge, e.g. 24."
  type        = number
  default     = 24
}

variable "jumpbox_external_gateway" {
  description = "Default gateway on mgmt_bridge for the bastion (so operator traffic + cloud-init package fetch work), e.g. \"192.168.1.1\"."
  type        = string
}

variable "vm_specs_overrides" {
  description = "Optional per-role {cores, memory(MiB)} override, merged over windows.tf's local.spec_map defaults (keys: domain-controller, member-server, workstation)."
  type = map(object({
    cores  = number
    memory = number
  }))
  default = {}
}

variable "bastion_cores" {
  description = "vCPU cores for the WireGuard bastion."
  type        = number
  default     = 1
}

variable "bastion_memory" {
  description = "Memory (MiB) for the WireGuard bastion."
  type        = number
  default     = 1024
}
