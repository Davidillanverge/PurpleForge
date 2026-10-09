variable "lab_name" {
  description = "lab.name from the spec; used as the resource-name prefix and the lab/project default tag everything is scoped by."
  type        = string
}

variable "region" {
  description = "lab.region from the spec (AWS region, e.g. eu-west-1)."
  type        = string
}

variable "supernet" {
  description = "Lab-wide /16 from lab-manifest.json network_plan.supernet — the VPC CIDR."
  type        = string
}

variable "management_cidr" {
  description = "Management/bastion subnet CIDR (network_plan.management_subnet). The only subnet with a route to the internet gateway."
  type        = string
}

variable "jumpbox_private_ip" {
  description = "Static private IP for the WireGuard bastion (network_plan.jumpbox_ip)."
  type        = string
}

variable "domains" {
  description = "domain -> subnet CIDR, one /24 per forest[] entry (network_plan.domains.*.subnet)."
  type = map(object({
    subnet_cidr = string
  }))
}

variable "machines" {
  description = "Flattened machine instances with assigned name/domain/role/os/ip (from lab-manifest.json, named by scripts/forge/ during generate)."
  type = list(object({
    name     = string
    domain   = string
    role     = string # domain-controller | member-server | workstation
    os       = string # one of lab-spec.schema.json's machines[].os enum
    ip       = string
    image_id = optional(string) # machines[].image_id override — an AMI id (ami-xxxxxxxx), e.g. a golden workstation image with an EDR agent pre-installed. null (the default) means "resolve the stock Windows AMI for os via SSM" — see windows.tf.
  }))
}

variable "admin_username" {
  description = "Local administrator username configured on every Windows VM. NOTE: EC2 Windows AMIs ship an enabled built-in Administrator (RID-500); the user_data bootstrap sets ITS password to admin_password rather than creating a second account, so the account the domain inherits at DCPromo is the one Ansible drives (see windows.tf)."
  type        = string
  default     = "purpleforge"
}

variable "admin_password" {
  description = "Local administrator password for every Windows VM. Generate per-lab, never commit — lives only in generated/<lab>/ (gitignored)."
  type        = string
  sensitive   = true
}

variable "ansible_password" {
  description = "Password for the dedicated local 'ansible' automation account created on every Windows VM for WinRM (kept separate from admin, following vendor/GOAD's convention). Generate per-lab, never commit."
  type        = string
  sensitive   = true
}

variable "jumpbox_username" {
  description = "SSH username for the WireGuard bastion (Ubuntu)."
  type        = string
  default     = "purpleforge"
}

variable "bastion_instance_type" {
  description = "EC2 instance type for the WireGuard bastion. t3.micro is enough: it only forwards WireGuard + NATs the private subnets."
  type        = string
  default     = "t3.micro"
}

variable "instance_type_overrides" {
  description = "Optional per-role EC2 instance type override (keys: domain-controller, member-server, workstation), merged over windows.tf's local.instance_type_map defaults. Set this when a region/account lacks the default family or needs more memory, rather than editing the hardcoded defaults."
  type        = map(string)
  default     = {}
}

variable "os_overrides" {
  description = "Deploy-time per-role Windows image override (keys: domain-controller, member-server, workstation), each a value present in windows.tf's local.os_ssm_map — e.g. \"windows-server-2022\". Set by deploy.sh from PF_OS, and overrides the os baked into machines[] at generate time so the SAME committed lab can redeploy on a different stock Windows image without regenerating. A per-machine machines[].image_id (AMI) pin still wins. Empty (default) = every VM keeps its baked os. NOTE: this swaps only the backing AMI — the ansible-lockdown hardening baseline still targets the os chosen at generate time."
  type        = map(string)
  default     = {}
}

variable "image_id_overrides" {
  description = "Deploy-time per-role custom AMI override (same role keys as os_overrides): an AMI id (ami-xxxxxxxx) used for every VM of that role — e.g. a golden image with an EDR agent/tooling pre-installed. Set by deploy.sh from PF_IMAGE_ID. Takes precedence over os/os_overrides for that role. A per-machine machines[].image_id pin still wins over this. Empty (default) = resolve the stock Windows AMI for os via SSM."
  type        = map(string)
  default     = {}
}

variable "os_ssm_overrides" {
  description = "Extra os -> SSM-parameter-name entries merged over windows.tf's built-in os_ssm_map, letting os_overrides (PF_OS) name a Windows image PurpleForge ships no mapping for (e.g. a Core or non-English SKU). Set by deploy.sh from PF_IMAGE_SSM under the key given by PF_OS. An empty-string value marks an os as client/BYOL-only (resolve via image_id instead)."
  type        = map(string)
  default     = {}
}

variable "wireguard_port" {
  description = "UDP port the bastion's WireGuard interface listens on. This is the ONLY inbound port ever exposed to the internet in this template."
  type        = number
  default     = 51820
}

variable "wireguard_allowed_cidrs" {
  description = "Source CIDRs allowed to reach the WireGuard UDP port. Defaults to the internet because VPN clients roam; this is not a Windows/RDP/WinRM exposure — see CLAUDE.md invariant #1."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "bastion_ssh_allowed_cidrs" {
  description = "Source CIDRs allowed to SSH into the bastion directly (e.g. for initial troubleshooting). Empty by default: no SSH rule is created, so the bastion has zero inbound surface besides WireGuard."
  type        = list(string)
  default     = []
}

variable "auto_shutdown_cron" {
  description = "lab.auto_shutdown's time as an EventBridge Scheduler cron(...) expression (e.g. \"cron(0 20 * * ? *)\" for 20:00). Unlike Azure, EventBridge accepts an IANA timezone directly (auto_shutdown_timezone), so no Windows-timezone translation is needed — CLAUDE.md invariant #4."
  type        = string
}

variable "auto_shutdown_timezone" {
  description = "IANA timezone name (e.g. \"Europe/Madrid\") for the auto_shutdown schedule. EventBridge Scheduler accepts IANA names natively."
  type        = string
}

variable "endpoint_probes" {
  description = "role -> TCP connectivity probes (proto/port/required), rendered by forge from core.ENDPOINT_PROBES. Published per node in the lab_endpoints output so the lifecycle scripts discover what to probe instead of hardcoding ports."
  type = map(list(object({
    proto    = string
    port     = number
    required = bool
  })))
  default = {}
}
