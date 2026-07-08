variable "lab_name" {
  description = "lab.name from the spec; used as the resource-name prefix."
  type        = string
}

variable "location" {
  description = "lab.region from the spec (Azure location name, e.g. westeurope)."
  type        = string
}

variable "supernet" {
  description = "Lab-wide /16 from lab-manifest.json network_plan.supernet."
  type        = string
}

variable "management_cidr" {
  description = "Management/bastion subnet CIDR (network_plan.management_subnet)."
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
  description = "Flattened machine instances with assigned name/domain/role/os/ip (from lab-manifest.json, named by scripts/forge.py during generate)."
  type = list(object({
    name     = string
    domain   = string
    role     = string # domain-controller | member-server | workstation
    os       = string # one of lab-spec.schema.json's machines[].os enum
    ip       = string
    image_id = optional(string) # machines[].image_id override — a managed image or Shared Image Gallery version resource ID, e.g. a golden workstation image with an EDR agent pre-installed. null (the default) means "use the marketplace publisher/offer/sku for os instead" — see windows.tf.
    vm_size  = optional(string) # machines[].vm_size override from the spec. null (the default) means "use windows.tf's per-role local.size_map / var.vm_size_overrides".
  }))
}

variable "admin_username" {
  description = "Local administrator username for every Windows VM."
  type        = string
  default     = "purpleforge"
}

variable "admin_password" {
  description = "Local administrator password for every Windows VM. Generate per-lab, never commit — lives only in generated/<lab>/ (gitignored)."
  type        = string
  sensitive   = true
}

variable "ansible_password" {
  description = "Password for the dedicated local 'ansible' automation account created on every Windows VM for WinRM (kept separate from admin_username/admin_password, following vendor/GOAD/template/provider/*/windows.tf's convention). Generate per-lab, never commit."
  type        = string
  sensitive   = true
}

variable "jumpbox_username" {
  description = "SSH username for the WireGuard bastion (Ubuntu)."
  type        = string
  default     = "purpleforge"
}

variable "bastion_size" {
  type    = string
  default = "Standard_B1s"
}

variable "vm_size_overrides" {
  description = "Optional per-role VM size override (keys: domain-controller, member-server, workstation), merged over windows.tf's local.size_map Burstable-family defaults. Some Azure subscriptions (free/trial/sponsored) restrict the entire B-series family with a persistent 'NotAvailableForSubscription' SKU restriction in every mainstream region — set this (e.g. to a Dv3-series size) when that's the case rather than editing the hardcoded defaults, which are the right cost-optimized choice for a normal pay-as-you-go subscription."
  type        = map(string)
  default     = {}
}

variable "os_overrides" {
  description = "Deploy-time per-role Windows image override (keys: domain-controller, member-server, workstation), each a value present in windows.tf's local.os_image_map (or added via custom_os_images) — e.g. \"windows-server-2022\". Set by deploy.sh from PF_OS, and overrides the os baked into machines[] at generate time so the SAME committed lab can redeploy on a newer/different stock Windows image without regenerating. A per-machine machines[].image_id pin still wins. Empty (default) = every VM keeps its baked os. NOTE: this swaps only the backing marketplace image — the ansible-lockdown hardening baseline still targets the os chosen at generate time (regenerate the spec to change that)."
  type        = map(string)
  default     = {}
}

variable "image_id_overrides" {
  description = "Deploy-time per-role custom image override (same role keys as os_overrides): a managed image or Shared Image Gallery version resource ID cloned for every VM of that role — e.g. a golden image with an EDR agent/tooling pre-installed. Set by deploy.sh from PF_IMAGE_ID. Takes precedence over os/os_overrides for that role (a source_image_id and a marketplace source_image_reference are mutually exclusive). A per-machine machines[].image_id pin still wins over this. Empty (default) = use the marketplace image for os."
  type        = map(string)
  default     = {}
}

variable "custom_os_images" {
  description = "Extra marketplace image definitions merged over windows.tf's built-in os->{publisher,offer,sku} map, letting os_overrides (PF_OS) name a Windows image PurpleForge ships no mapping for (a specific SKU or a non-default publisher). Set by deploy.sh from PF_IMAGE_PUBLISHER/PF_IMAGE_OFFER/PF_IMAGE_SKU under the key given by PF_OS. Keys already in the built-in map are overridden."
  type = map(object({
    publisher = string
    offer     = string
    sku       = string
  }))
  default = {}
}

variable "image_version_override" {
  description = "Marketplace image version used for the source_image_reference of every marketplace-backed VM (default \"latest\" = current behavior). Set by deploy.sh from PF_IMAGE_VERSION; typically paired with PF_IMAGE_SKU to pin a specific custom image version. Hosts using image_id/image_id_overrides ignore this (they clone by resource ID)."
  type        = string
  default     = "latest"
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

variable "auto_shutdown_time" {
  description = "lab.auto_shutdown's time component, HHMM (e.g. 2000 for 20:00) — CLAUDE.md invariant #4: every deployment carries auto_shutdown."
  type        = string
}

variable "auto_shutdown_timezone" {
  description = "Legacy Windows timezone ID (e.g. \"Romance Standard Time\" for Europe/Madrid) required by azurerm_dev_test_global_vm_shutdown_schedule.timezone — verified against a real `terraform plan` (azurerm 3.117.1) that IANA names like \"Europe/Madrid\" are rejected outright, not just discouraged. scripts/forge.py's IANA_TO_WINDOWS_TIMEZONE map does the lab.auto_shutdown IANA-zone -> Windows-ID translation before this variable is set in terraform.tfvars.json."
  type        = string
}
