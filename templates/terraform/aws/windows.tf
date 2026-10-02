# Windows VM shape mirrors templates/terraform/azure/windows.tf: private-IP-only
# EC2 instances (no public IP ever attached to a Windows host), a WinRM
# bootstrap run from user_data (the AWS analogue of Azure's
# CustomScriptExtension running Ansible's ConfigureRemotingForAnsible.ps1), and
# WinRM reachable only from the management/bastion subnet via the domain SG.

locals {
  # Stock Windows AMIs are resolved from AWS's public SSM parameters
  # (/aws/service/ami-windows-latest/...), the AWS-recommended way to always get
  # the current, region-correct AMI without hardcoding ami-ids. These are the
  # first-party "English-Full-Base" Windows Server images.
  #
  # CLIENT OS CAVEAT (windows-10-22h2 / windows-11-23h2): AWS does NOT publish
  # desktop/client Windows as stock EC2 AMIs (unlike Azure's MicrosoftWindowsDesktop
  # marketplace offers). A client-OS machine on AWS therefore REQUIRES a
  # machines[].image_id / image_id_overrides AMI (a BYOL image you built and
  # own). These entries map to "" as a sentinel; a machine that resolves to ""
  # with no image_id fails the precondition on the instance below with a clear
  # message rather than a confusing SSM "parameter not found".
  os_ssm_map = merge({
    "windows-server-2016" = "/aws/service/ami-windows-latest/Windows_Server-2016-English-Full-Base"
    "windows-server-2019" = "/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base"
    "windows-server-2022" = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
    "windows-server-2025" = "/aws/service/ami-windows-latest/Windows_Server-2025-English-Full-Base"
    "windows-10-22h2"     = "" # client OS — supply a BYOL image_id (see caveat above)
    "windows-11-23h2"     = "" # client OS — supply a BYOL image_id (see caveat above)
  }, var.os_ssm_overrides)

  instance_type_map = merge({
    "domain-controller" = "t3.medium"
    "member-server"     = "t3.medium"
    "workstation"       = "t3.medium"
  }, var.instance_type_overrides)

  machines_by_name = { for m in var.machines : m.name => m }

  # Effective backing image per machine, resolving deploy-time overrides against
  # the values baked in at generate time. Precedence, most specific first:
  #   image_id : per-machine machines[].image_id (AMI) > per-role image_id_overrides
  #   os       : per-role os_overrides                 > per-machine machines[].os
  # A resolved image_id (AMI) wins over the SSM lookup for os.
  effective_image_id = {
    for k, m in local.machines_by_name :
    k => m.image_id != null ? m.image_id : lookup(var.image_id_overrides, m.role, null)
  }
  effective_os = {
    for k, m in local.machines_by_name :
    k => lookup(var.os_overrides, m.role, m.os)
  }

  # Distinct os values that actually need an SSM lookup (no resolved image_id and
  # a non-empty SSM parameter name), so a lab with only BYOL/client images makes
  # zero SSM data reads and a server-only lab resolves just the ones it uses.
  ssm_os_needed = toset([
    for k, m in local.machines_by_name :
    local.effective_os[k]
    if local.effective_image_id[k] == null && local.os_ssm_map[local.effective_os[k]] != ""
  ])
}

data "aws_ssm_parameter" "windows_ami" {
  for_each = local.ssm_os_needed
  name     = local.os_ssm_map[each.value]
}

resource "aws_instance" "windows" {
  for_each = local.machines_by_name

  # A resolved image_id (AMI) wins; otherwise the SSM-resolved stock AMI for the
  # effective os.
  ami = coalesce(
    local.effective_image_id[each.key],
    local.os_ssm_map[local.effective_os[each.key]] != "" ? data.aws_ssm_parameter.windows_ami[local.effective_os[each.key]].value : null,
  )
  instance_type = local.instance_type_map[each.value.role]

  network_interface {
    network_interface_id = aws_network_interface.windows[each.key].id
    device_index         = 0
  }

  # user_data runs once on first boot (EC2Launch handles the <powershell> block).
  # It sets the built-in Administrator (RID-500) password — the account the new
  # forest's domain Administrator inherits at DCPromo — then creates the dedicated
  # 'ansible' WinRM account, runs Ansible's ConfigureRemotingForAnsible.ps1, and
  # opens WinRM to the lab's own supernet only (never the internet: invariant #1).
  # Passwords are passed to net user double-quoted; generate_password already
  # excludes shell-hostile characters as belt-and-braces.
  user_data = <<-POWERSHELL
    <powershell>
    net user Administrator "${var.admin_password}"
    net user ansible "${var.ansible_password}" /add /expires:never /y
    net localgroup administrators ansible /add
    $ErrorActionPreference = "Stop"
    $url = "https://raw.githubusercontent.com/ansible/ansible/38e50c9f819a045ea4d40068f83e78adbfaf2e68/examples/scripts/ConfigureRemotingForAnsible.ps1"
    $dst = "$env:TEMP\ConfigureRemotingForAnsible.ps1"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $dst
    powershell -ExecutionPolicy Unrestricted -File $dst
    New-NetFirewallRule -DisplayName "PurpleForge-WinRM-VPC" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -RemoteAddress ${var.supernet} -Action Allow -Profile Any
    </powershell>
    <persist>false</persist>
  POWERSHELL

  lifecycle {
    precondition {
      condition     = local.effective_image_id[each.key] != null || local.os_ssm_map[local.effective_os[each.key]] != ""
      error_message = "Machine '${each.key}' uses os '${local.effective_os[each.key]}', which AWS does not publish as a stock EC2 AMI (client Windows). Set machines[].image_id (or image_id_overrides for role '${each.value.role}') to a BYOL AMI id."
    }
  }

  tags = { Name = each.value.name }
}

resource "aws_network_interface" "windows" {
  for_each = local.machines_by_name

  subnet_id       = aws_subnet.domain[each.value.domain].id
  private_ips     = [each.value.ip]
  security_groups = [aws_security_group.domain[each.value.domain].id]

  tags = { Name = "${var.lab_name}-${each.value.name}-eni" }
}
