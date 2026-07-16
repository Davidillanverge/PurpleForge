#ps1_sysnative
# =============================================================================
# PurpleForge — Windows first-boot bootstrap, run by cloudbase-init's
# UserDataPlugin on the cloned VM. This is the on-prem twin of the Azure layer's
# ConfigureRemotingForAnsible.ps1 CustomScriptExtension: it means the Proxmox
# template does NOT need WinRM or the `ansible` account pre-baked — only
# cloudbase-init (which is required anyway for the static IP). Everything below
# is idempotent, so a template that already has these baked is unharmed.
#
# It must run fully OFFLINE: the lab bridge is isolated (no internet uplink), so
# nothing is downloaded — the WinRM setup is inlined here, not fetched.
#
# Rendered by Terraform (templatefile): the dollar-brace tokens are Terraform
# vars (admin_username / admin_password / ansible_password / supernet).
# PowerShell variables deliberately use the brace-less $name form so Terraform
# does not treat them as interpolation.
# =============================================================================
$ErrorActionPreference = "Stop"

Start-Transcript -Path "$env:SystemDrive\pf-bootstrap.log" -Append -ErrorAction SilentlyContinue | Out-Null

# --- Local admin accounts --------------------------------------------------
# purpleforge  : the domain-admin-to-be. The GOAD domain_controller role renames
#                this local account to the real Administrator at DC promotion, so
#                its LOGIN password must be admin_password (see forge.py
#                build_ansible_groups). cloudbase-init's user_account also sets
#                this; re-asserting here is a harmless belt-and-braces in case a
#                custom user-data drops cipassword.
# ansible      : the dedicated WinRM automation account Ansible connects as
#                (inventory ansible_user: ansible), kept separate from the admin.
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'   # 'Administrators', locale-independent
function Ensure-LocalAdmin($Name, $Password) {
  $sec = ConvertTo-SecureString $Password -AsPlainText -Force
  if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name $Name -Password $sec -PasswordNeverExpires $true
  } else {
    New-LocalUser -Name $Name -Password $sec -PasswordNeverExpires -AccountNeverExpires | Out-Null
  }
  if (-not (Get-LocalGroupMember -Group $adminGroup -Member $Name -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group $adminGroup -Member $Name
  }
}
# Free the "Administrator" name for GOAD's promotion-time rename. The
# domain_controller role renames the local ${admin_username} account to
# "Administrator"; that fails with "The name Administrator is already in use" if
# the built-in Administrator (RID 500) still holds the name (as it does on any
# stock Windows image where it's enabled). Rename+disable the built-in one out of
# the way first — unless the admin IS the built-in Administrator. Local accounts
# are superseded by the domain's at DC promotion, so this only matters pre-promo.
if ('${admin_username}' -ne 'Administrator') {
  $pfBuiltinAdmin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
  if ($pfBuiltinAdmin -and $pfBuiltinAdmin.Name -eq 'Administrator') {
    Disable-LocalUser -Name $pfBuiltinAdmin.Name -ErrorAction SilentlyContinue
    Rename-LocalUser -Name $pfBuiltinAdmin.Name -NewName 'Administrator.builtin' -ErrorAction SilentlyContinue
  }
}

Ensure-LocalAdmin '${admin_username}' '${admin_password}'
Ensure-LocalAdmin 'ansible' '${ansible_password}'

# --- WinRM: HTTPS 5986 + Basic auth, self-signed cert ----------------------
# Matches the Ansible inventory exactly (transport basic, cert validation
# ignore, port 5986). -SkipNetworkProfileCheck because a freshly cloned host is
# not domain-joined yet, so its NIC is in the Public profile and a plain
# Enable-PSRemoting/winrm quickconfig would refuse.
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null

# Self-signed cert bound to this host's name (reuse one if it already exists).
$cn = $env:COMPUTERNAME
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$cn" } | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -DnsName $cn -CertStoreLocation Cert:\LocalMachine\My
}

# (Re)create the HTTPS listener on 5986 bound to that cert.
Get-ChildItem WSMan:\localhost\Listener |
  Where-Object { $_.Keys -contains 'Transport=HTTPS' } |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null

# Auth: Basic over HTTPS (no CBT step to mismatch on a DC — see the inventory
# comment). Unencrypted stays off; this is HTTPS.
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\localhost\Service\MaxMemoryPerShellMB -Value 1024 -ErrorAction SilentlyContinue

# --- Firewall --------------------------------------------------------------
# Allow 5986 from the lab supernet AND the WireGuard client subnet
# (10.250.250.0/24). Ansible/operators reach the DC THROUGH the tunnel: the
# bastion forwards those packets keeping the WG client's source IP (10.250.250.2),
# which is NOT in the lab supernet — a supernet-only rule silently drops WinRM
# over the tunnel (the bug that made 5986 unreachable while 5985 worked). Still
# no inbound from outside these private ranges, so invariant #1 holds.
$pfWinrmScopes = @('${supernet}','10.250.250.0/24')
if (Get-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -ErrorAction SilentlyContinue) {
  Set-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -RemoteAddress $pfWinrmScopes -Enabled True
} else {
  New-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $pfWinrmScopes -Action Allow -Profile Any | Out-Null
}

Restart-Service -Name WinRM
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
