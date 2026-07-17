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
# RESILIENCE (learned the hard way): each logical step runs inside Invoke-PfPhase
# so a failure in ONE step never skips the CRITICAL later ones. The old version
# set $ErrorActionPreference='Stop' for the whole script, so the FIRST hiccup
# aborted everything after it — e.g. a wrong WSMan tuning path killed the DC run
# before the 5986 firewall rule AND the built-in-Administrator rename (breaking
# DC promotion), and a benign New-LocalUser race killed the workstation run
# before the HTTPS listener + the `ansible` password were ever set (breaking
# WinRM-over-tunnel). Phases + a race-safe Ensure-LocalAdmin fix both.
#
# Rendered by Terraform (templatefile): the dollar-brace tokens are Terraform
# vars (admin_username / admin_password / ansible_password / supernet).
# PowerShell variables deliberately use the brace-less $name form so Terraform
# does not treat them as interpolation.
# =============================================================================
$ErrorActionPreference = "Stop"

Start-Transcript -Path "$env:SystemDrive\pf-bootstrap.log" -Append -ErrorAction SilentlyContinue | Out-Null

# Run a named phase, containing any (even terminating) error so the following
# phases still execute. cloudbase-init re-runs this script across boot passes, so
# a phase that failed once completes idempotently on the next pass.
function Invoke-PfPhase($Name, [scriptblock]$Body) {
  try { & $Body } catch { Write-Output ("PF-PHASE-FAIL [" + $Name + "]: " + $_.Exception.Message) }
}

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
  try {
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
      Set-LocalUser -Name $Name -Password $sec -PasswordNeverExpires $true
    } else {
      New-LocalUser -Name $Name -Password $sec -PasswordNeverExpires -AccountNeverExpires | Out-Null
    }
  } catch {
    # Raced with cloudbase-init or a prior boot pass that created the account
    # between the Get-LocalUser check and New-LocalUser ("User X already
    # exists"): the account exists, so just (re)assert the password we need.
    Set-LocalUser -Name $Name -Password $sec -PasswordNeverExpires $true
  }
  if (-not (Get-LocalGroupMember -Group $adminGroup -Member $Name -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group $adminGroup -Member $Name
  }
}
Invoke-PfPhase 'local-admins' {
  Ensure-LocalAdmin '${admin_username}' '${admin_password}'
  Ensure-LocalAdmin 'ansible' '${ansible_password}'
}

# --- WinRM: HTTPS 5986 + Basic auth, self-signed cert ----------------------
# Matches the Ansible inventory exactly (transport basic, cert validation
# ignore, port 5986). -SkipNetworkProfileCheck because a freshly cloned host is
# not domain-joined yet, so its NIC is in the Public profile and a plain
# Enable-PSRemoting/winrm quickconfig would refuse.
Invoke-PfPhase 'winrm-https' {
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
  # Optional tuning only; the knob lives under Shell (NOT Service — pointing it
  # at Service throws "path does not exist"). Best-effort, never fatal.
  try { Set-Item -Path WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024 } catch { }
}

# --- Firewall --------------------------------------------------------------
# Allow 5986 from the lab supernet AND the WireGuard client subnet
# (10.250.250.0/24). Ansible/operators reach the DC THROUGH the tunnel: the
# bastion forwards those packets keeping the WG client's source IP (10.250.250.2),
# which is NOT in the lab supernet — a supernet-only rule silently drops WinRM
# over the tunnel (the bug that made 5986 unreachable while 5985 worked). Still
# no inbound from outside these private ranges, so invariant #1 holds.
Invoke-PfPhase 'winrm-firewall' {
  $pfWinrmScopes = @('${supernet}','10.250.250.0/24')
  if (Get-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -RemoteAddress $pfWinrmScopes -Enabled True
  } else {
    New-NetFirewallRule -DisplayName 'PurpleForge-WinRM-HTTPS' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $pfWinrmScopes -Action Allow -Profile Any | Out-Null
  }
  Restart-Service -Name WinRM
}

# --- Free the "Administrator" name for GOAD's promotion-time rename ---------
# The GOAD domain_controller role renames the local ${admin_username} account to
# "Administrator" before creating the forest; it fails with "the name
# Administrator is already in use" if the built-in Administrator still holds it.
# Done in its OWN phase so it ALWAYS runs even if a WinRM step above hiccuped,
# and as a RENAME only (never Disable-LocalUser: disabling the built-in account
# can log off the first-boot autologon session and kill this very script
# mid-run). Renaming keeps the SID, so it doesn't drop the session. Local
# accounts are superseded by the domain's at DC promotion, so this only matters
# for the pre-promotion rename.
Invoke-PfPhase 'free-administrator-name' {
  if ('${admin_username}' -ne 'Administrator') {
    $pfBuiltinAdmin = Get-LocalUser | Where-Object { $_.SID -and $_.SID.Value -match '-500$' }
    if ($pfBuiltinAdmin -and $pfBuiltinAdmin.Name -eq 'Administrator') {
      Rename-LocalUser -Name 'Administrator' -NewName 'AdministratorBuiltin' -ErrorAction SilentlyContinue
    }
  }
}

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
