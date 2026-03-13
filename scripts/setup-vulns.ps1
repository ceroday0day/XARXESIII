<#
.SYNOPSIS
    Vulnerability Setup — Applies deliberate misconfigurations for the attack chain.

.DESCRIPTION
    Configures the following vulnerabilities:
    1. AS-REP Roasting: b.white — no Kerberos preauthentication
    2. ACL Abuse: svc_monitor has GenericWrite over svc_backup
    3. DCSync: svc_deploy has Replicating Directory Changes All
    4. GPO Misconfiguration: IT_Admins can edit Default Domain Policy
    5. AdminSDHolder abuse path
    6. Skeleton Key–friendly environment (WDigest enabled)

.PARAMETER DomainName
    FQDN of the domain
#>
param(
    [Parameter(Mandatory)][string]$DomainName
)

$ErrorActionPreference = "Stop"
$VerbosePreference     = "Continue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp][$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "OK"    { "Green" }
            default { "Cyan" }
        }
    )
}

$domainParts = $DomainName.Split(".")
$domainDN    = ($domainParts | ForEach-Object { "DC=$_" }) -join ","

Import-Module ActiveDirectory -ErrorAction Stop

Write-Log "Applying vulnerability chain to $DomainName..."

# ═══════════════════════════════════════════════════════════════════════════
# VULN 1: AS-REP Roasting — Dr. Bob White
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 1: Enabling AS-REP Roasting for b.white..."
try {
    Set-ADAccountControl -Identity "b.white" -DoesNotRequirePreAuth $true
    Write-Log "b.white: 'Do not require Kerberos preauthentication' ENABLED" -Level "OK"
} catch {
    Write-Log "Failed to configure AS-REP Roasting: $_" -Level "ERROR"
}

# ═══════════════════════════════════════════════════════════════════════════
# VULN 2: ACL Abuse — svc_monitor → GenericWrite → svc_backup
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 2: Granting svc_monitor GenericWrite over svc_backup..."
try {
    $monitorUser = Get-ADUser -Identity "svc_monitor"
    $backupUser  = Get-ADUser -Identity "svc_backup"

    $monitorSID = [System.Security.Principal.SecurityIdentifier]$monitorUser.SID
    $backupDN   = $backupUser.DistinguishedName

    # Build ACE: GenericWrite for svc_monitor on svc_backup object
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $monitorSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $backupObj = [ADSI]"LDAP://$backupDN"
    $backupObj.ObjectSecurity.AddAccessRule($ace)
    $backupObj.CommitChanges()

    Write-Log "svc_monitor has GenericWrite over svc_backup" -Level "OK"
} catch {
    Write-Log "Failed to configure ACL abuse: $_" -Level "ERROR"
}

# ═══════════════════════════════════════════════════════════════════════════
# VULN 3: DCSync — svc_deploy gets Replicating Directory Changes All
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 3: Granting DCSync rights to svc_deploy..."
try {
    $deployUser = Get-ADUser -Identity "svc_deploy"
    $deploySID  = [System.Security.Principal.SecurityIdentifier]$deployUser.SID

    # Replicating Directory Changes           = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    # Replicating Directory Changes All       = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
    # Replicating Directory Changes In Filtered Set = 89e95b76-444d-4c62-991a-0facbeda640c
    $guidReplChanges    = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $guidReplChangesAll = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

    $domainObj = [ADSI]"LDAP://$domainDN"

    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $deploySID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $guidReplChanges
    )
    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $deploySID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $guidReplChangesAll
    )

    $domainObj.ObjectSecurity.AddAccessRule($ace1)
    $domainObj.ObjectSecurity.AddAccessRule($ace2)
    $domainObj.CommitChanges()

    Write-Log "svc_deploy has DCSync rights (Replicating Directory Changes All)" -Level "OK"
} catch {
    Write-Log "Failed to configure DCSync: $_" -Level "ERROR"
}

# ═══════════════════════════════════════════════════════════════════════════
# VULN 4: GPO Misconfiguration — IT_Admins can edit Default Domain Policy
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 4: Granting IT_Admins write access to Default Domain Policy..."
try {
    $itAdmins   = Get-ADGroup -Identity "IT_Admins"
    $itAdminSID = [System.Security.Principal.SecurityIdentifier]$itAdmins.SID

    # Default Domain Policy GUID is always {31B2F340-016D-11D2-945F-00C04FB984F9}
    $gpoPath = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDN"
    $gpoObj  = [ADSI]"LDAP://$gpoPath"

    $gpoAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $itAdminSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $gpoObj.ObjectSecurity.AddAccessRule($gpoAce)
    $gpoObj.CommitChanges()

    Write-Log "IT_Admins can modify Default Domain Policy" -Level "OK"
} catch {
    Write-Log "Failed to configure GPO misconfiguration: $_" -Level "ERROR"
}

# ═══════════════════════════════════════════════════════════════════════════
# VULN 5: AdminSDHolder abuse path
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 5: Adding IT_Admins to AdminSDHolder ACL..."
try {
    $adminSDHolder = "CN=AdminSDHolder,CN=System,$domainDN"
    $adminSDObj    = [ADSI]"LDAP://$adminSDHolder"

    $sdAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $itAdminSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $adminSDObj.ObjectSecurity.AddAccessRule($sdAce)
    $adminSDObj.CommitChanges()

    Write-Log "AdminSDHolder ACL modified — IT_Admins have GenericAll" -Level "OK"
} catch {
    Write-Log "Failed to configure AdminSDHolder: $_" -Level "ERROR"
}

# ═══════════════════════════════════════════════════════════════════════════
# VULN 6: WDigest / Credential Caching (Skeleton Key–friendly)
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "VULN 6: Enabling WDigest credential caching..."
try {
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigestPath)) {
        New-Item -Path $wdigestPath -Force | Out-Null
    }
    Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 1 -Type DWord
    Write-Log "WDigest UseLogonCredential enabled (cleartext creds in memory)" -Level "OK"
} catch {
    Write-Log "Failed to enable WDigest: $_" -Level "ERROR"
}

# ── Disable Defender on DC ───────────────────────────────────────────────
Write-Log "Disabling Windows Defender on DC..."
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue

# ── Disable Firewall on DC ──────────────────────────────────────────────
Write-Log "Disabling Windows Firewall on DC..."
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction SilentlyContinue

Write-Log "All vulnerabilities configured successfully" -Level "OK"
Write-Log "Attack chain is ready for exploitation" -Level "OK"
