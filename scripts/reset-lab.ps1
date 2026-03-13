<#
.SYNOPSIS
    Lab Reset — Resets all passwords and misconfigurations to initial state.

.DESCRIPTION
    Resets the 0xLab-AD environment to its initial vulnerable state.
    Useful after practice or when the lab has been modified during testing.

.NOTES
    Run this on DC01 as Domain Administrator.
#>
param(
    [string]$DomainName = "umbrella.corp"
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

Write-Log "Starting lab reset for $DomainName..."

# ═══════════════════════════════════════════════════════════════════════════
# RESET PASSWORDS
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Resetting user passwords..."

$passwords = @{
    "a.green"     = "UmbrellaCorp2024!"
    "b.white"     = "Biologist2024!"
    "svc_backup"  = "Backup2024Secure!"
    "svc_deploy"  = "DeployAut0m@tion!"
    "helpdesk01"  = "H3lpd3sk2024!"
    "ceo"         = "Ex3cutiv3P@ss!"
    "cfo"         = "F1nanc3Secur3!"
    "cto"         = "T3chL3ad2024!"
    "svc_sql"     = "SQLSummer2024"
    "svc_iis"     = "IIS@ccount2024!"
    "svc_monitor" = "Monitor2024!"
}

foreach ($user in $passwords.Keys) {
    try {
        $secPw = ConvertTo-SecureString $passwords[$user] -AsPlainText -Force
        Set-ADAccountPassword -Identity $user -NewPassword $secPw -Reset
        Set-ADUser -Identity $user -Enabled $true -PasswordNeverExpires $true
        Unlock-ADAccount -Identity $user -ErrorAction SilentlyContinue
        Write-Log "Password reset: $user" -Level "OK"
    } catch {
        Write-Log "Failed to reset password for ${user}: $_" -Level "ERROR"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# RESET VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Re-applying vulnerability configurations..."

# VULN 1: AS-REP Roasting
try {
    Set-ADAccountControl -Identity "b.white" -DoesNotRequirePreAuth $true
    Write-Log "AS-REP Roasting re-enabled for b.white" -Level "OK"
} catch {
    Write-Log "Failed to reset AS-REP Roasting: $_" -Level "ERROR"
}

# VULN 2: GenericWrite ACL (svc_monitor → svc_backup)
try {
    $monitorUser = Get-ADUser -Identity "svc_monitor"
    $backupUser  = Get-ADUser -Identity "svc_backup"
    $monitorSID  = [System.Security.Principal.SecurityIdentifier]$monitorUser.SID

    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $monitorSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $backupObj = [ADSI]"LDAP://$($backupUser.DistinguishedName)"
    $backupObj.ObjectSecurity.AddAccessRule($ace)
    $backupObj.CommitChanges()
    Write-Log "GenericWrite ACL re-applied" -Level "OK"
} catch {
    Write-Log "Failed to reset ACL: $_" -Level "ERROR"
}

# VULN 3: DCSync rights for svc_deploy
try {
    $deployUser = Get-ADUser -Identity "svc_deploy"
    $deploySID  = [System.Security.Principal.SecurityIdentifier]$deployUser.SID

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
    Write-Log "DCSync rights re-applied for svc_deploy" -Level "OK"
} catch {
    Write-Log "Failed to reset DCSync: $_" -Level "ERROR"
}

# VULN 4: GPO — IT_Admins write on Default Domain Policy
try {
    $itAdmins   = Get-ADGroup -Identity "IT_Admins"
    $itAdminSID = [System.Security.Principal.SecurityIdentifier]$itAdmins.SID

    $gpoPath = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDN"
    $gpoObj  = [ADSI]"LDAP://$gpoPath"

    $gpoAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $itAdminSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )

    $gpoObj.ObjectSecurity.AddAccessRule($gpoAce)
    $gpoObj.CommitChanges()
    Write-Log "GPO misconfiguration re-applied" -Level "OK"
} catch {
    Write-Log "Failed to reset GPO: $_" -Level "ERROR"
}

# Re-enable group memberships
try {
    Add-ADGroupMember -Identity "IT_Admins"        -Members "helpdesk01"  -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "Domain Admins"    -Members "IT_Admins"   -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "Backup Operators" -Members "svc_backup"  -ErrorAction SilentlyContinue
    Write-Log "Group memberships verified" -Level "OK"
} catch {
    Write-Log "Group membership reset warning: $_" -Level "WARN"
}

# SPNs
try {
    Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{
        Add = "MSSQLSvc/srv01.${DomainName}:1433", "MSSQLSvc/srv01.${DomainName}"
    } -ErrorAction SilentlyContinue
    Set-ADUser -Identity "svc_iis" -ServicePrincipalNames @{
        Add = "HTTP/srv01.${DomainName}", "HTTP/srv01"
    } -ErrorAction SilentlyContinue
    Write-Log "SPNs verified" -Level "OK"
} catch {
    Write-Log "SPN reset warning: $_" -Level "WARN"
}

# WDigest
$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) {
    New-Item -Path $wdigestPath -Force | Out-Null
}
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 1 -Type DWord

Write-Log "Lab reset complete — all vulnerabilities restored to initial state" -Level "OK"
