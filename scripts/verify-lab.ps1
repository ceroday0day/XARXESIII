<#
.SYNOPSIS
    Lab Verification — Checks all vulnerabilities are correctly configured.

.DESCRIPTION
    Validates every vulnerability in the attack chain and prints a status
    table with checkmarks or crosses for each item.

.NOTES
    Run on DC01 as Domain Administrator.
    Exit code 0 = all checks passed, 1 = one or more checks failed.
#>
param(
    [string]$DomainName = "umbrella.corp"
)

$ErrorActionPreference = "Continue"

$domainParts = $DomainName.Split(".")
$domainDN    = ($domainParts | ForEach-Object { "DC=$_" }) -join ","

Import-Module ActiveDirectory -ErrorAction Stop

$results  = @()
$allPass  = $true

function Test-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test
    )

    $status = $false
    $detail = ""
    try {
        $status = & $Test
        if (-not $status) { $detail = "Check returned false" }
    } catch {
        $detail = $_.Exception.Message
    }

    $script:results += [PSCustomObject]@{
        Category = $Category
        Check    = $Name
        Status   = if ($status) { [char]0x2713 } else { [char]0x2717 }  # checkmark / cross
        Pass     = $status
        Detail   = $detail
    }

    if (-not $status) { $script:allPass = $false }
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  0xLab-AD Vulnerability Verification Report"          -ForegroundColor Cyan
Write-Host "  Domain: $DomainName"                                  -ForegroundColor Cyan
Write-Host "  Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"   -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# ── AD Structure ─────────────────────────────────────────────────────────
Test-Check "Structure" "OU=Departments exists" {
    [bool](Get-ADOrganizationalUnit -Filter "Name -eq 'Departments'" -ErrorAction SilentlyContinue)
}

Test-Check "Structure" "OU=Research exists" {
    [bool](Get-ADOrganizationalUnit -Filter "Name -eq 'Research'" -ErrorAction SilentlyContinue)
}

Test-Check "Structure" "OU=IT exists" {
    [bool](Get-ADOrganizationalUnit -Filter "Name -eq 'IT'" -ErrorAction SilentlyContinue)
}

Test-Check "Structure" "OU=Management exists" {
    [bool](Get-ADOrganizationalUnit -Filter "Name -eq 'Management'" -ErrorAction SilentlyContinue)
}

Test-Check "Structure" "OU=ServiceAccounts exists" {
    [bool](Get-ADOrganizationalUnit -Filter "Name -eq 'ServiceAccounts'" -ErrorAction SilentlyContinue)
}

# ── Users ────────────────────────────────────────────────────────────────
$expectedUsers = @("a.green", "b.white", "svc_backup", "svc_deploy", "helpdesk01",
                   "ceo", "cfo", "cto", "svc_sql", "svc_iis", "svc_monitor")

foreach ($user in $expectedUsers) {
    Test-Check "Users" "User '$user' exists and enabled" {
        $u = Get-ADUser -Identity $user -Properties Enabled -ErrorAction Stop
        $u.Enabled -eq $true
    }
}

# ── Groups ───────────────────────────────────────────────────────────────
Test-Check "Groups" "IT_Admins group exists" {
    [bool](Get-ADGroup -Identity "IT_Admins" -ErrorAction Stop)
}

Test-Check "Groups" "Research_Access group exists" {
    [bool](Get-ADGroup -Identity "Research_Access" -ErrorAction Stop)
}

Test-Check "Groups" "VPN_Users group exists" {
    [bool](Get-ADGroup -Identity "VPN_Users" -ErrorAction Stop)
}

Test-Check "Groups" "helpdesk01 is member of IT_Admins" {
    $members = Get-ADGroupMember -Identity "IT_Admins" -ErrorAction Stop
    $members.SamAccountName -contains "helpdesk01"
}

Test-Check "Groups" "IT_Admins nested in Domain Admins" {
    $members = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
    $members.Name -contains "IT_Admins"
}

Test-Check "Groups" "svc_backup in Backup Operators" {
    $members = Get-ADGroupMember -Identity "Backup Operators" -ErrorAction Stop
    $members.SamAccountName -contains "svc_backup"
}

# ── Vulnerability 1: AS-REP Roasting ────────────────────────────────────
Test-Check "VULN" "AS-REP Roasting: b.white no preauth" {
    $user = Get-ADUser -Identity "b.white" -Properties DoesNotRequirePreAuth -ErrorAction Stop
    $user.DoesNotRequirePreAuth -eq $true
}

# ── Vulnerability 2: ACL Abuse (GenericWrite) ────────────────────────────
Test-Check "VULN" "ACL: svc_monitor GenericWrite on svc_backup" {
    $backupUser = Get-ADUser -Identity "svc_backup" -ErrorAction Stop
    $monitorUser = Get-ADUser -Identity "svc_monitor" -ErrorAction Stop
    $acl = Get-Acl "AD:\$($backupUser.DistinguishedName)"
    $monitorSID = $monitorUser.SID.Value
    $found = $acl.Access | Where-Object {
        $_.IdentityReference.Value -match $monitorSID -and
        $_.ActiveDirectoryRights -match "GenericWrite"
    }
    [bool]$found
}

# ── Vulnerability 3: Kerberoasting (SPN) ────────────────────────────────
Test-Check "VULN" "Kerberoast: svc_sql has SPN set" {
    $user = Get-ADUser -Identity "svc_sql" -Properties ServicePrincipalName -ErrorAction Stop
    $user.ServicePrincipalName.Count -gt 0
}

# ── Vulnerability 4: DCSync rights ──────────────────────────────────────
Test-Check "VULN" "DCSync: svc_deploy has replication rights" {
    $deployUser = Get-ADUser -Identity "svc_deploy" -ErrorAction Stop
    $acl = Get-Acl "AD:\$domainDN"
    $deploySID = $deployUser.SID.Value
    $found = $acl.Access | Where-Object {
        $_.IdentityReference.Value -match $deploySID -and
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    }
    [bool]$found
}

# ── Vulnerability 5: GPO misconfiguration ───────────────────────────────
Test-Check "VULN" "GPO: IT_Admins can edit Default Domain Policy" {
    $gpoPath = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDN"
    $acl = Get-Acl "AD:\$gpoPath"
    $itAdmins = Get-ADGroup -Identity "IT_Admins" -ErrorAction Stop
    $itSID = $itAdmins.SID.Value
    $found = $acl.Access | Where-Object {
        $_.IdentityReference.Value -match $itSID -and
        $_.ActiveDirectoryRights -match "GenericAll"
    }
    [bool]$found
}

# ── Vulnerability 6: WDigest ────────────────────────────────────────────
Test-Check "VULN" "WDigest credential caching enabled" {
    $val = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -ErrorAction Stop
    $val.UseLogonCredential -eq 1
}

# ── SMB Share ────────────────────────────────────────────────────────────
Test-Check "Infra" "Public SMB share exists on SRV01" {
    $share = Get-SmbShare -Name "Public" -ErrorAction Stop
    [bool]$share
}

# ═══════════════════════════════════════════════════════════════════════════
# RESULTS TABLE
# ═══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("{0,-12} {1,-50} {2}" -f "CATEGORY", "CHECK", "STATUS") -ForegroundColor White
Write-Host ("-" * 70) -ForegroundColor DarkGray

foreach ($r in $results) {
    $color = if ($r.Pass) { "Green" } else { "Red" }
    Write-Host ("{0,-12} {1,-50} {2}" -f $r.Category, $r.Check, $r.Status) -ForegroundColor $color
    if (-not $r.Pass -and $r.Detail) {
        Write-Host ("             Detail: {0}" -f $r.Detail) -ForegroundColor DarkYellow
    }
}

$passed = ($results | Where-Object { $_.Pass }).Count
$total  = $results.Count

Write-Host ""
Write-Host ("-" * 70) -ForegroundColor DarkGray
if ($allPass) {
    Write-Host "RESULT: ALL CHECKS PASSED ($passed/$total)" -ForegroundColor Green
} else {
    Write-Host "RESULT: SOME CHECKS FAILED ($passed/$total passed)" -ForegroundColor Red
}
Write-Host ""

if (-not $allPass) { exit 1 }
