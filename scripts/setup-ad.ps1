<#
.SYNOPSIS
    Active Directory Structure Setup — Creates OUs, users, groups, and SPNs.

.DESCRIPTION
    Builds the Umbrella Corporation organizational structure:
    - OUs: Departments > Research, IT, Management, ServiceAccounts
    - Users with realistic attributes
    - Groups with nested memberships
    - Service Principal Names for Kerberoasting targets

.PARAMETER DomainName
    FQDN of the domain (e.g. umbrella.corp)
.PARAMETER AdminPassword
    Default password for admin-level accounts
#>
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$AdminPassword
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

# Build distinguished name from domain FQDN
$domainParts = $DomainName.Split(".")
$domainDN    = ($domainParts | ForEach-Object { "DC=$_" }) -join ","

Write-Log "Domain DN: $domainDN"

Import-Module ActiveDirectory -ErrorAction Stop

# ═══════════════════════════════════════════════════════════════════════════
# ORGANIZATIONAL UNITS
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Creating Organizational Units..."

$ous = @(
    @{ Name = "Departments";      Path = $domainDN }
    @{ Name = "Research";         Path = "OU=Departments,$domainDN" }
    @{ Name = "IT";               Path = "OU=Departments,$domainDN" }
    @{ Name = "Management";       Path = "OU=Departments,$domainDN" }
    @{ Name = "ServiceAccounts";  Path = "OU=Departments,$domainDN" }
)

foreach ($ou in $ous) {
    $ouDN = "OU=$($ou.Name),$($ou.Path)"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
        Write-Log "Created OU: $ouDN" -Level "OK"
    } else {
        Write-Log "OU already exists: $ouDN" -Level "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# USER ACCOUNTS
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Creating user accounts..."

$defaultPw = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

$users = @(
    # Research Department
    @{
        SamAccountName  = "a.green"
        GivenName       = "Alice"
        Surname         = "Green"
        Name            = "Dr. Alice Green"
        DisplayName     = "Dr. Alice Green"
        Title           = "Senior Research Scientist"
        Department      = "Research"
        Path            = "OU=Research,OU=Departments,$domainDN"
        Password        = $defaultPw
        Description     = "T-Virus research lead"
    }
    @{
        SamAccountName  = "b.white"
        GivenName       = "Bob"
        Surname         = "White"
        Name            = "Dr. Bob White"
        DisplayName     = "Dr. Bob White"
        Title           = "Molecular Biologist"
        Department      = "Research"
        Path            = "OU=Research,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "Biologist2024!" -AsPlainText -Force)
        Description     = "Gene therapy researcher"
    }
    # IT Department
    @{
        SamAccountName  = "svc_backup"
        GivenName       = "SVC"
        Surname         = "Backup"
        Name            = "svc_backup"
        DisplayName     = "Backup Service Account"
        Title           = "Service Account"
        Department      = "IT"
        Path            = "OU=IT,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "Backup2024Secure!" -AsPlainText -Force)
        Description     = "Backup operator service account"
    }
    @{
        SamAccountName  = "svc_deploy"
        GivenName       = "SVC"
        Surname         = "Deploy"
        Name            = "svc_deploy"
        DisplayName     = "Deployment Service Account"
        Title           = "Service Account"
        Department      = "IT"
        Path            = "OU=IT,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "DeployAut0m@tion!" -AsPlainText -Force)
        Description     = "Automated deployment service account"
    }
    @{
        SamAccountName  = "helpdesk01"
        GivenName       = "Help"
        Surname         = "Desk"
        Name            = "helpdesk01"
        DisplayName     = "Helpdesk Operator 01"
        Title           = "IT Helpdesk"
        Department      = "IT"
        Path            = "OU=IT,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "H3lpd3sk2024!" -AsPlainText -Force)
        Description     = "First-level IT support"
    }
    # Management
    @{
        SamAccountName  = "ceo"
        GivenName       = "Ozwell"
        Surname         = "Spencer"
        Name            = "Ozwell Spencer (CEO)"
        DisplayName     = "Ozwell Spencer"
        Title           = "Chief Executive Officer"
        Department      = "Management"
        Path            = "OU=Management,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "Ex3cutiv3P@ss!" -AsPlainText -Force)
        Description     = "CEO — Umbrella Corporation"
    }
    @{
        SamAccountName  = "cfo"
        GivenName       = "James"
        Surname         = "Marcus"
        Name            = "James Marcus (CFO)"
        DisplayName     = "James Marcus"
        Title           = "Chief Financial Officer"
        Department      = "Management"
        Path            = "OU=Management,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "F1nanc3Secur3!" -AsPlainText -Force)
        Description     = "CFO — Umbrella Corporation"
    }
    @{
        SamAccountName  = "cto"
        GivenName       = "William"
        Surname         = "Birkin"
        Name            = "William Birkin (CTO)"
        DisplayName     = "William Birkin"
        Title           = "Chief Technology Officer"
        Department      = "Management"
        Path            = "OU=Management,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "T3chL3ad2024!" -AsPlainText -Force)
        Description     = "CTO — Umbrella Corporation"
    }
    # Service Accounts
    @{
        SamAccountName  = "svc_sql"
        GivenName       = "SVC"
        Surname         = "SQL"
        Name            = "svc_sql"
        DisplayName     = "SQL Service Account"
        Title           = "Service Account"
        Department      = "ServiceAccounts"
        Path            = "OU=ServiceAccounts,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "SQLSummer2024" -AsPlainText -Force)
        Description     = "MSSQL service account"
    }
    @{
        SamAccountName  = "svc_iis"
        GivenName       = "SVC"
        Surname         = "IIS"
        Name            = "svc_iis"
        DisplayName     = "IIS Service Account"
        Title           = "Service Account"
        Department      = "ServiceAccounts"
        Path            = "OU=ServiceAccounts,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "IIS@ccount2024!" -AsPlainText -Force)
        Description     = "IIS application pool identity"
    }
    @{
        SamAccountName  = "svc_monitor"
        GivenName       = "SVC"
        Surname         = "Monitor"
        Name            = "svc_monitor"
        DisplayName     = "Monitoring Service Account"
        Title           = "Service Account"
        Department      = "ServiceAccounts"
        Path            = "OU=ServiceAccounts,OU=Departments,$domainDN"
        Password        = (ConvertTo-SecureString "Monitor2024!" -AsPlainText -Force)
        Description     = "Nagios XI monitoring account"
    }
)

foreach ($user in $users) {
    $sam = $user.SamAccountName
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
        $upn = "$sam@$DomainName"
        New-ADUser `
            -SamAccountName    $user.SamAccountName `
            -UserPrincipalName $upn `
            -GivenName         $user.GivenName `
            -Surname           $user.Surname `
            -Name              $user.Name `
            -DisplayName       $user.DisplayName `
            -Title             $user.Title `
            -Department        $user.Department `
            -Description       $user.Description `
            -Path              $user.Path `
            -AccountPassword   $user.Password `
            -Enabled           $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $false `
            -ErrorAction Stop
        Write-Log "Created user: $sam" -Level "OK"
    } else {
        Write-Log "User already exists: $sam" -Level "WARN"
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# GROUPS
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Creating groups..."

$groups = @(
    @{
        Name        = "IT_Admins"
        Path        = "OU=IT,OU=Departments,$domainDN"
        Scope       = "Global"
        Category    = "Security"
        Description = "IT administrators — shadow admin group"
    }
    @{
        Name        = "Research_Access"
        Path        = "OU=Research,OU=Departments,$domainDN"
        Scope       = "Global"
        Category    = "Security"
        Description = "Access to research data and lab systems"
    }
    @{
        Name        = "VPN_Users"
        Path        = "OU=Departments,$domainDN"
        Scope       = "Global"
        Category    = "Security"
        Description = "Remote VPN access group"
    }
)

foreach ($group in $groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
        New-ADGroup `
            -Name          $group.Name `
            -Path          $group.Path `
            -GroupScope    $group.Scope `
            -GroupCategory $group.Category `
            -Description   $group.Description `
            -ErrorAction Stop
        Write-Log "Created group: $($group.Name)" -Level "OK"
    } else {
        Write-Log "Group already exists: $($group.Name)" -Level "WARN"
    }
}

# ── Group Memberships ────────────────────────────────────────────────────
Write-Log "Configuring group memberships..."

# IT_Admins members
Add-ADGroupMember -Identity "IT_Admins" -Members "helpdesk01" -ErrorAction SilentlyContinue

# Nest IT_Admins into Domain Admins (shadow admin — common misconfiguration)
Add-ADGroupMember -Identity "Domain Admins" -Members "IT_Admins" -ErrorAction SilentlyContinue
Write-Log "IT_Admins nested into Domain Admins (shadow admin group)" -Level "OK"

# Research_Access members
Add-ADGroupMember -Identity "Research_Access" -Members "a.green", "b.white" -ErrorAction SilentlyContinue

# VPN_Users — broad group
Add-ADGroupMember -Identity "VPN_Users" -Members "a.green", "b.white", "helpdesk01", "ceo", "cto" -ErrorAction SilentlyContinue

# Add svc_backup to Backup Operators (built-in)
Add-ADGroupMember -Identity "Backup Operators" -Members "svc_backup" -ErrorAction SilentlyContinue
Write-Log "svc_backup added to Backup Operators" -Level "OK"

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE PRINCIPAL NAMES (for Kerberoasting)
# ═══════════════════════════════════════════════════════════════════════════
Write-Log "Setting Service Principal Names..."

# svc_sql — Kerberoastable target with weak password
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{
    Add = "MSSQLSvc/srv01.${DomainName}:1433", "MSSQLSvc/srv01.${DomainName}"
}
Write-Log "SPN set for svc_sql (Kerberoastable)" -Level "OK"

# svc_iis — additional SPN
Set-ADUser -Identity "svc_iis" -ServicePrincipalNames @{
    Add = "HTTP/srv01.${DomainName}", "HTTP/srv01"
}
Write-Log "SPN set for svc_iis" -Level "OK"

Write-Log "Active Directory structure setup complete" -Level "OK"
