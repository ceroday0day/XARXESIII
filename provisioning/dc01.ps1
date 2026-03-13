<#
.SYNOPSIS
    DC01 Provisioning — Promotes Windows Server 2019 to Primary Domain Controller.

.DESCRIPTION
    Installs AD DS role, creates umbrella.corp forest, configures DNS, and
    sets static IP. This script runs as the first provisioner on DC01.

.PARAMETER DomainName
    FQDN of the domain (e.g. umbrella.corp)
.PARAMETER NetBIOSName
    NetBIOS name of the domain (e.g. UMBRELLA)
.PARAMETER SafeModePassword
    DSRM (Directory Services Restore Mode) password
.PARAMETER StaticIP
    Static IP address for this DC
#>
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$NetBIOSName,
    [Parameter(Mandatory)][string]$SafeModePassword,
    [Parameter(Mandatory)][string]$StaticIP
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

try {
    Write-Log "Starting DC01 provisioning for domain: $DomainName"

    # ── Configure static IP and DNS ──────────────────────────────────────
    Write-Log "Configuring static IP: $StaticIP"
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Ethernet*" } | Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    # Remove existing IP configuration
    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute    -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
        -IPAddress $StaticIP `
        -PrefixLength 24 `
        -DefaultGateway "192.168.56.1" -ErrorAction SilentlyContinue

    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
        -ServerAddresses @("127.0.0.1", "8.8.8.8")

    Write-Log "Static IP configured" -Level "OK"

    # ── Install AD DS role ───────────────────────────────────────────────
    Write-Log "Installing AD DS Windows feature..."
    $feature = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
    if ($feature.Success) {
        Write-Log "AD DS role installed successfully" -Level "OK"
    } else {
        throw "AD DS role installation failed"
    }

    # ── Promote to Domain Controller ─────────────────────────────────────
    Write-Log "Promoting server to Domain Controller..."
    $securePw = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force

    Import-Module ADDSDeployment

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetBIOSName `
        -SafeModeAdministratorPassword $securePw `
        -InstallDNS:$true `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -DomainMode "WinThreshold" `
        -ForestMode "WinThreshold" `
        -NoRebootOnCompletion:$false `
        -Force:$true `
        -ErrorAction Stop

    Write-Log "Domain Controller promotion initiated — machine will reboot" -Level "OK"

} catch {
    Write-Log "DC01 provisioning failed: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 1
}
