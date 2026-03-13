<#
.SYNOPSIS
    WS01 Provisioning — Joins domain and configures IT workstation.

.DESCRIPTION
    Joins the umbrella.corp domain and configures Windows 10 workstation
    as an IT administration endpoint with common tools.

.PARAMETER DomainName
    FQDN of the domain
.PARAMETER NetBIOSName
    NetBIOS name of the domain
.PARAMETER AdminPassword
    Domain admin password for joining
.PARAMETER DCIP
    IP address of the Domain Controller
#>
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$NetBIOSName,
    [Parameter(Mandatory)][string]$AdminPassword,
    [Parameter(Mandatory)][string]$DCIP
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
    Write-Log "Starting WS01 provisioning"

    # ── Configure DNS to point to DC ─────────────────────────────────────
    Write-Log "Configuring DNS to point to DC at $DCIP"
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Ethernet*" } | Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($DCIP)
    Write-Log "DNS configured" -Level "OK"

    # ── Join domain ──────────────────────────────────────────────────────
    Write-Log "Joining domain: $DomainName"
    $secPw   = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    $domCred = New-Object System.Management.Automation.PSCredential("$NetBIOSName\Administrator", $secPw)

    $maxRetries = 5
    $retryDelay = 30
    for ($i = 1; $i -le $maxRetries; $i++) {
        try {
            Add-Computer -DomainName $DomainName -Credential $domCred -Restart:$false -Force -ErrorAction Stop
            Write-Log "Successfully joined domain" -Level "OK"
            break
        } catch {
            Write-Log "Domain join attempt $i/$maxRetries failed: $_" -Level "WARN"
            if ($i -eq $maxRetries) { throw "Failed to join domain after $maxRetries attempts" }
            Start-Sleep -Seconds $retryDelay
        }
    }

    # ── Disable firewall for lab ─────────────────────────────────────────
    Write-Log "Disabling Windows Firewall for lab environment..."
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    Write-Log "Firewall disabled" -Level "OK"

    # ── Disable Defender for lab ─────────────────────────────────────────
    Write-Log "Disabling Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    Write-Log "Windows Defender disabled" -Level "OK"

    # ── Install RSAT for AD administration ───────────────────────────────
    Write-Log "Installing RSAT tools..."
    Get-WindowsCapability -Online -Name "Rsat.*" | Where-Object {
        $_.Name -match "ActiveDirectory|GroupPolicy|DNS"
    } | ForEach-Object {
        Write-Log "Installing: $($_.Name)"
        Add-WindowsCapability -Online -Name $_.Name -ErrorAction SilentlyContinue
    }
    Write-Log "RSAT tools installed" -Level "OK"

    # ── Enable PS Remoting ───────────────────────────────────────────────
    Write-Log "Enabling PowerShell Remoting..."
    Enable-PSRemoting -Force -ErrorAction SilentlyContinue
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Write-Log "PS Remoting enabled" -Level "OK"

    # ── Enable RDP ───────────────────────────────────────────────────────
    Write-Log "Enabling Remote Desktop..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Type DWord
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    Write-Log "RDP enabled" -Level "OK"

    Write-Log "WS01 provisioning complete" -Level "OK"
    Write-Log "Rebooting to apply domain join..."
    Restart-Computer -Force

} catch {
    Write-Log "WS01 provisioning failed: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 1
}
