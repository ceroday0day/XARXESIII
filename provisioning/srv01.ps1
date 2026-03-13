<#
.SYNOPSIS
    SRV01 Provisioning — Joins domain, installs IIS and configures file shares.

.DESCRIPTION
    Joins the umbrella.corp domain, installs IIS with file upload web app,
    and creates anonymous SMB share with planted credentials.

.PARAMETER DomainName
    FQDN of the domain
.PARAMETER NetBIOSName
    NetBIOS name of the domain
.PARAMETER AdminPassword
    Domain admin password for joining
.PARAMETER DCIP
    IP address of the Domain Controller
.PARAMETER StaticIP
    Static IP for this server
#>
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$NetBIOSName,
    [Parameter(Mandatory)][string]$AdminPassword,
    [Parameter(Mandatory)][string]$DCIP,
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
    Write-Log "Starting SRV01 provisioning"

    # ── Configure static IP ──────────────────────────────────────────────
    Write-Log "Configuring static IP: $StaticIP"
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "Ethernet*" } | Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute    -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress -InterfaceIndex $adapter.ifIndex `
        -IPAddress $StaticIP -PrefixLength 24 `
        -DefaultGateway "192.168.56.1" -ErrorAction SilentlyContinue

    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($DCIP)
    Write-Log "Network configured — DNS pointing to DC at $DCIP" -Level "OK"

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

    # ── Install IIS ──────────────────────────────────────────────────────
    Write-Log "Installing IIS with ASP.NET support..."
    Install-WindowsFeature -Name Web-Server, Web-Asp-Net45, Web-Mgmt-Tools -IncludeAllSubFeature -ErrorAction Stop
    Write-Log "IIS installed" -Level "OK"

    # ── Deploy vulnerable intranet web app ───────────────────────────────
    Write-Log "Deploying vulnerable intranet web application..."
    $webRoot = "C:\inetpub\wwwroot\intranet"
    New-Item -Path $webRoot -ItemType Directory -Force | Out-Null

    # Default page
    @"
<!DOCTYPE html>
<html>
<head><title>Umbrella Corp Intranet</title></head>
<body>
<h1>Welcome to Umbrella Corporation Intranet</h1>
<p>Internal document portal — authorized personnel only.</p>
<hr>
<h3>Document Upload</h3>
<form action="upload.aspx" method="post" enctype="multipart/form-data">
    <input type="file" name="fileUpload" />
    <input type="submit" value="Upload Document" />
</form>
<p><small>IT Support: helpdesk@umbrella.corp | Ext. 4444</small></p>
</body>
</html>
"@ | Set-Content -Path "$webRoot\index.html" -Force

    # Vulnerable file upload — accepts .aspx files (webshell vector)
    @'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if (Request.Files.Count > 0) {
        HttpPostedFile file = Request.Files[0];
        // VULNERABILITY: No file extension validation — allows .aspx upload
        string savePath = Server.MapPath("~/intranet/uploads/" + file.FileName);
        Directory.CreateDirectory(Path.GetDirectoryName(savePath));
        file.SaveAs(savePath);
        Response.Write("<p>File uploaded: " + file.FileName + "</p>");
    }
}
</script>
'@ | Set-Content -Path "$webRoot\upload.aspx" -Force

    New-Item -Path "$webRoot\uploads" -ItemType Directory -Force | Out-Null

    # Create IIS site
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-Website -Name "Intranet" -ErrorAction SilentlyContinue) {
        Remove-Website -Name "Intranet"
    }
    New-Website -Name "Intranet" -PhysicalPath $webRoot -Port 8080 -Force | Out-Null
    Write-Log "Intranet web app deployed on port 8080 (vulnerable file upload)" -Level "OK"

    # ── Create anonymous SMB share with planted credentials ──────────────
    Write-Log "Creating anonymous Public SMB share..."
    $sharePath = "C:\Shares\Public"
    New-Item -Path $sharePath -ItemType Directory -Force | Out-Null

    # Plant fake internal document with cleartext credentials
    @"
===============================================================
         UMBRELLA CORPORATION — INTERNAL MEMORANDUM
===============================================================
TO:      IT Operations Team
FROM:    CISO Office
DATE:    2024-01-15
SUBJECT: Monitoring Service Account Credentials

Team,

As discussed in last week's change advisory board, the new
monitoring agent (Nagios XI) has been deployed across all servers.

The service account credentials for the monitoring system are:

    Username : UMBRELLA\svc_monitor
    Password : Monitor2024!

Please ensure these credentials are updated in your local
configuration files. The account has read access to performance
counters and event logs on all servers.

IMPORTANT: This account should NOT be given additional privileges
beyond what is documented in the SOC runbook (Section 4.3).

Regards,
IT Security Operations
===============================================================
"@ | Set-Content -Path "$sharePath\IT-Memo-Monitoring-Setup.txt" -Force

    @"
Umbrella Corporation - Server Inventory (Q1 2024)
================================================
DC01    192.168.56.10   Domain Controller   Windows Server 2019
SRV01   192.168.56.11   File/Web Server     Windows Server 2016
WS01    192.168.56.12   IT Workstation      Windows 10

VPN Gateway: vpn.umbrella.corp:443
Intranet:    http://srv01:8080/intranet/
"@ | Set-Content -Path "$sharePath\Server-Inventory-Q1.txt" -Force

    # Create SMB share with anonymous/everyone access
    New-SmbShare -Name "Public" -Path $sharePath `
        -FullAccess "Everyone" `
        -Description "Public documents — read only" `
        -ErrorAction Stop

    # Grant anonymous access via registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 0 -Type DWord
    Set-ItemProperty -Path $regPath -Name "NullSessionShares" -Value "Public" -Type MultiString

    # Allow anonymous enumeration
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 0 -Type DWord
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 0 -Type DWord
    Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 1 -Type DWord

    Write-Log "Anonymous SMB share created at \\SRV01\Public" -Level "OK"

    # ── Disable Windows Firewall (lab environment) ───────────────────────
    Write-Log "Disabling Windows Firewall for lab environment..."
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    Write-Log "Firewall disabled" -Level "OK"

    # ── Disable Windows Defender (allow offensive tools) ─────────────────
    Write-Log "Disabling Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    Write-Log "Windows Defender disabled" -Level "OK"

    Write-Log "SRV01 provisioning complete" -Level "OK"
    Write-Log "Rebooting to apply domain join..."
    Restart-Computer -Force

} catch {
    Write-Log "SRV01 provisioning failed: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 1
}
