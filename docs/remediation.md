# Remediation Guide — 0xLab-AD

> This guide provides **actionable fixes** for each vulnerability in the lab.
> Use this as a blue team training resource to understand how to harden an
> Active Directory environment.

---

## Table of Contents

1. [Anonymous SMB Share](#1-anonymous-smb-share)
2. [IIS Unrestricted File Upload](#2-iis-unrestricted-file-upload)
3. [ACL Misconfiguration](#3-acl-misconfiguration)
4. [Kerberoasting Mitigation](#4-kerberoasting-mitigation)
5. [Backup Operators Hardening](#5-backup-operators-hardening)
6. [AS-REP Roasting Prevention](#6-as-rep-roasting-prevention)
7. [DCSync Rights Review](#7-dcsync-rights-review)
8. [GPO Permissions Audit](#8-gpo-permissions-audit)
9. [Shadow Admin Elimination](#9-shadow-admin-elimination)
10. [AdminSDHolder Protection](#10-adminsdholder-protection)
11. [WDigest Credential Protection](#11-wdigest-credential-protection)
12. [General Hardening Checklist](#12-general-hardening-checklist)

---

## 1. Anonymous SMB Share

### Problem
Anonymous access to `\\SRV01\Public` exposes sensitive documents with
cleartext service account credentials.

### Fix

```powershell
# 1. Remove anonymous access from the share
Revoke-SmbShareAccess -Name "Public" -AccountName "Everyone" -Force
Grant-SmbShareAccess -Name "Public" -AccountName "UMBRELLA\Domain Users" `
    -AccessRight Read -Force

# 2. Re-enable null session restrictions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RestrictNullSessAccess" -Value 1 -Type DWord
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "NullSessionShares" -ErrorAction SilentlyContinue

# 3. Restrict anonymous enumeration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord

# 4. Remove documents with cleartext credentials
Remove-Item "C:\Shares\Public\IT-Memo-Monitoring-Setup.txt" -Force

# 5. Rotate the exposed credential immediately
Set-ADAccountPassword -Identity "svc_monitor" `
    -NewPassword (ConvertTo-SecureString "$(New-Guid)" -AsPlainText -Force) -Reset
```

### Ongoing Controls
- Deploy a secret scanning tool (e.g., Snaffler) to scan file shares weekly
- Use a password manager for service account credentials
- Enforce GPO: "Network access: Restrict anonymous access to Named Pipes and Shares"

---

## 2. IIS Unrestricted File Upload

### Problem
The intranet file upload endpoint on SRV01:8080 accepts `.aspx` files,
enabling webshell deployment.

### Fix

```powershell
# 1. Add file extension validation in the upload handler
# Replace the upload.aspx with a version that validates extensions:
$secureUpload = @'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
private static readonly string[] AllowedExtensions = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"
};

protected void Page_Load(object sender, EventArgs e) {
    if (Request.Files.Count > 0) {
        HttpPostedFile file = Request.Files[0];
        string ext = Path.GetExtension(file.FileName).ToLowerInvariant();

        if (!AllowedExtensions.Contains(ext)) {
            Response.StatusCode = 400;
            Response.Write("File type not allowed: " + ext);
            return;
        }

        // Generate random filename to prevent path traversal
        string safeName = Guid.NewGuid().ToString() + ext;
        string savePath = Server.MapPath("~/intranet/uploads/" + safeName);
        file.SaveAs(savePath);
        Response.Write("File uploaded successfully.");
    }
}
</script>
'@

Set-Content -Path "C:\inetpub\wwwroot\intranet\upload.aspx" -Value $secureUpload

# 2. Configure IIS Request Filtering to block dangerous extensions
Import-Module WebAdministration
Add-WebConfigurationProperty -PSPath "IIS:\Sites\Intranet" `
    -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Name "." -Value @{fileExtension=".aspx"; allowed="false"}
Add-WebConfigurationProperty -PSPath "IIS:\Sites\Intranet" `
    -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Name "." -Value @{fileExtension=".asp"; allowed="false"}
Add-WebConfigurationProperty -PSPath "IIS:\Sites\Intranet" `
    -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Name "." -Value @{fileExtension=".exe"; allowed="false"}

# 3. Remove any existing uploaded webshells
Get-ChildItem "C:\inetpub\wwwroot\intranet\uploads" -Filter "*.aspx" | Remove-Item -Force

# 4. Set the upload directory to non-executable
# (Remove script execution from the uploads virtual directory)
```

### Ongoing Controls
- Deploy a Web Application Firewall (WAF) for internal applications
- Implement file content validation (magic bytes, not just extension)
- Regular vulnerability scanning of internal web applications
- File integrity monitoring on web application directories

---

## 3. ACL Misconfiguration

### Problem
`svc_monitor` has GenericWrite over `svc_backup`, allowing password reset
or targeted Kerberoasting.

### Fix

```powershell
# 1. Remove the overly broad ACL
$backupUser = Get-ADUser -Identity "svc_backup"
$monitorUser = Get-ADUser -Identity "svc_monitor"
$monitorSID = [System.Security.Principal.SecurityIdentifier]$monitorUser.SID

$backupObj = [ADSI]"LDAP://$($backupUser.DistinguishedName)"
$acl = $backupObj.ObjectSecurity

# Remove GenericWrite ACEs for svc_monitor
$acesToRemove = $acl.Access | Where-Object {
    $_.IdentityReference.Value -eq $monitorSID.Value -and
    $_.ActiveDirectoryRights -match "GenericWrite"
}

foreach ($ace in $acesToRemove) {
    $acl.RemoveAccessRule($ace) | Out-Null
}

$backupObj.ObjectSecurity = $acl
$backupObj.CommitChanges()

# 2. If svc_monitor needs to read monitoring data, grant only:
$readAce = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $monitorSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$backupObj.ObjectSecurity.AddAccessRule($readAce)
$backupObj.CommitChanges()
```

### Ongoing Controls
- Run BloodHound or PingCastle monthly to identify dangerous ACL paths
- Implement a change review process for AD delegations
- Document all intentional delegations in a security register

---

## 4. Kerberoasting Mitigation

### Problem
`svc_sql` has SPNs set with a weak, crackable password.

### Fix

```powershell
# Option 1 (Recommended): Convert to Group Managed Service Account (gMSA)
# gMSAs use 240-character auto-rotated passwords — immune to Kerberoasting

# Create KDS root key (required once per domain, wait 10h before use in prod)
Add-KdsRootKey -EffectiveImmediately

# Create gMSA
New-ADServiceAccount -Name "gmsa_sql" `
    -DNSHostName "gmsa_sql.umbrella.corp" `
    -PrincipalsAllowedToRetrieveManagedPassword "SRV01$" `
    -ServicePrincipalNames "MSSQLSvc/srv01.umbrella.corp:1433"

# Install on the target server
Install-ADServiceAccount -Identity "gmsa_sql"

# Option 2: If gMSA is not possible, use a strong password (30+ chars)
$strongPw = -join ((65..90) + (97..122) + (48..57) + (33..38) |
    Get-Random -Count 40 | ForEach-Object { [char]$_ })
Set-ADAccountPassword -Identity "svc_sql" `
    -NewPassword (ConvertTo-SecureString $strongPw -AsPlainText -Force) -Reset

# Option 3: Enable AES-only encryption (makes cracking harder)
Set-ADUser -Identity "svc_sql" `
    -KerberosEncryptionType AES128, AES256
```

### Ongoing Controls
- Audit all accounts with SPNs: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`
- Enforce 25+ character passwords for all SPN accounts
- Migrate to gMSAs wherever possible
- Monitor for Kerberoasting: detect RC4 TGS requests (Event ID 4769, encryption type 0x17)

---

## 5. Backup Operators Hardening

### Problem
`svc_backup` is a member of Backup Operators and can dump registry hives
(SAM, SYSTEM, SECURITY) containing credentials.

### Fix

```powershell
# 1. Review and minimize Backup Operators membership
Get-ADGroupMember "Backup Operators" | Format-Table Name, SamAccountName

# 2. Remove unnecessary members
Remove-ADGroupMember -Identity "Backup Operators" -Members "svc_backup" -Confirm:$false

# 3. Use a dedicated backup solution with its own authentication
# (e.g., Veeam agent, which doesn't need Backup Operators membership)

# 4. If Backup Operators membership is truly required:
# - Use a Tier 0 service account with a gMSA
# - Restrict logon to backup servers only via GPO
# - Enable and monitor privileged access events

# 5. Restrict remote registry access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" `
    -Name "RemoteRegAccess" -Value 1 -Type DWord
```

### Ongoing Controls
- Monthly review of privileged group membership
- Alert on any Backup Operators group changes (Event ID 4728/4732)
- Restrict logon rights for backup service accounts via GPO

---

## 6. AS-REP Roasting Prevention

### Problem
`b.white` has "Do not require Kerberos preauthentication" enabled.

### Fix

```powershell
# 1. Re-enable preauthentication
Set-ADAccountControl -Identity "b.white" -DoesNotRequirePreAuth $false

# 2. Find ALL accounts with preauthentication disabled
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
    -Properties DoesNotRequirePreAuth |
    Select-Object Name, SamAccountName, DistinguishedName

# 3. Fix all affected accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | ForEach-Object {
    Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false
    Write-Host "Fixed: $($_.SamAccountName)"
}

# 4. Force password change for previously exposed accounts
Set-ADUser -Identity "b.white" -ChangePasswordAtLogon $true
```

### Ongoing Controls
- Add a scheduled task to check for `DoesNotRequirePreAuth` accounts daily
- Create a GPO or monitoring alert for this setting
- Document any legitimate exceptions with compensating controls

---

## 7. DCSync Rights Review

### Problem
`svc_deploy` has Replicating Directory Changes All, enabling DCSync attacks.

### Fix

```powershell
# 1. Remove DCSync rights from svc_deploy
$deployUser = Get-ADUser -Identity "svc_deploy"
$deploySID = [System.Security.Principal.SecurityIdentifier]$deployUser.SID

$guidReplChanges    = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$guidReplChangesAll = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

$domainDN = (Get-ADDomain).DistinguishedName
$domainObj = [ADSI]"LDAP://$domainDN"
$acl = $domainObj.ObjectSecurity

$acesToRemove = $acl.Access | Where-Object {
    $_.IdentityReference.Value -eq $deploySID.Value -and
    ($_.ObjectType -eq $guidReplChanges -or $_.ObjectType -eq $guidReplChangesAll)
}

foreach ($ace in $acesToRemove) {
    $acl.RemoveAccessRule($ace) | Out-Null
}

$domainObj.ObjectSecurity = $acl
$domainObj.CommitChanges()

# 2. Audit all accounts with replication rights
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\$domainDN"
$acl.Access | Where-Object {
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
} | Select-Object IdentityReference, AccessControlType

# 3. Only Domain Controllers and Azure AD Connect should have these rights
```

### Ongoing Controls
- Monthly audit of replication rights on the domain object
- Alert on 4662 events with replication GUIDs from non-DC sources
- Use Microsoft Defender for Identity to detect DCSync attempts

---

## 8. GPO Permissions Audit

### Problem
`IT_Admins` has GenericAll on the Default Domain Policy.

### Fix

```powershell
# 1. Remove IT_Admins' GenericAll from Default Domain Policy
$itAdmins = Get-ADGroup -Identity "IT_Admins"
$itAdminSID = [System.Security.Principal.SecurityIdentifier]$itAdmins.SID

$domainDN = (Get-ADDomain).DistinguishedName
$gpoPath = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,$domainDN"
$gpoObj = [ADSI]"LDAP://$gpoPath"
$acl = $gpoObj.ObjectSecurity

$acesToRemove = $acl.Access | Where-Object {
    $_.IdentityReference.Value -eq $itAdminSID.Value -and
    $_.ActiveDirectoryRights -match "GenericAll"
}

foreach ($ace in $acesToRemove) {
    $acl.RemoveAccessRule($ace) | Out-Null
}

$gpoObj.ObjectSecurity = $acl
$gpoObj.CommitChanges()

# 2. Audit all GPO permissions
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $perms = Get-GPPermission -Guid $gpo.Id -All
    $perms | Where-Object { $_.Permission -eq "GpoEditDeleteModifySecurity" } |
        Select-Object @{N='GPO';E={$gpo.DisplayName}}, Trustee, Permission
}

# 3. Grant only GpoRead and GpoApply to IT_Admins if needed
Set-GPPermission -Guid "31B2F340-016D-11D2-945F-00C04FB984F9" `
    -TargetName "IT_Admins" -TargetType Group `
    -PermissionLevel GpoRead
```

### Ongoing Controls
- Quarterly GPO permission audits
- Use Group Policy Management Console (GPMC) delegation model
- Monitor Event ID 5136/5137 for GPO object modifications

---

## 9. Shadow Admin Elimination

### Problem
`IT_Admins` is nested into Domain Admins, making `helpdesk01` a shadow
Domain Admin.

### Fix

```powershell
# 1. Remove IT_Admins from Domain Admins
Remove-ADGroupMember -Identity "Domain Admins" -Members "IT_Admins" -Confirm:$false

# 2. Find all shadow admin paths
# Using PowerShell to check recursive Domain Admin membership:
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, ObjectClass |
    Format-Table -AutoSize

# 3. Create a proper delegation model:
# - Help desk gets "Reset Password" delegation on user OUs only
# - No group nesting into privileged groups
# - Use AdminCount attribute to track protected accounts

# 4. Delegate specific rights to helpdesk01 instead:
$ouDN = "OU=Departments,DC=umbrella,DC=corp"
dsacls $ouDN /G "UMBRELLA\helpdesk01:RPWP;pwdLastSet" /I:S
dsacls $ouDN /G "UMBRELLA\helpdesk01:CA;Reset Password" /I:S
```

### Ongoing Controls
- Run `Get-ADGroupMember -Recursive "Domain Admins"` weekly
- Use BloodHound to visualize all paths to DA
- Implement tiered administration (Tier 0/1/2 model)
- Regular review of all nested group memberships in privileged groups

---

## 10. AdminSDHolder Protection

### Problem
`IT_Admins` has GenericAll on AdminSDHolder, which propagates to all
protected groups every 60 minutes.

### Fix

```powershell
# 1. Remove unauthorized ACEs from AdminSDHolder
$domainDN = (Get-ADDomain).DistinguishedName
$adminSDHolder = "CN=AdminSDHolder,CN=System,$domainDN"
$sdObj = [ADSI]"LDAP://$adminSDHolder"
$acl = $sdObj.ObjectSecurity

$itAdmins = Get-ADGroup -Identity "IT_Admins"
$itAdminSID = [System.Security.Principal.SecurityIdentifier]$itAdmins.SID

$acesToRemove = $acl.Access | Where-Object {
    $_.IdentityReference.Value -eq $itAdminSID.Value
}

foreach ($ace in $acesToRemove) {
    $acl.RemoveAccessRule($ace) | Out-Null
}

$sdObj.ObjectSecurity = $acl
$sdObj.CommitChanges()

# 2. Force SDProp to run immediately (to propagate clean ACL)
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("runProtectAdminGroupsTask", 1)
$rootDSE.SetInfo()

# 3. Verify the ACL is clean
(Get-Acl "AD:\$adminSDHolder").Access |
    Select-Object IdentityReference, ActiveDirectoryRights |
    Format-Table -AutoSize
```

### Ongoing Controls
- Monitor AdminSDHolder ACL changes (Event ID 5136)
- Baseline the AdminSDHolder ACL and alert on deviations
- Include AdminSDHolder in quarterly AD security reviews

---

## 11. WDigest Credential Protection

### Problem
WDigest stores plaintext passwords in LSASS memory, extractable with mimikatz.

### Fix

```powershell
# 1. Disable WDigest credential caching
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0 -Type DWord

# 2. Enable LSA Protection (RunAsPPL) — prevents mimikatz from reading LSASS
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force

# 3. Enable Credential Guard (Windows 10/Server 2016+)
# Via GPO: Computer Configuration > Administrative Templates >
#   System > Device Guard > Turn On Virtualization Based Security
# Or via registry:
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -Value 1 -PropertyType DWord -Force

# 4. Re-enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
```

### Ongoing Controls
- Deploy Credential Guard via GPO across all workstations and servers
- Monitor WDigest registry key for unauthorized changes
- Enable ASR rules to protect LSASS
- Consider deploying Microsoft Defender for Endpoint

---

## 12. General Hardening Checklist

### Network Security
- [ ] Enable Windows Firewall on all machines with proper rules
- [ ] Enforce SMB signing: `Set-SmbServerConfiguration -RequireSecuritySignature $true`
- [ ] Enforce LDAP signing via GPO
- [ ] Disable LLMNR and NetBIOS-NS
- [ ] Segment network with VLANs (Tier 0/1/2)

### Authentication
- [ ] Enforce complex passwords (15+ characters)
- [ ] Implement fine-grained password policies for service accounts
- [ ] Enable account lockout policies
- [ ] Migrate service accounts to gMSAs
- [ ] Disable RC4 for Kerberos (AES only)

### Monitoring
- [ ] Deploy SIEM with Windows Event Forwarding
- [ ] Configure advanced audit policies (not just basic)
- [ ] Enable PowerShell Script Block Logging
- [ ] Deploy Microsoft Defender for Identity
- [ ] Set up honey tokens (accounts, SPNs, shares)

### Access Control
- [ ] Implement tiered administration model
- [ ] Remove all shadow admin paths
- [ ] Review all AD delegations quarterly
- [ ] Implement Privileged Access Workstations (PAWs) for Tier 0
- [ ] Enable Protected Users group for admin accounts

### Backup & Recovery
- [ ] Secure backup infrastructure separately from production AD
- [ ] Test AD restoration procedures
- [ ] Maintain offline backups of AD (for ransomware recovery)
- [ ] Document all service account dependencies
