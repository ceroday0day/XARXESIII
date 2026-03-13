# Vulnerabilities — 0xLab-AD

> Each vulnerability is documented with its **technical details**, **real-world
> context** explaining why organizations have these misconfigurations, and
> **detection** indicators for blue teams.

---

## Table of Contents

1. [Anonymous SMB Share with Cleartext Credentials](#1-anonymous-smb-share-with-cleartext-credentials)
2. [IIS Unrestricted File Upload](#2-iis-unrestricted-file-upload)
3. [ACL Misconfiguration — GenericWrite](#3-acl-misconfiguration--genericwrite)
4. [Kerberoasting — Weak SPN Password](#4-kerberoasting--weak-spn-password)
5. [Backup Operators Group Abuse](#5-backup-operators-group-abuse)
6. [AS-REP Roasting](#6-as-rep-roasting)
7. [DCSync Rights Delegation](#7-dcsync-rights-delegation)
8. [GPO Misconfiguration](#8-gpo-misconfiguration)
9. [Shadow Admin via Nested Groups](#9-shadow-admin-via-nested-groups)
10. [AdminSDHolder Abuse](#10-adminsdholder-abuse)
11. [WDigest Credential Caching](#11-wdigest-credential-caching)

---

## 1. Anonymous SMB Share with Cleartext Credentials

### Technical Details

- **Location:** `\\SRV01\Public`
- **Contents:** IT memo containing `svc_monitor:Monitor2024!` in cleartext
- **Protocol:** SMB (port 445), anonymous access enabled
- **Registry settings:** `RestrictNullSessAccess = 0`, `RestrictAnonymous = 0`

### Real-World Context

Anonymous SMB shares are **extremely common** in enterprise environments, and
cleartext credentials in shared documents are a recurring finding in penetration
tests. This happens because:

- **Legacy compatibility:** Older applications and scripts may rely on
  anonymous access to shared folders. IT teams enable it "temporarily" and
  never revert the change.
- **Operational convenience:** Teams share credentials in documents, wikis,
  or SharePoint pages because password managers are not adopted organization-wide.
  Service account passwords in particular are often shared in IT documentation.
- **Change management gaps:** When monitoring tools like Nagios, PRTG, or
  SolarWinds are deployed, the service account credentials are documented in
  setup guides that get left on shared drives.
- **Audit blind spots:** Many organizations scan for credentials in code repos
  (via tools like git-secrets) but don't scan file shares, SharePoint, or
  internal wikis for exposed passwords.

### Detection

- Monitor for anonymous SMB connections (Event ID 5140 with anonymous user)
- Scan file shares for credential patterns using tools like Snaffler
- Alert on `RestrictNullSessAccess` registry modifications

---

## 2. IIS Unrestricted File Upload

### Technical Details

- **Location:** `http://SRV01:8080/intranet/upload.aspx`
- **Vulnerability:** File upload endpoint accepts any file extension, including `.aspx`
- **Impact:** Remote code execution via ASPX webshell
- **Upload directory:** `C:\inetpub\wwwroot\intranet\uploads\`

### Real-World Context

Unrestricted file upload is a **perennial web application vulnerability** that
appears consistently in OWASP Top 10. In corporate intranets:

- **Internal apps get less scrutiny:** Organizations invest heavily in securing
  external-facing applications but often treat intranet apps as "trusted."
  Internal web applications frequently lack input validation, file type checking,
  and other security controls.
- **Legacy code:** Many intranet applications are built on older frameworks
  (classic ASP, old ASP.NET) without modern security patterns. They may have
  been written by developers who have since left the company.
- **"It's behind the firewall":** The assumption that internal networks are
  safe leads to relaxed security controls. Once an attacker gains internal
  network access (via phishing, VPN compromise, or physical access), these
  internal applications become easy targets.
- **Development/testing artifacts:** Upload features meant for internal
  testing often make it into production intranet applications without
  proper security review.

### Detection

- IIS logs showing `.aspx` file uploads to unexpected directories
- File integrity monitoring on web application directories
- Web application firewall (WAF) rules for file upload endpoints
- Monitor for new `.aspx` files in web-accessible directories

---

## 3. ACL Misconfiguration — GenericWrite

### Technical Details

- **Source:** `svc_monitor` (monitoring service account)
- **Target:** `svc_backup` (backup service account)
- **Right:** GenericWrite (allows modification of most attributes)
- **Abuse:** Can set SPN for targeted Kerberoasting, reset password, or
  modify group membership

### Real-World Context

ACL misconfigurations are the **number one finding** in BloodHound assessments
of real Active Directory environments. GenericWrite delegations happen because:

- **Monitoring tool requirements:** Tools like SCCM, SCOM, Nagios, and custom
  monitoring solutions sometimes require write access to AD objects to update
  attributes, manage group memberships, or reset passwords. IT teams grant
  broad permissions instead of the minimum required.
- **Helpdesk delegation gone wrong:** When creating delegated administration
  models, administrators often grant GenericWrite instead of more specific
  rights (like "Reset Password" only). The AD delegation wizard makes it
  easy to over-permission.
- **Accumulated permissions:** Over years, service accounts accumulate
  permissions as different projects add ACEs without reviewing existing ones.
  Nobody audits the full ACL on objects, and permissions are rarely removed.
- **Schema extension side effects:** Third-party applications that extend
  the AD schema sometimes add broad ACLs to service accounts during
  installation without documenting the security implications.

### Detection

- Regular ACL audits with BloodHound or PingCastle
- Monitor for SPN modifications (Event ID 4742 with ServicePrincipalName change)
- Alert on password resets of service accounts (Event ID 4724)

---

## 4. Kerberoasting — Weak SPN Password

### Technical Details

- **Account:** `svc_sql`
- **SPNs:** `MSSQLSvc/srv01.umbrella.corp:1433`, `MSSQLSvc/srv01.umbrella.corp`
- **Password:** `SQLSummer2024` (crackable with wordlist)
- **Attack:** Any authenticated user can request TGS tickets for SPN accounts
  and crack them offline

### Real-World Context

Kerberoasting is **one of the most impactful AD attacks** because it requires
only a single valid domain credential and produces results that can be cracked
offline without generating failed authentication events. The conditions exist
because:

- **SQL Server service accounts:** SQL Server is one of the most common
  applications that registers SPNs. DBAs often set passwords that are
  memorable rather than truly random, especially for accounts created years
  ago before security awareness improved.
- **Password age:** Service account passwords are rarely rotated in most
  organizations. A password set in 2018 using standards that were "good
  enough" at the time may now be trivially crackable with modern GPUs.
- **No Managed Service Accounts:** Group Managed Service Accounts (gMSAs)
  solve the Kerberoasting problem by using 240-character automatically
  rotated passwords, but adoption remains low. Many organizations don't
  know they exist or consider migration too risky.
- **Application compatibility concerns:** Even when teams want to change
  service account passwords, they fear breaking dependent applications.
  The lack of documentation about which applications use which service
  accounts creates a paralysis that leaves weak passwords in place.

### Detection

- Monitor for TGS requests to service accounts (Event ID 4769)
- Alert on RC4 encryption type in Kerberos requests (encryption type 0x17)
- Use honeypot SPN accounts with alerts on any TGS request

---

## 5. Backup Operators Group Abuse

### Technical Details

- **Account:** `svc_backup`
- **Group:** Backup Operators (built-in)
- **Capability:** Can read any file on the system (bypass NTFS ACLs), dump
  registry hives (SAM, SYSTEM, SECURITY) containing local credentials
- **Attack:** `reg save HKLM\SAM`, `reg save HKLM\SYSTEM` remotely

### Real-World Context

Backup Operators is a **frequently overlooked privileged group** because:

- **Backup software requirements:** Enterprise backup solutions (Veeam,
  Commvault, Veritas) need to read all files regardless of NTFS permissions.
  The Backup Operators group provides this capability, and backup service
  accounts are routinely added.
- **Perceived as non-admin:** Many administrators don't consider Backup
  Operators as a security-sensitive group because it doesn't grant explicit
  admin rights. However, the ability to read any file (including SAM and
  SECURITY hives) effectively makes it equivalent to local admin.
- **Not monitored:** Most SIEM rules focus on Domain Admins and
  Administrators groups. Backup Operators membership changes and usage
  often fly under the radar.
- **Shared responsibilities:** In smaller organizations, IT staff wear
  multiple hats. A sysadmin who also handles backups gets added to Backup
  Operators, and their service accounts inherit these powerful rights.

### Detection

- Monitor Backup Operators group membership changes (Event ID 4728/4732)
- Alert on remote registry access to SAM/SECURITY hives
- Audit who is in Backup Operators and justify each membership

---

## 6. AS-REP Roasting

### Technical Details

- **Account:** `b.white` (Dr. Bob White)
- **Setting:** `DONT_REQUIRE_PREAUTH` flag enabled in userAccountControl
- **Attack:** Request AS-REP without knowing the password, crack offline
- **Tool:** `impacket-GetNPUsers`

### Real-World Context

AS-REP Roasting targets accounts with Kerberos preauthentication disabled.
This setting exists in real environments because:

- **Legacy application compatibility:** Some older applications and systems
  don't support Kerberos preauthentication. When these systems need to
  authenticate against AD, IT teams disable preauthentication on the
  associated user accounts.
- **Linux/UNIX integration (historical):** Older versions of pam_krb5 and
  some UNIX-AD integration solutions required preauthentication to be
  disabled. Although modern solutions (SSSD, realmd) handle this correctly,
  accounts configured years ago may still have the flag set.
- **Accidental misconfiguration:** The "Do not require Kerberos
  preauthentication" checkbox in ADUC is easily checked accidentally.
  Some organizations have no audit process to detect when this flag is
  set on accounts.
- **Troubleshooting artifacts:** When troubleshooting Kerberos issues,
  disabling preauthentication is a common step. If the root cause is
  found elsewhere, the preauthentication setting may not be reverted.

### Detection

- Monitor for AS-REQ without preauthentication data (Event ID 4768,
  result code 0x0, no preauthentication type)
- Regularly audit accounts with `DONT_REQUIRE_PREAUTH` flag
- Use PowerShell: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`

---

## 7. DCSync Rights Delegation

### Technical Details

- **Account:** `svc_deploy`
- **Rights:** `Replicating Directory Changes` + `Replicating Directory Changes All`
  on the domain object
- **Impact:** Can replicate any AD object's password hash, including krbtgt
- **GUIDs:** `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes),
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)

### Real-World Context

DCSync-capable accounts outside of Domain Controllers are a **critical** finding
because they provide complete domain compromise. They exist because:

- **Azure AD Connect:** The most common legitimate reason for DCSync rights.
  The Azure AD Connect service account needs replication rights to synchronize
  password hashes to Azure AD. If this account is compromised, the entire
  on-premises and cloud directory is at risk.
- **Third-party identity solutions:** Products like Okta AD Agent, PingFederate,
  and other identity providers may request replication rights during installation.
  Administrators grant them without fully understanding the security implications.
- **Migration projects:** During AD migrations (consolidation, restructuring,
  forest trust setup), administrators grant replication rights to service
  accounts. These rights are often not revoked after the project completes.
- **SIEM/monitoring integration:** Some SIEM solutions request replication
  rights to monitor AD changes in real-time. While there are safer alternatives
  (like using the AD replication changelog), some products default to requesting
  full replication rights.

### Detection

- Monitor for DRS replication requests from non-DC sources (Event ID 4662
  with replication GUIDs)
- Regularly audit accounts with replication rights on the domain object
- Alert on DCSync-like behavior: multiple 4662 events with both replication
  GUIDs from the same source in a short time window

---

## 8. GPO Misconfiguration

### Technical Details

- **Group:** `IT_Admins`
- **GPO:** Default Domain Policy (`{31B2F340-016D-11D2-945F-00C04FB984F9}`)
- **Right:** GenericAll (full control over the GPO object)
- **Impact:** Can modify domain-wide policy, push scripts, create local admins

### Real-World Context

GPO permissions are frequently misconfigured because:

- **Delegation complexity:** GPO security involves permissions on both the
  AD object (GPC) and the SYSVOL file share (GPT). Administrators often
  fix permissions on one but not the other, or grant overly broad permissions
  to simplify management.
- **IT team autonomy:** In organizations with multiple IT teams, GPO
  management is often delegated to different groups. Over time, delegations
  accumulate and the effective permissions on GPOs become difficult to audit.
- **Default policies as targets:** The Default Domain Policy and Default
  Domain Controllers Policy are especially dangerous because they apply to
  all objects in their scope. Granting write access to these GPOs effectively
  grants control over the entire domain.
- **Tool limitations:** Most AD management tools don't make it easy to audit
  GPO permissions comprehensively. Without tools like BloodHound or
  Group3r, GPO ACL issues go undetected.

### Detection

- Audit GPO modification events (Event ID 5136 on groupPolicyContainer objects)
- Regularly review GPO ACLs with Get-GPPermission or BloodHound
- Monitor for unexpected GPO link changes (Event ID 5136/5137)

---

## 9. Shadow Admin via Nested Groups

### Technical Details

- **Group:** `IT_Admins`
- **Member:** `helpdesk01`
- **Nested into:** `Domain Admins`
- **Impact:** `helpdesk01` effectively has Domain Admin rights through
  group nesting, which is not immediately obvious

### Real-World Context

Shadow administrators through nested groups are **one of the most common
enterprise AD issues**:

- **Administrative convenience:** IT managers create departmental admin
  groups and nest them into built-in admin groups for easier management.
  This creates indirect paths to admin that are not visible in simple
  group membership queries.
- **Organizational changes:** When teams merge or restructure, group
  nesting is used to maintain access without migrating individual users.
  Over time, the nesting depth increases and becomes impossible to trace
  manually.
- **Audit tool limitations:** Native AD tools like ADUC show direct
  membership only. Without recursive membership queries or graph-based
  tools like BloodHound, nested admin paths remain invisible.
- **Principle of least privilege violations:** Help desk accounts are
  especially problematic because they are used by junior IT staff who
  may be more susceptible to phishing. If a helpdesk account has
  indirect Domain Admin access, a phishing attack on a junior analyst
  can lead to complete domain compromise.

### Detection

- Use `Get-ADGroupMember -Recursive "Domain Admins"` to find all
  effective members
- BloodHound: Query for shortest paths to Domain Admins
- Regularly audit and flatten admin group nesting

---

## 10. AdminSDHolder Abuse

### Technical Details

- **Container:** `CN=AdminSDHolder,CN=System,DC=umbrella,DC=corp`
- **Modified ACL:** `IT_Admins` has GenericAll on AdminSDHolder
- **Mechanism:** Every 60 minutes, `SDProp` process copies AdminSDHolder's
  ACL to all protected groups and accounts
- **Impact:** Persistent control over Domain Admins, Enterprise Admins,
  and other protected objects

### Real-World Context

AdminSDHolder abuse is a **sophisticated persistence mechanism** that
exploits a legitimate AD security feature:

- **Misunderstood feature:** Most AD administrators don't fully understand
  the SDProp mechanism. They may modify AdminSDHolder permissions without
  realizing the cascading effect on all protected objects.
- **Post-compromise persistence:** Attackers who gain Domain Admin often
  modify AdminSDHolder as a backdoor. Even if the specific compromise is
  detected and remediated, the AdminSDHolder modification survives and
  re-grants access every 60 minutes.
- **Audit difficulty:** AdminSDHolder changes don't generate obvious
  alerts in most SIEM configurations. The object is rarely monitored,
  and the ACL propagation is a normal AD process.

### Detection

- Monitor ACL changes on `CN=AdminSDHolder,CN=System` (Event ID 5136)
- Compare AdminSDHolder ACL against a known-good baseline
- Alert on any non-default ACEs on AdminSDHolder

---

## 11. WDigest Credential Caching

### Technical Details

- **Registry key:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
- **Value:** `UseLogonCredential = 1`
- **Impact:** Plaintext passwords stored in LSASS memory, extractable with
  mimikatz `sekurlsa::wdigest`

### Real-World Context

WDigest credential caching in memory is a legacy feature that persists in
many environments:

- **Pre-2014 default:** Before Microsoft's KB2871997 patch, WDigest stored
  cleartext passwords in memory by default on all Windows versions. Systems
  that haven't been updated or properly hardened after patching still have
  this enabled.
- **Legacy application requirements:** Some older applications (particularly
  web-based IIS applications using HTTP Digest authentication) require WDigest
  to function. Disabling it breaks these applications.
- **Mimikatz-friendly environment:** Combined with disabled Defender and no
  Credential Guard, this allows trivial credential extraction from memory.
  This exact combination is found in many real enterprises, especially on
  older server operating systems.

### Detection

- Monitor the WDigest registry key for changes
- Use Credential Guard on Windows 10/Server 2016+ to prevent extraction
- Deploy LSASS protection (RunAsPPL) to prevent credential dumping tools
