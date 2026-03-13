# Architecture — 0xLab-AD

## Overview

The 0xLab-AD environment simulates a small corporate Active Directory network
for **Umbrella Corporation**, a fictional biotech company. The lab is designed
to mirror common enterprise configurations that lead to domain compromise
when chained together.

---

## Network Architecture

### Addressing

| Machine | Role | IP Address | OS |
|---------|------|------------|----|
| DC01 | Primary Domain Controller | 192.168.56.10 | Windows Server 2019 |
| SRV01 | File Server + IIS Intranet | 192.168.56.11 | Windows Server 2016 |
| WS01 | IT Workstation | 192.168.56.12 | Windows 10 |
| WS02 | HR Workstation | 192.168.56.13 | Windows 10 |
| WS03 | Research Workstation | 192.168.56.14 | Windows 10 |
| WS04 | Management Workstation | 192.168.56.15 | Windows 10 |
| UBSRV01 | Linux Server (domain-joined) | 192.168.56.20 | Ubuntu Server 22.04 |
| KALI | Attacker Machine | 192.168.56.100 | Kali Linux (Rolling) |

### Network Configuration

- **Subnet:** 192.168.56.0/24
- **Adapter:** VirtualBox Host-Only (umbrella_net)
- **Gateway:** 192.168.56.1 (VirtualBox host)
- **DNS:** DC01 (192.168.56.10) for all domain members

### Ports & Services

#### DC01 (192.168.56.10)

| Port | Protocol | Service |
|------|----------|---------|
| 53 | TCP/UDP | DNS |
| 88 | TCP/UDP | Kerberos |
| 135 | TCP | RPC Endpoint Mapper |
| 139 | TCP | NetBIOS Session Service |
| 389 | TCP/UDP | LDAP |
| 445 | TCP | SMB |
| 464 | TCP/UDP | Kerberos kpasswd |
| 636 | TCP | LDAPS |
| 3268 | TCP | Global Catalog |
| 3269 | TCP | Global Catalog SSL |
| 5985 | TCP | WinRM HTTP |
| 5986 | TCP | WinRM HTTPS |

#### SRV01 (192.168.56.11)

| Port | Protocol | Service |
|------|----------|---------|
| 80 | TCP | IIS Default |
| 135 | TCP | RPC |
| 139 | TCP | NetBIOS |
| 445 | TCP | SMB (Public share) |
| 8080 | TCP | IIS Intranet (vulnerable) |
| 5985 | TCP | WinRM |

#### WS01 (192.168.56.12)

| Port | Protocol | Service |
|------|----------|---------|
| 135 | TCP | RPC |
| 445 | TCP | SMB |
| 3389 | TCP | RDP |
| 5985 | TCP | WinRM |

#### WS02 (192.168.56.13)

| Port | Protocol | Service |
|------|----------|---------|
| 135 | TCP | RPC |
| 445 | TCP | SMB |
| 3389 | TCP | RDP |
| 5985 | TCP | WinRM |

#### WS03 (192.168.56.14)

| Port | Protocol | Service |
|------|----------|---------|
| 135 | TCP | RPC |
| 445 | TCP | SMB |
| 3389 | TCP | RDP |
| 5985 | TCP | WinRM |

#### WS04 (192.168.56.15)

| Port | Protocol | Service |
|------|----------|---------|
| 135 | TCP | RPC |
| 445 | TCP | SMB |
| 3389 | TCP | RDP |
| 5985 | TCP | WinRM |

#### UBSRV01 (192.168.56.20)

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |

---

## Active Directory Structure

### Domain

- **FQDN:** umbrella.corp
- **NetBIOS:** UMBRELLA
- **Functional Level:** Windows Server 2016 (WinThreshold)
- **Forest Functional Level:** Windows Server 2016

### Organizational Unit Hierarchy

```
DC=umbrella,DC=corp
├── CN=Users (default)
├── CN=Computers (default)
├── CN=Builtin (default)
└── OU=Departments
    ├── OU=Research
    │   ├── Dr. Alice Green (a.green)
    │   ├── Dr. Bob White (b.white)
    │   └── Research_Access (group)
    ├── OU=IT
    │   ├── svc_backup
    │   ├── svc_deploy
    │   ├── helpdesk01
    │   └── IT_Admins (group)
    ├── OU=Management
    │   ├── Ozwell Spencer — CEO (ceo)
    │   ├── James Marcus — CFO (cfo)
    │   └── William Birkin — CTO (cto)
    └── OU=ServiceAccounts
        ├── svc_sql
        ├── svc_iis
        └── svc_monitor
```

### Group Memberships

```
Domain Admins
└── IT_Admins (nested — shadow admin)
    └── helpdesk01

Backup Operators
└── svc_backup

Research_Access
├── a.green
└── b.white

VPN_Users
├── a.green
├── b.white
├── helpdesk01
├── ceo
└── cto
```

### Service Principal Names (SPNs)

| Account | SPN | Purpose |
|---------|-----|---------|
| svc_sql | MSSQLSvc/srv01.umbrella.corp:1433 | SQL Server |
| svc_sql | MSSQLSvc/srv01.umbrella.corp | SQL Server (default) |
| svc_iis | HTTP/srv01.umbrella.corp | IIS Web Server |
| svc_iis | HTTP/srv01 | IIS (short name) |

---

## Provisioning Flow

The lab deploys in a specific order to handle dependencies:

```
1. DC01 — Install AD DS → Promote to DC → Reboot
      ↓
2. DC01 — setup-ad.ps1 → Create OUs, users, groups, SPNs → Reboot
      ↓
3. DC01 — setup-vulns.ps1 → Apply ACLs, AS-REP, DCSync, GPO
      ↓
4. SRV01 — Join domain → Install IIS → Create SMB share → Reboot
      ↓
5. WS01 — Join domain → Install RSAT → Enable RDP → Reboot
      ↓
6. WS02 — Join domain → Install RSAT → Enable RDP → Reboot
      ↓
7. WS03 — Join domain → Install RSAT → Enable RDP → Reboot
      ↓
8. WS04 — Join domain → Install RSAT → Enable RDP → Reboot
      ↓
9. UBSRV01 — Install realmd/SSSD → Join domain via realm join
      ↓
10. KALI — Install tools → Configure /etc/hosts → Sync attack scripts
```

### Resource Requirements

| VM | RAM | CPU | Disk |
|----|-----|-----|------|
| DC01 | 4 GB | 2 cores | ~40 GB |
| SRV01 | 2 GB | 2 cores | ~40 GB |
| WS01 | 2 GB | 2 cores | ~40 GB |
| WS02 | 2 GB | 2 cores | ~40 GB |
| WS03 | 2 GB | 2 cores | ~40 GB |
| WS04 | 2 GB | 2 cores | ~40 GB |
| UBSRV01 | 2 GB | 2 cores | ~10 GB |
| KALI | 4 GB | 2 cores | ~30 GB |
| **Total** | **20 GB** | **16 cores** | **~280 GB** |

> **Minimum host:** 24 GB RAM recommended (VirtualBox overhead + host OS).

---

## Security Configuration

### Deliberately Weakened

The following security controls are **intentionally disabled** for the lab:

- Windows Firewall (all profiles) on all Windows machines
- Windows Defender real-time protection
- SMB signing (not enforced)
- LDAP signing (not enforced)
- Kerberos preauthentication (disabled for b.white)
- WDigest credential caching (enabled for cleartext creds in memory)

### Default State

- All accounts have `PasswordNeverExpires` enabled
- No fine-grained password policies
- No account lockout policy
- PS Remoting enabled on all Windows machines
- Anonymous LDAP enumeration allowed
