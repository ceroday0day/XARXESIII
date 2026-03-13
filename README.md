# 0xLab-AD — Umbrella Corporation

[![Lab Type](https://img.shields.io/badge/Lab-Active%20Directory-blue)]()
[![Platform](https://img.shields.io/badge/Platform-Vagrant%20%2B%20VirtualBox-orange)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate--Advanced-red)]()
[![License](https://img.shields.io/badge/License-Educational%20Use-green)]()

> A fully automated vulnerable Active Directory lab for security research and penetration testing practice.
> Themed as **Umbrella Corporation** — a fictional biotech company.

---

## Network Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Host-Only Network                            │
│                    192.168.56.0/24                               │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │    DC01       │  │    SRV01     │  │    WS01      │          │
│  │ Win Srv 2019 │  │ Win Srv 2016 │  │  Windows 10  │          │
│  │   .56.10     │  │   .56.11     │  │   .56.12     │          │
│  │              │  │              │  │              │          │
│  │ - AD DS      │  │ - IIS 8080   │  │ - RSAT       │          │
│  │ - DNS        │  │ - SMB Share  │  │ - RDP        │          │
│  │ - GPO        │  │ - File Srv   │  │ - PS Remoting│          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                 │                   │
│  ═══════╪═════════════════╪═════════════════╪═══════════════    │
│         │     umbrella.corp domain          │                   │
│         │                 │                 │                   │
│  ┌──────┴─────────────────┴─────────────────┴───────┐          │
│  │                  NAT Network                       │          │
│  └──────────────────────┬────────────────────────────┘          │
│                         │                                       │
│                  ┌──────┴───────┐                               │
│                  │    KALI      │                               │
│                  │ Kali Linux   │                               │
│                  │   .56.100    │                               │
│                  │              │                               │
│                  │ - impacket   │                               │
│                  │ - bloodhound │                               │
│                  │ - nmap       │                               │
│                  │ - hashcat    │                               │
│                  └──────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

| Software | Version | Link |
|----------|---------|------|
| Vagrant | ≥ 2.3 | [vagrantup.com](https://www.vagrantup.com/downloads) |
| VirtualBox | ≥ 7.0 | [virtualbox.org](https://www.virtualbox.org/wiki/Downloads) |
| RAM | ≥ 16 GB | — |
| Disk | ≥ 80 GB free | — |

### Deploy the Lab

```bash
# Clone the repository
git clone <repo-url> 0xLab-AD
cd 0xLab-AD

# Deploy all machines (takes ~30-45 minutes)
vagrant up

# Check status
vagrant status

# SSH into Kali attacker machine
vagrant ssh kali
```

### Lab Management

```bash
# Pause the lab (saves state)
vagrant suspend

# Resume the lab
vagrant resume

# Destroy and rebuild from scratch
vagrant destroy -f && vagrant up

# Reset all vulnerabilities to initial state (run on DC01)
vagrant winrm dc01 -c "powershell -File C:\vagrant\scripts\reset-lab.ps1"

# Verify all vulnerabilities are configured
vagrant winrm dc01 -c "powershell -File C:\vagrant\scripts\verify-lab.ps1"
```

---

## Attack Path Overview

The lab implements a **multi-stage attack chain** that requires understanding
and chaining of multiple techniques — no single exploit gives Domain Admin.

```
Anonymous SMB ──► Cleartext Creds ──► ACL Abuse ──► Kerberoasting
       │                                                  │
       ▼                                                  ▼
  IIS Webshell ──► RCE on SRV01         Backup Operators Abuse
                                                  │
                                                  ▼
              AS-REP Roasting ──► DCSync ──► Golden Ticket
                                     │
                                     ▼
                              DOMAIN COMPROMISE
```

### Vulnerability Summary

| # | Technique | Target | Difficulty |
|---|-----------|--------|------------|
| 1 | Anonymous SMB Access | SRV01 | Easy |
| 2 | IIS File Upload (Webshell) | SRV01 | Easy |
| 3 | ACL Abuse (GenericWrite) | svc_monitor → svc_backup | Medium |
| 4 | Kerberoasting | svc_sql | Medium |
| 5 | Backup Operators Abuse | svc_backup → Registry Hives | Medium |
| 6 | AS-REP Roasting | b.white | Easy |
| 7 | DCSync | svc_deploy | Hard |
| 8 | GPO Abuse | IT_Admins | Hard |
| 9 | AdminSDHolder Persistence | IT_Admins | Advanced |
| 10 | Golden Ticket | krbtgt hash | Advanced |

---

## Repository Structure

```
0xLab-AD/
├── Vagrantfile                     # VM definitions and provisioning
├── README.md                       # This file
├── provisioning/
│   ├── dc01.ps1                    # DC promotion and forest creation
│   ├── srv01.ps1                   # IIS + SMB share setup
│   └── ws01.ps1                    # Workstation domain join
├── scripts/
│   ├── setup-ad.ps1                # OUs, users, groups, SPNs
│   ├── setup-vulns.ps1             # Deliberate misconfigurations
│   ├── reset-lab.ps1               # Reset to initial state
│   └── verify-lab.ps1              # Vulnerability health check
├── attacker/
│   ├── auto-enum.sh                # Automated enumeration script
│   └── attack-chain.md             # Step-by-step walkthrough
└── docs/
    ├── architecture.md             # Detailed infrastructure docs
    ├── vulnerabilities.md          # Vulnerability deep-dives
    └── remediation.md              # Blue team fixes
```

---

## Domain Structure

**Domain:** `umbrella.corp` | **NetBIOS:** `UMBRELLA`

```
umbrella.corp
└── OU=Departments
    ├── OU=Research
    │   ├── Dr. Alice Green (a.green)
    │   └── Dr. Bob White (b.white)     ← AS-REP Roastable
    ├── OU=IT
    │   ├── svc_backup                   ← Backup Operators
    │   ├── svc_deploy                   ← DCSync rights
    │   └── helpdesk01                   ← Shadow Domain Admin
    ├── OU=Management
    │   ├── CEO — Ozwell Spencer
    │   ├── CFO — James Marcus
    │   └── CTO — William Birkin
    └── OU=ServiceAccounts
        ├── svc_sql                      ← Kerberoastable (weak pwd)
        ├── svc_iis
        └── svc_monitor                  ← Entry point creds
```

---

## Tools Required

### On Kali (Pre-installed)

- **impacket** — GetUserSPNs, GetNPUsers, secretsdump, psexec, smbclient
- **BloodHound** + **bloodhound-python** — AD graph analysis
- **CrackMapExec** — Multi-protocol credential testing
- **nmap** — Network scanning
- **hashcat** / **john** — Password cracking
- **evil-winrm** — WinRM shells
- **enum4linux-ng** — SMB enumeration
- **ldapdomaindump** — LDAP data extraction
- **Responder** — LLMNR/NBT-NS poisoning

### Optional (Windows)

- **Rubeus** — Kerberos abuse
- **Mimikatz** — Credential extraction
- **SharpGPOAbuse** — GPO exploitation
- **PowerView** — AD enumeration

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Detailed infrastructure and network design |
| [Vulnerabilities](docs/vulnerabilities.md) | Deep-dive into each vulnerability with real-world context |
| [Remediation](docs/remediation.md) | Blue team guide — how to fix each misconfiguration |
| [Attack Chain](attacker/attack-chain.md) | Step-by-step exploitation walkthrough |

---

## Disclaimer

> **⚠️ This lab is for authorized security research and education only.**
>
> All vulnerabilities are **deliberately configured** in an isolated environment.
> Do not deploy this on production networks. Do not use these techniques against
> systems without explicit written authorization.
>
> The creators assume no liability for misuse of this material.
