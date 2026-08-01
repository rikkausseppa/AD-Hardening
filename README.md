# AD Hardening

Active Directory hardening techniques, scripts, and best practices based on real-world security assessments and post-incident remediation work.

## Contents

| # | Topic | Attack Technique | MITRE |
|---|-------|-----------------|-------|
| 01 | [SPN Audit & Kerberoasting Prevention](./01-SPN-Kerberoasting/) | Kerberoasting | T1558.003 |
| 02 | [krbtgt Reset & Golden Ticket Prevention](./02-krbtgt-GoldenTicket/) | Golden Ticket | T1558.001 |
| 03 | [DCSync Permission Audit & Cleanup](./03-DCSync-Cleanup/) | DCSync | T1003.006 |
| 04 | [SQL Service Account & Virtual Account Migration](./04-SQL-VirtualAccount/) | LSA Secrets | T1552.004 |

## Background

This repository documents hardening work performed after a ransomware incident. The attacker gained initial access through a compromised endpoint, performed lateral movement using credential theft techniques, and achieved domain compromise.

Key findings that enabled the attack:
- Privileged accounts running SQL services (credentials in LSA Secrets)
- SPNs on Domain Admin accounts (Kerberoasting target)
- krbtgt reset only once after incident (Golden Ticket still possible)
- Orphaned DCSync permissions from years of tool installations

## Environment

- Windows Server 2022 Domain Controllers
- Windows 10/11 endpoints
- Microsoft Entra Connect (hybrid identity)
- CrowdStrike Falcon EDR

## Tools Used

- PowerShell 5.1+
- Active Directory PowerShell Module
- Repadmin
- Setspn
- SQL Server WMI Provider

## Key Principles

**1. Audit before change** — Never modify without documenting current state first.

**2. Always have a rollback plan** — Every change includes restore commands.

**3. Verify after every change** — Multi-layer validation (service → data → application → user).

**4. One change at a time** — Easier to isolate issues when changes are atomic.

**5. Least privilege everywhere** — Virtual Accounts, gMSA, no human accounts as service accounts.

## Upcoming

- 05 - GPO Hardening (LLMNR, Print Spooler, SMB Signing)
- 06 - Tier Model Implementation
- 07 - Loopback Processing for Terminal Servers
- 08 - Telegram Alert System for Critical AD Events
- 09 - LAPS Deployment
- 10 - Entra Connect Hardening

## Connect

- [LinkedIn](https://linkedin.com/rikkausseppa
- [PowerShell-Automation](https://github.com/rikkausseppa/AD-Hardening/)
