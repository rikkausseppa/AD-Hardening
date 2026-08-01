
# 04 - SQL Server Service Account & Virtual Account Migration

## The Problem: LSA Secrets

When SQL Server runs under a domain account, Windows must store that account's password to auto-start the service after reboot. The password is stored in LSA Secrets registry location in reversible encrypted format.

Anyone with SYSTEM privileges on that server can read it in plaintext using tools like mimikatz `lsadump::secrets`. No brute force, no cracking — direct read. If that account is Domain Admin, the entire domain is compromised from a single server.

## What is a Virtual Account?

Virtual Accounts (`NT SERVICE\ServiceName`) are managed service identities introduced in Windows Server 2008 R2. They have no password — nothing is stored, nothing can be stolen. They are isolated to the specific service and machine, and use the machine account identity for network access.

## What I Found

SQL Server instance on an application server was running under a Domain Admin account. That server was accessible to many users and external vendors for software updates. LSA Secrets on that server contained the Domain Admin password in recoverable format. This was the most likely lateral movement path in a previous ransomware incident.

## Critical Discovery During Remediation

Registry `DefaultData` was empty, suggesting databases were in the default SQL directory. However `sys.master_files` revealed databases were in a custom path (`C:\AppData\...`). The Virtual Account had no permissions there. Migrating without fixing this first would have caused all databases to enter RECOVERY_PENDING state and taken down the application completely.

**Always verify actual database file locations before migrating service accounts.**

## Remediation Steps

**1 — Audit SQL service accounts across all servers**
```powershell
Get-ADComputer -Filter {Enabled -eq $true -and OperatingSystem -like "*Server*"} | % {
    Get-CimInstance Win32_Service -ComputerName $_.Name -EA 0 |
        Where-Object { $_.Name -match '^MSSQL' } |
        Select-Object @{n='Server';e={$_.PSComputerName}}, Name, StartName, State
}
```

**2 — Backup NTFS permissions on database directories**
```powershell
icacls "C:\DatabasePath" /save C:\Backup\db_permissions.txt /T /C
# Restore: icacls "C:\DatabasePath" /restore C:\Backup\db_permissions.txt
```

**3 — Grant Virtual Account access to database directories**
```powershell
icacls "C:\DatabasePath" /grant '"NT SERVICE\MSSQL$INSTANCENAME":(OI)(CI)F' /T /C
```

**4 — Migrate service account using WMI (NOT services.msc)**
```powershell
$svc = Get-CimInstance -Namespace "root\Microsoft\SqlServer\ComputerManagement16" `
    -ClassName SqlService | Where-Object { $_.ServiceName -eq 'MSSQL$INSTANCENAME' }

Invoke-CimMethod -InputObject $svc -MethodName SetServiceAccount -Arguments @{
    ServiceStartName     = 'NT SERVICE\MSSQL$INSTANCENAME'
    ServiceStartPassword = ''
}
# Expected: ReturnValue : 0
```

**5 — Verify all databases are ONLINE**
```powershell
Invoke-Command -ComputerName sql-server -ScriptBlock {
    sqlcmd -S .\INSTANCENAME -E -W -Q "SELECT name, state_desc FROM sys.databases"
}
```

## Why NOT services.msc?

SQL Server Configuration Manager (and its WMI interface) updates NTFS permissions, registry ACLs, and re-encrypts the Service Master Key for the new account context. services.msc does none of this. Using services.msc risks the service failing to start or encrypted data becoming inaccessible.

## Result

- SQL service migrated to Virtual Account — no password stored anywhere
- All databases remained ONLINE after migration
- Application services running normally
- LSA Secrets no longer contains domain credentials on this server

## Key Lesson

Never use human or privileged accounts as SQL service accounts. Use `NT SERVICE\MSSQL$InstanceName` (Virtual Account) or gMSA. Virtual Accounts have no password — nothing to steal, nothing to crack, nothing stored in LSA Secrets.

## References
- [MITRE ATT&CK T1552.004 - LSA Secrets](https://attack.mitre.org/techniques/T1552/004/)
- [Virtual Accounts - Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/service-accounts/service-accounts)
- [SQL Server Service Account Best Practices](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)
