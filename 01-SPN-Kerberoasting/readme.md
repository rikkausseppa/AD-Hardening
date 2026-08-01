# 01 - SPN Audit & Kerberoasting Prevention

## What is Kerberoasting?

Kerberoasting targets Active Directory user accounts with Service Principal Names (SPNs).

**Attack Flow:**
## Why is it Critical?

- **Silent:** Offline cracking leaves no logs in AD
- **Fast:** RC4 tickets cracked with GPU in minutes  
- **High impact:** SPN on Domain Admin = full domain compromise

## What I Found

During an AD hardening assessment:

- Multiple **privileged user accounts** had SPNs registered
- **Orphaned SPNs** pointing to deleted servers still existed
- KDC issues tickets even for non-existent servers — still vulnerable

**Root cause:** SQL Server installed using human/admin accounts instead of service accounts.

## Remediation

**1. Audit**
```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
setspn -X  # Check duplicates
```

**2. Migrate SQL to Virtual Account**
```powershell
$svc = Get-CimInstance -Namespace "root\Microsoft\SqlServer\ComputerManagement16" `
    -ClassName SqlService | Where-Object { $_.ServiceName -eq 'MSSQL$SQLEXPRESS' }

Invoke-CimMethod -InputObject $svc -MethodName SetServiceAccount -Arguments @{
    ServiceStartName     = 'NT SERVICE\MSSQL$SQLEXPRESS'
    ServiceStartPassword = ''
}
```

**3. Remove SPNs**
```powershell
setspn -D "MSSQLSvc/server.domain.com:1433" AccountName
```

## Result

12 SPNs removed
SQL migrated to Virtual Account (no password stored)
Kerberoasting surface eliminated
All databases remained ONLINE

## Key Lesson

> Never use human or privileged accounts as SQL service accounts.
> Use `NT SERVICE\MSSQL$InstanceName` (Virtual Account) — no password, nothing to steal.

## References
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Virtual Accounts - Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/service-accounts/service-accounts)
