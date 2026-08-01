
<#
.SYNOPSIS
    DCSync Permission Audit and Cleanup Script
.DESCRIPTION
    Audits domain root ACL for accounts with DCSync permissions.
    DCSync allows an account to replicate all password hashes from AD
    without being a Domain Controller — including krbtgt and Administrator.
    
    Legitimate DCSync permissions should only exist on:
    - Domain Controllers
    - Enterprise Domain Controllers  
    - BUILTIN\Administrators
    
    Any other account with these permissions is a critical security risk.
.NOTES
    Run with Domain Admin privileges on Domain Controller
    Always backup ACL before making changes
#>

#region BACKUP

$dn = (Get-ADDomain).DistinguishedName
$backupPath = "C:\ADYedek\domain_acl_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"

New-Item -Path "C:\ADYedek" -ItemType Directory -Force | Out-Null
Get-Acl "AD:$dn" | Export-Clixml $backupPath
Write-Host "ACL backup saved: $backupPath" -ForegroundColor Green
Write-Host "Restore with: Set-Acl 'AD:$dn' (Import-Clixml '$backupPath')" -ForegroundColor Yellow

#endregion

#region AUDIT

Write-Host "`n=== DCSYNC PERMISSION AUDIT ===" -ForegroundColor Cyan

$replicationRights = @(
    [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # Replicating Directory Changes All
    [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # Replicating Directory Changes
)

$acl = Get-Acl "AD:$dn"
$dcsyncEntries = $acl.Access | Where-Object { $_.ObjectType -in $replicationRights }

Write-Host "`nAll accounts with DCSync permissions:" -ForegroundColor Yellow
$dcsyncEntries | Select-Object @{n='Identity';e={$_.IdentityReference}}, 
                                ActiveDirectoryRights, 
                                AccessControlType | 
    Format-Table -AutoSize

# Identify orphaned SIDs (deleted accounts still holding permissions)
$orphaned = $dcsyncEntries | Where-Object { 
    $_.IdentityReference.Value -match '^S-1-5-21-' 
}

if ($orphaned) {
    Write-Host "`nORPHANED DCSync permissions found (deleted accounts):" -ForegroundColor Red
    $orphaned | Select-Object @{n='SID';e={$_.IdentityReference}} | Format-Table
    Write-Host "Count: $($orphaned.Count)" -ForegroundColor Red
} else {
    Write-Host "`nNo orphaned DCSync permissions found." -ForegroundColor Green
}

#endregion

#region CLEANUP

Write-Host "`n=== CLEANUP ===" -ForegroundColor Cyan
Write-Host "Removing orphaned DCSync ACEs (deleted account SIDs only)..." -ForegroundColor Yellow

$confirm = Read-Host "Type YES to remove $($orphaned.Count) orphaned ACEs"
if ($confirm -ne "YES") { Write-Host "Aborted."; exit }

foreach ($ace in $orphaned) {
    $null = $acl.RemoveAccessRuleSpecific($ace)
}

Set-Acl "AD:$dn" -AclObject $acl
Write-Host "Cleanup complete." -ForegroundColor Green

#endregion

#region VERIFY

Write-Host "`n=== VERIFICATION ===" -ForegroundColor Cyan
Write-Host "Remaining DCSync permissions (should only be system accounts):" -ForegroundColor Yellow

$acl2 = Get-Acl "AD:$dn"
$acl2.Access | Where-Object { $_.ObjectType -in $replicationRights } | 
    Select-Object @{n='Identity';e={$_.IdentityReference}} | 
    Sort-Object Identity -Unique | 
    Format-Table -AutoSize

#endregion
