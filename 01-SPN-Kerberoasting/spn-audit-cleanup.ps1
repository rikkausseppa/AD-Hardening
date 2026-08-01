
<#
.SYNOPSIS
    SPN Audit and Cleanup Script
.DESCRIPTION
    Detects user accounts with Service Principal Names (SPNs) registered.
    Human accounts with SPNs are vulnerable to Kerberoasting attacks.
    Attacker can request TGS tickets offline and crack passwords without detection.
.AUTHOR
    AD Hardening Project
.NOTES
    Run with Domain Admin privileges
    Review output before removing any SPNs
#>

#region AUDIT - Detect SPNs on user accounts

Write-Host "`n=== SPN AUDIT ===" -ForegroundColor Cyan
Write-Host "Scanning for user accounts with SPNs registered...`n"

$spnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} `
    -Properties ServicePrincipalName, PasswordLastSet, whenCreated, whenChanged |
    Select-Object SamAccountName, 
                  PasswordLastSet, 
                  whenCreated, 
                  whenChanged,
                  @{n='SPN';e={$_.ServicePrincipalName -join ' | '}}

if ($spnUsers) {
    Write-Host "FOUND - Accounts with SPNs:" -ForegroundColor Yellow
    $spnUsers | Format-Table -AutoSize
} else {
    Write-Host "CLEAN - No user accounts with SPNs found." -ForegroundColor Green
}

#endregion

#region CHECK - Duplicate SPNs (causes Kerberos authentication failures)

Write-Host "`n=== DUPLICATE SPN CHECK ===" -ForegroundColor Cyan
setspn -X
Write-Host ""

#endregion

#region AUDIT - Orphaned SPNs (pointing to deleted servers)

Write-Host "=== ORPHANED SPN CHECK ===" -ForegroundColor Cyan
Write-Host "Checking if SPN target computers still exist in AD...`n"

foreach ($user in $spnUsers) {
    foreach ($spn in ($user.SPN -split ' \| ')) {
        if ($spn -match 'MSSQLSvc/([^:]+)') {
            $server = $matches[1] -replace '\..*',''
            $exists = Get-ADComputer $server -EA SilentlyContinue
            if (-not $exists) {
                Write-Host "ORPHANED SPN: $spn on account $($user.SamAccountName)" -ForegroundColor Red
                Write-Host "  Server '$server' does not exist in AD" -ForegroundColor Red
            }
        }
    }
}

#endregion

#region REMOVE - Uncomment to remove specific SPNs
# WARNING: Verify each SPN before removal
# setspn -D "MSSQLSvc/servername.domain.com:1433" AccountName
# setspn -D "MSSQLSvc/servername.domain.com" AccountName
#endregion
