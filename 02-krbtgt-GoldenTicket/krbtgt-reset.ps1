
<#
.SYNOPSIS
    krbtgt Account Password Reset Script
.DESCRIPTION
    Resets the krbtgt account password to protect against Golden Ticket attacks.
    
    IMPORTANT: Must be reset TWICE with minimum 10 hours between resets.
    - First reset: invalidates current key
    - Second reset: invalidates previous key (N-1)
    
    Single reset is NOT sufficient - attacker's old key still works.
.NOTES
    Run on PDC Emulator with Domain Admin privileges
    Monitor for Kerberos errors after reset
#>

#region PRE-CHECK

Write-Host "`n=== PRE-FLIGHT CHECKS ===" -ForegroundColor Cyan

# Check replication health first
Write-Host "Checking replication status..." -ForegroundColor Yellow
repadmin /replsummary

# Get current KVNO
$kvno = (Get-ADUser krbtgt -Properties 'msDS-KeyVersionNumber').'msDS-KeyVersionNumber'
Write-Host "`nCurrent krbtgt KVNO: $kvno" -ForegroundColor Yellow
Write-Host "After reset it will be: $($kvno + 1)" -ForegroundColor Yellow

# Check last password set via replication metadata
$dn = (Get-ADUser krbtgt).DistinguishedName
Write-Host "`nChecking password history via replication metadata..."
repadmin /showobjmeta localhost "$dn" | Select-String "unicodePwd|pwdLastSet"

#endregion

#region RESET

Write-Host "`n=== krbtgt PASSWORD RESET ===" -ForegroundColor Cyan
Write-Host "WARNING: Reset krbtgt TWICE with 10+ hours between resets" -ForegroundColor Red
Write-Host "Single reset leaves previous key (N-1) still
