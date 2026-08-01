
<#
.SYNOPSIS
    SQL Server Service Account Audit Script
.DESCRIPTION
    Detects SQL Server instances running under privileged domain accounts.
    SQL services running as Domain Admin store credentials in LSA Secrets —
    readable in plaintext by anyone with SYSTEM privileges on that server.
.NOTES
    Run with Domain Admin privileges
#>

#region AUDIT - Find SQL services running under domain accounts

Write-Host "`n=== SQL SERVICE ACCOUNT AUDIT ===" -ForegroundColor Cyan

$servers = Get-ADComputer -Filter {
    Enabled -eq $true -and OperatingSystem -like "*Server*"
} | Select-Object -ExpandProperty Name

$results = foreach ($server in $servers) {
    if (Test-Connection $server -Count 1 -Quiet -EA SilentlyContinue) {
        Get-CimInstance Win32_Service -ComputerName $server -EA SilentlyContinue |
            Where-Object { 
                $_.Name -match '^MSSQL|SQLAgent|SQLSERVERAGENT' -and
                $_.StartName -notmatch 'NT SERVICE|NT AUTHORITY|LocalSystem|^$'
            } |
            Select-Object @{n='Server';e={$server}}, 
                          Name, 
                          StartName, 
                          State,
                          @{n='Risk';e={
                            if ($_.StartName -match 'Domain Admins|Administrator') { 'CRITICAL' }
                            else { 'HIGH' }
                          }}
    }
}

if ($results) {
    Write-Host "FOUND - SQL services running under domain accounts:" -ForegroundColor Red
    $results | Format-Table -AutoSize
    Write-Host "`nThese accounts store passwords in LSA Secrets!" -ForegroundColor Red
    Write-Host "Anyone with local admin on these servers can read plaintext passwords." -ForegroundColor Red
} else {
    Write-Host "CLEAN - No SQL services running under domain accounts." -ForegroundColor Green
}

#endregion

#region CHECK - Verify Virtual Account configuration

Write-Host "`n=== VIRTUAL ACCOUNT VERIFICATION ===" -ForegroundColor Cyan

$sqlServices = foreach ($server in $servers) {
    if (Test-Connection $server -Count 1 -Quiet -EA SilentlyContinue) {
        Get-CimInstance Win32_Service -ComputerName $server -EA SilentlyContinue |
            Where-Object { $_.Name -match '^MSSQL' } |
            Select-Object @{n='Server';e={$server}},
                          Name,
                          StartName,
                          State,
                          @{n='Status';e={
                            if ($_.StartName -match 'NT SERVICE') { '✅ Virtual Account' }
                            elseif ($_.StartName -match 'NT AUTHORITY') { '✅ Built-in' }
                            else { '❌ Domain Account - FIX REQUIRED' }
                          }}
    }
}

$sqlServices | Format-Table -AutoSize

#endregion

#region MIGRATE - Change SQL service to Virtual Account
# WARNING: Use SQL Server Configuration Manager WMI interface
# Never use services.msc — it won't update Service Master Key

# Uncomment and modify to migrate:
<#
$server = "sql-server-name"
$instance = "SQLEXPRESS"  # or MSSQLSERVER for default instance

$svc = Get-CimInstance -Namespace "root\Microsoft\SqlServer\ComputerManagement16" `
    -ClassName SqlService -ComputerName $server |
    Where-Object { $_.ServiceName -eq "MSSQL`$$instance" }

Invoke-CimMethod -InputObject $svc -MethodName SetServiceAccount -Arguments @{
    ServiceStartName     = "NT SERVICE\MSSQL`$$instance"
    ServiceStartPassword = ''
}
#>

#endregion
