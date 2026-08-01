# 02 - krbtgt Reset & Golden Ticket Prevention

## What is a Golden Ticket?

If an attacker obtains the krbtgt account's password hash, they can forge any Kerberos ticket for any user, with any privileges, valid for any duration — even after the real account is deleted or password changed.

**Why it's catastrophic:**
- Works even if targeted account password is changed or deleted
- No failed login logs generated
- Ticket can be valid for 10 years
- Attacker can return months later using the same ticket

## How krbtgt Works

When a user logs in, the DC generates a TGT (Ticket Granting Ticket) encrypted with the krbtgt key. The KDC trusts any TGT it can successfully decrypt — without checking AD. If the attacker has the krbtgt hash, they encrypt their own TGT and the KDC trusts it unconditionally.

## Why Single Reset is NOT Enough

AD maintains two valid krbtgt keys simultaneously (N and N-1) to prevent authentication disruption during rotation.

Single reset: N = new key, N-1 = old key → attacker's key still works.

Double reset (10+ hours apart): N = newest, N-1 = first reset, N-2 = attacker's key → INVALID.

## What I Found

- krbtgt password had only been reset once after a security incident
- Previous key (N-1) was still valid — attacker could still forge tickets
- Replication metadata confirmed single reset with one timestamp
- KVNO was at 5, needed second reset to reach 6

## Remediation Steps

**1 — Check replication health before reset**
```powershell
repadmin /replsummary
```

**2 — Check current KVNO**
```powershell
(Get-ADUser krbtgt -Properties 'msDS-KeyVersionNumber').'msDS-KeyVersionNumber'
```

**3 — Verify last reset via replication metadata**
```powershell
$dn = (Get-ADUser krbtgt).DistinguishedName
repadmin /showobjmeta localhost "$dn"
# Look for unicodePwd — single timestamp = single reset = NOT safe
```

**4 — Reset on PDC Emulator**
```powershell
$pdc = (Get-ADDomain).PDCEmulator
Add-Type -AssemblyName System.Web
$pwd = [System.Web.Security.Membership]::GeneratePassword(64,12)
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) -Server $pdc
$pwd = $null
```

**5 — Force replication and verify KVNO on all DCs**
```powershell
repadmin /syncall /AdeP

Get-ADDomainController -Filter * | ForEach-Object {
    $k = (Get-ADUser krbtgt -Properties 'msDS-KeyVersionNumber' -Server $_.HostName).'msDS-KeyVersionNumber'
    "$($_.HostName) -> KVNO: $k"
}
```

**6 — Wait minimum 10 hours, then repeat steps 4-5**

## Result

- krbtgt reset twice with KVNO verified on all DCs
- Replication confirmed consistent across all Domain Controllers
- Previous attacker keys fully invalidated
- Zero authentication disruption during the entire process

## Key Lessons

Always reset krbtgt twice after any security incident. Wait minimum 10 hours between resets (default Kerberos ticket lifetime). Verify KVNO matches on ALL Domain Controllers after each reset. The password content doesn't matter — no one logs in as krbtgt. Generate a random 64-character password and clear it from memory immediately after use.

## References

- [MITRE ATT&CK T1558.001 - Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [Microsoft - Kerberos Golden Ticket Alerts](https://docs.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts)

