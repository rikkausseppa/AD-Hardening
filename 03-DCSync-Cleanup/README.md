
# 03 - DCSync Permission Audit & Cleanup

## What is DCSync?

DCSync abuses Active Directory replication protocol. An account with `Replicating Directory Changes All` permission can impersonate a Domain Controller and request all password hashes — including krbtgt and Administrator — without touching LSASS or running malware on the DC.

**Why it's critical:**
- Dumps ALL password hashes silently
- Uses legitimate AD replication protocol — hard to detect
- Works remotely without DC access
- ## What I Found

Domain root ACL contained orphaned DCSync ACEs — permissions assigned to accounts that no longer exist in AD. Accumulated over years from software installations never properly cleaned up.

## Result

- 32 orphaned DCSync ACEs removed
- Only legitimate system accounts retain DCSync permissions
- Zero functionality impacted

## Key Lesson

Every tool installation adds DCSync ACEs. Uninstallation never removes them. Audit DCSync permissions quarterly and implement cleanup checklist for every software removal.

## References
- [MITRE ATT&CK T1003.006 - DCSync](https://attack.mitre.org/techniques/T1003/006/)
