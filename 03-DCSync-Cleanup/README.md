
# 03 - DCSync Permission Audit & Cleanup

## What is DCSync?

DCSync abuses Active Directory replication protocol. An account with `Replicating Directory Changes All` permission can impersonate a Domain Controller and request all password hashes — including krbtgt and Administrator — without touching LSASS or running malware on the DC.

**Why it's critical:**
- Dumps ALL password hashes silently
- Uses legitimate AD replication protocol — hard to detect
- Works remotely without DC access
