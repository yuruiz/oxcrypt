This directory vendors nfsserve 0.10.2 (BSD-3-Clause) from the crates.io source archive.

Local changes:
- Pass the NFSv3 EXCLUSIVE CREATE verifier from XDR to a verifier-aware filesystem method.
- Dispatch GUARDED CREATE to an atomic filesystem method rather than separate lookup/create calls.
- New trait methods default to NFS3ERR_NOTSUPP so implementations cannot accidentally claim unsupported guarantees.
- Remove example manifest entries whose source files are not included in the published archive.

The CryptomatorNFS implementation supplies both operations and persists exclusive verifiers in file timestamps as permitted by RFC 1813 section 3.3.8. Protocol regressions are in crates/oxcrypt-nfs/tests/create_rpc.rs.
