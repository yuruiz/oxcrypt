This directory vendors nfsserve 0.10.2 (BSD-3-Clause) from the crates.io source archive.

Local changes:
- Pass the NFSv3 EXCLUSIVE CREATE verifier from XDR to a verifier-aware filesystem method.
- Dispatch GUARDED CREATE to an atomic filesystem method rather than separate lookup/create calls.
- New trait methods default to NFS3ERR_NOTSUPP so implementations cannot accidentally claim unsupported guarantees.
- Remove example manifest entries whose source files are not included in the published archive.

The CryptomatorNFS implementation supplies both operations and persists exclusive verifiers in file timestamps as permitted by RFC 1813 section 3.3.8. Protocol regressions are in crates/oxcrypt-nfs/tests/create_rpc.rs.

Request bounds:
- Limit total RPC records/XDR byte fields to 4 MiB and records to 128 fragments; bound u32 vectors by the same byte budget.
- Share 16 outstanding-request permits across connections, retained until response transmission, and limit an export to 64 connections.
- Pump input and output independently so backpressure does not prevent draining replies. Cancel socket pumps on disconnect; dispatched filesystem work completes under its retained permit.
- Bound READ/READDIR output requests to the advertised 1 MiB transfer size and reject undersized READDIR budgets without integer underflow.
