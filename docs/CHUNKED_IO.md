# Chunked mount I/O

FUSE, NFS and WebDAV file handles use authenticated 32 KiB chunks. Opening an existing file authenticates its header; content authentication happens when the affected chunks are accessed. Partial writes read only the intersecting old chunks; complete chunk overwrites skip old decryption. One dirty plaintext chunk is buffered per editor, separately from caller-owned read/write buffers.

Edits keep the original content key and header. Every changed chunk receives a fresh random nonce. Both SIV_GCM and SIV_CTRMAC are supported. Unmodified ciphertext is preserved byte-for-byte.

Ciphertext stages use APFS cloning or Linux reflinks where available, with bounded-memory ciphertext copying as a fallback. Commit synchronizes and atomically publishes a complete file; failed commits retain the stage. An unexpected replacement or modification of the original ciphertext causes a conflict error instead of silently overwriting a newer version. All FUSE handles of an inode share one editor, including readers and unlinked or overwritten open files.

NFS acknowledges each successful WRITE only after commit, matching nfsserve's FILE_SYNC reply. WebDAV streams GET ranges and keeps PUT stages until flush succeeds. WebDAV COPY clones/copies ciphertext without re-encryption; copied content is authenticated when read. Failed FUSE closes can archive staged ciphertext using the recovery workflow.

The fixed authentication chunk size imposes a minimum amplification for small edits. Extending a file across a gap must create authenticated zero chunks. A filesystem without clone support still copies untouched ciphertext for atomic publication. Cloud providers may upload whole files even when local I/O uses COW. File Provider/FSKit and CLI import/export paths have separate I/O lifecycles; this change does not certify those native backends for production use.

Native macOS attribute operations use AppleDouble sidecars capped at 64 MiB and have a separate metadata I/O path. The one-chunk plaintext bound above applies to ordinary mounted file handles, not to an entire attribute request.
