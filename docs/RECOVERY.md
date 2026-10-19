# Recovering failed write-back

If a final write-back fails, OxCrypt retains the write handle until either the vault commit succeeds or an encrypted emergency copy is saved. Recovery copies use the vault master key; neither their contents nor their intended filename is stored in plaintext.

WebDAV shutdown stops accepting connections and waits for active requests. It retries completed uploads whose write-back failed. Uploads interrupted before their final flush are archived without replacing the original file. Shutdown reports recovery locations and unresolved errors; API callers can retry `server.stop().await` while retaining the server. Await explicit shutdown before dropping its Tokio runtime, since asynchronous cleanup requested by `Drop` requires that runtime to remain alive.

Copies live in persistent per-user storage: `~/Library/Application Support/oxcrypt/recovery` on macOS, `$XDG_STATE_HOME/oxcrypt/recovery` (default `~/.local/state/oxcrypt/recovery`) on Linux, or `%LOCALAPPDATA%/oxcrypt/recovery` on Windows. The mount log and unmount error include the exact recovery directory.

Export a copy using the original vault and its password:

```sh
oxcrypt recover /path/to/vault /path/to/recovery-directory /path/to/new-output-file
```

The output must not exist. Export authenticates the complete copy before publishing the output and retains the encrypted recovery directory. Compare the recovered file with the current vault file before deciding which version to keep, then explicitly remove the recovery directory when no longer needed.

If both the vault storage and recovery storage fail, pending bytes remain in memory for another attempt at teardown. Unmount reports unresolved writes; no software can persist those bytes while every available storage destination is failing. Process termination can lose data that never reached either destination.
