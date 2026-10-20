# Debugging & Profiling

Specialized debugging tools and techniques for development.

## Code Coverage

Uses `cargo-llvm-cov` (installed automatically by devenv):

```bash
cargo llvm-cov nextest --workspace           # Text summary
cargo llvm-cov nextest --workspace --html    # HTML report (target/llvm-cov/html/)
cargo llvm-cov nextest --workspace --open    # Open HTML report
cargo llvm-cov nextest --workspace --lcov --output-path lcov.info  # LCOV format
```

## Timing Leak Detection

Uses dudect statistical methodology to detect timing side-channels in cryptographic operations.

```bash
# Run all timing tests
cargo bench -p oxcrypt-core --bench timing_leaks

# Run specific test
cargo bench -p oxcrypt-core --bench timing_leaks -- --filter key_unwrap

# Continuous mode (runs until Ctrl+C)
cargo bench -p oxcrypt-core --bench timing_leaks -- --continuous key_unwrap
```

**Interpretation**: t-value < 4.5 = PASS (no timing leak), t-value > 4.5 = FAIL (potential leak)

**Tests include**:
- RFC 3394 key unwrap integrity check
- HMAC verification (via ring)
- AES-GCM file header/content decryption
- AES-SIV filename decryption

## Async Debugging with tokio-console

All mount backends (`oxcrypt-fuse`, `oxcrypt-fskit`, `oxcrypt-webdav`, `oxcrypt-nfs`) and the GUI support [tokio-console](https://github.com/tokio-rs/console) for real-time async task introspection.

```bash
# Build a specific backend with console support
cargo build -p oxcrypt-fuse --features tokio-console
cargo build -p oxcrypt-fskit --features tokio-console
cargo build -p oxcrypt-webdav --features tokio-console
cargo build -p oxcrypt-nfs --features tokio-console

# Or build CLI/GUI with console support (forwards to all enabled backends)
cargo build -p oxcrypt --features fuse,tokio-console
cargo build -p oxcrypt-desktop --features fuse,tokio-console

# Terminal 1: Run the mount or GUI
./target/debug/oxmount ~/vault /mnt/point
# or
./target/debug/oxvault

# Terminal 2: Connect console
tokio-console http://127.0.0.1:6669  # CLI tools (oxmount, oxcrypt, etc.)
tokio-console http://127.0.0.1:6670  # GUI (oxvault)
```

**Port Configuration**:
- CLI tools use port **6669** by default
- GUI uses port **6670** by default (to avoid conflicts)
- Override with `TOKIO_CONSOLE_PORT=<port>` environment variable
- If port is in use, the app will log a warning and continue without console instrumentation

**Requirements** (already configured in this repo):
- `tokio_unstable` cfg flag: Set via `.cargo/config.toml`
- `tokio/tracing` feature: Enabled by the `tokio-console` feature flag
- Per-layer filtering: The console layer has its own built-in filter; don't apply a global `EnvFilter` that might block tokio instrumentation events

**What you can observe**:
- Active async tasks and their states
- Task poll times and waker counts
- Resource contention (mutexes, semaphores)
- `spawn_blocking` threads for CPU-bound crypto (vault decryption operations)
- `block_on` calls from FUSE operations (filesystem.rs)

**Verification via gRPC** (if tokio-console TUI isn't available):

```bash
# Install grpcurl
brew install grpcurl

# Query the console endpoint directly
cd ~/.cargo/registry/src/*/console-api-*/proto
timeout 2 grpcurl -plaintext -import-path . -proto instrument.proto \
    127.0.0.1:6669 rs.tokio.console.instrument.Instrument/WatchUpdates \
    | jq '.taskUpdate.newTasks[]? | "\(.location.file):(\(.location.line))"'
```

**Troubleshooting**:
- **No tasks visible**: Trigger some vault operations (read files, list directories). Idle vaults won't show activity.
- **Port in use**: Another instance may be running. Check with `lsof -i :6669` and kill the old process.
- **grpc-status: 12**: The gRPC server is running but you sent an invalid request. Use proper protobuf encoding.
- **Console shows empty**: Ensure `tokio_unstable` cfg is set in `.cargo/config.toml` (already configured in this repo).

The `tokio-console` feature is opt-in and adds zero overhead to normal builds.

## Crash Debugging with rust-lldb

When the binary crashes (segfault, abort, stack overflow), use `rust-lldb` to get backtraces with proper Rust symbol demangling.

### Getting a Backtrace from a Crash

```bash
# Build with debug symbols (release with debug info is fine)
cargo build -p oxcrypt-bench --release

# Run under rust-lldb with crash handler
# The -k flag runs commands WHEN process stops (not before!)
rust-lldb \
    -o "run" \
    -k "thread backtrace all" \
    -k "quit" \
    -- ./target/release/oxbench test_vault fuse --password PASSWORD --suite workloads
```

**Key flags**:
- `-o "run"`: Start execution immediately
- `-k "command"`: Run command when process **stops** (crash, signal, breakpoint)
- `-- args`: Arguments passed to the target binary

**Common `-k` commands**:
- `thread backtrace all`: Show all thread stacks (useful for hangs/deadlocks)
- `bt`: Show current thread backtrace only
- `register read`: Dump CPU registers
- `frame variable`: Show local variables in current frame

### Interactive Debugging

```bash
# Start interactively
rust-lldb ./target/release/oxbench

# In lldb prompt:
(lldb) run test_vault fuse --password PASSWORD --suite workloads
# ... wait for crash ...
(lldb) bt          # current thread backtrace
(lldb) bt all      # all threads
(lldb) frame select 5  # examine frame #5
(lldb) frame variable  # show locals
(lldb) expression someVar  # evaluate expression
```

### macOS Crash Reports

Crashes also generate `.ips` files in `~/Library/Logs/DiagnosticReports/`:

```bash
# Find recent crash reports
ls -lt ~/Library/Logs/DiagnosticReports/*.ips | head -5

# Read crash report (JSON format with symbolicated backtrace)
cat ~/Library/Logs/DiagnosticReports/oxcrypt-2024-*.ips | jq .

# Extract the thread backtrace
cat ~/Library/Logs/DiagnosticReports/oxcrypt-*.ips | jq '.threads[0].frames'
```

The `.ips` files contain:
- Exception type and signal
- Register state at crash
- Thread backtraces with symbolication
- Loaded images and their UUIDs

### Stack Overflow Debugging

Stack overflows appear as `EXC_BAD_ACCESS` with address near stack limit or as `SIGABRT` with malloc failure. The backtrace will show extreme recursion:

```
frame #0: __pthread_kill + 8
frame #1: abort + 124
frame #2: _rust_panic_cleanup + 96
...
frame #3707: std::sys::fs::unix::remove_dir_impl::remove_dir_all_recursive
```

Deep recursion (hundreds of frames) indicates infinite loop or unbounded recursion.

## FSKit Debugging (macOS 15.4+)

FSKit is Apple's user-space filesystem framework. Debugging requires understanding the multi-process architecture: your app → XPC → fskitd → FSKit extension.

### Viewing fskitd Logs

```bash
# Real-time fskitd logs
log stream --predicate 'subsystem == "com.apple.FSKit"' --level debug

# Historical logs with all FSKit-related processes
log show --predicate 'subsystem == "com.apple.FSKit" OR process == "fskitd" OR process == "mount"' --last 5m

# Save to file for analysis
log show --predicate 'subsystem == "com.apple.FSKit"' --last 10m > /tmp/fskit.log
```

### Extension Registration

```bash
# List registered FSKit extensions (+ prefix = enabled)
pluginkit -m -p com.apple.fskit.fsmodule

# Force extension refresh
pluginkit -e use -i com.agucova.oxcrypt.desktop.fsextension
```

### Host App XPC Service

```bash
# Start host app in XPC mode (for FSKit support)
~/Applications/OxVaultFS.app/Contents/MacOS/OxVaultFS --xpc 2>/tmp/oxcrypt-hostapp.err &

# Check XPC service is running
ps aux | grep -i "oxvault.*xpc"

# Tail host app logs
tail -f /tmp/oxcrypt-hostapp.err
```

### Extension Debug Logging

The extension writes debug logs to `/tmp/oxvault_fskit_debug.log`:

```bash
# Watch extension logs (if running)
tail -f /tmp/oxvault_fskit_debug.log

# Check if extension was ever loaded
cat /tmp/oxvault_fskit_debug.log
```

### Common fskitd Log Patterns

**Successful client connection:**
```
Hello FSClient! entitlement yes
About to get current agent for 501
Probing with <FSResource>...
```

**Missing entitlements (third-party mount command):**
```
Hello FSClient! entitlement no
About to get current agent for 501
[connection invalidated 10s later with no probe]
```

**Root user rejection:**
```
Attempt to start non-Apple extension <private> on behalf of root
```

## FSKit Public Mounting (macOS 27+)

[Apple's public `FSClient.mountSingleVolume` API](https://developer.apple.com/documentation/fskit/fsclient/mountsinglevolume(resource:bundleid:options:completionhandler:))
is available starting in macOS 27.0. It requires the host's
`com.apple.developer.fskit.mount` entitlement and a visible, enabled extension.
The extension still needs `com.apple.developer.fskit.fsmodule`. Entitlement files
must match the signed app and its provisioning profile.

OxCrypt passes an `FSPathURLResource` for the vault directory. FSKit loads and
activates the volume, creates its mountpoint under `/Volumes`, and returns the
actual mount URL. The host registers that returned path only after success. A
failed mount removes the pending reservation and restores the credential state
from before that attempt (or deletes a newly created credential); cleanup failures
are reported. Concurrent requests for
the same vault are rejected before changing its credential. System unmount commands
have a 15-second timeout each. A failed unmount retains registry and credentials for
retry; credential cleanup after successful detachment can be retried independently.

The host no longer uses trigger disk images or `/sbin/mount -F` for its mount
requests. macOS versions below 27 receive an explicit unsupported-system error.
The earlier macOS 15.4/26.0.1 `entitlement no` observations describe the command and
private-API routes tested on those releases; they do not establish that current
third-party public mounting is unavailable.

The backend remains disabled unless `OXCRYPT_EXPERIMENTAL_FSKIT=1` is set. Build
with the Xcode 27 SDK, verify the signed host has the mount entitlement, and enable
the extension through System Settings before an intentional runtime test. Neither
a successful build nor extension registration proves that mounting works. An
end-to-end signed mount, read/write, and unmount cycle remains a separate required
validation. Use FUSE, WebDAV, or NFS when this environment is not available.

`bash crates/oxcrypt-fskit/extension/test-mount-lifecycle.sh` checks reservations,
actual-path registration, duplicate requests, and failure cleanup without mounting
or accessing Keychain.
