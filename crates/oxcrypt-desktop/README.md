# oxcrypt-desktop

Desktop GUI for managing Cryptomator vaults using [Dioxus](https://dioxuslabs.com/).

## Features

- Create, open, and manage Cryptomator vaults
- Mount/unmount vaults as native filesystems
- Multiple backend support:
  - **FUSE** (Linux/macOS) - requires `--features fuse`
  - **WebDAV** (cross-platform) - requires `--features webdav`
  - **NFS** (Linux/macOS) - requires `--features nfs`
  - **File Provider** (macOS 13+) - requires `--features fileprovider`
- Automatic backend selection based on platform capabilities
- System tray integration
- Real-time vault statistics

## Installation

```bash
# Build and install
cargo install --path crates/oxcrypt-desktop --features fuse

# Run
oxcrypt-desktop
```

## Building with Different Backends

```bash
# FUSE backend (Linux/macOS with macFUSE)
cargo build -p oxcrypt-desktop --features fuse --release

# WebDAV backend (cross-platform, no kernel extensions)
cargo build -p oxcrypt-desktop --features webdav --release

# Multiple backends
cargo build -p oxcrypt-desktop --features fuse,webdav,nfs --release
```

## Architecture

```
oxcrypt-desktop (Dioxus desktop app)
     │
     ├── MountManager
     │        │
     │        ├── FuseBackend (from oxcrypt-fuse)
     │        ├── WebDavBackend (from oxcrypt-webdav)
     │        ├── NfsBackend (from oxcrypt-nfs)
     │        └── FileProviderBackend (from oxcrypt-fileprovider)
     │
     ├── VaultState (app state)
     │
     └── Components (UI)
```

### Modules

| Module | Description |
|--------|-------------|
| `backend/` | Filesystem backend integration |
| `state/` | Application state and vault management |
| `components/` | Dioxus UI components |
| `dialogs/` | Modal dialogs (password, create vault, etc.) |
| `tray/` | System tray integration |
| `error/` | Error handling and display |

## Backend Selection

The GUI supports automatic or manual backend selection:

| Backend | Platform | Requirements |
|---------|----------|--------------|
| FUSE | Linux, macOS | libfuse/macFUSE installed |
| WebDAV | All | None (userspace server) |
| NFS | Linux, macOS | None (userspace server) |
| File Provider | macOS 13+ | Built-in system extension |

When using `BackendType::Auto`, the GUI will select the best available backend for your platform.

## Development

The project uses the Dioxus CLI (`dx`) for development. It's included in the devenv.

### Using dx (recommended)

```bash
# Hot-reload development server
dx serve -p oxcrypt-desktop

# With FUSE backend enabled
dx serve -p oxcrypt-desktop --features fuse

# With WebDAV backend enabled
dx serve -p oxcrypt-desktop --features webdav

# Production build
dx build -p oxcrypt-desktop --release

# Bundle for distribution (creates .app on macOS)
dx bundle -p oxcrypt-desktop --release
```

### Using cargo

```bash
# Run in development mode
cargo run -p oxcrypt-desktop --features fuse

# Run with WebDAV support
cargo run -p oxcrypt-desktop --features webdav

# Run tests
cargo test -p oxcrypt-desktop
```

## License

This project is licensed under the [Mozilla Public License 2.0](../../LICENSE).

## Linux startup acceptance

Build the Linux backends and run the GUI on an isolated X11 display:

```sh
cargo build --locked -p oxcrypt-desktop --no-default-features --features mimalloc,fuse,webdav,nfs
xvfb-run -a dbus-run-session -- python3 scripts/test-linux-desktop.py target/debug/oxcrypt-desktop
```

The test requires `xvfb`, `xauth`, `xdotool`, and a D-Bus session, in addition to
the GTK/WebKit libraries needed by the desktop app. It uses temporary configuration
directories, verifies a visible OxCrypt window belonging to the launched process,
and requires a clean exit after SIGINT. Missing prerequisites fail the test.
The `Linux Desktop Startup` workflow provides the same check on Ubuntu and can
also be started manually. Harness tests alone do not validate GTK or the real GUI.

## macOS Keychain

The unlock dialog can save a password in macOS Keychain after a successful mount.
Saving is opt-in. Use **Use saved password** to retrieve it, or **Forget saved
password** to remove it. A locked or unavailable keychain reports an error and
manual password entry remains available. Passwords are stored under
`org.oxcrypt.desktop.vault-password`, keyed by OxCrypt's vault ID, never in its JSON
configuration. Cryptomator's existing keychain items are not imported or changed.
Changing a vault password removes the old saved credential; the next successful
unlock can save the replacement. Removing a vault also removes its saved password.

To test the integration with an unlocked login keychain (uses a random test account):

```sh
cargo test -p oxcrypt-desktop --no-default-features --features fuse \
  --bin oxcrypt-desktop keychain::tests::keychain_roundtrip_update_and_forget -- --ignored
```
