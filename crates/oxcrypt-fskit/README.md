# oxcrypt-fskit

Swift FFI bindings for Cryptomator vault FSKit integration.

Provides native filesystem integration on macOS 27+ via FSKit, using Swift-Rust FFI for seamless system-level encrypted vault mounting without kernel extensions.

## Requirements

- macOS 27 or later for public client mounting
- Xcode 27 SDK to build the host
- Host signing/provisioning with `com.apple.developer.fskit.mount`
- Extension signing/provisioning with `com.apple.developer.fskit.fsmodule`
- Swift FFI support

## License

Licensed under the Mozilla Public License 2.0.

## Experimental availability

The native FSKit backend is disabled by default. Developers must explicitly set
`OXCRYPT_EXPERIMENTAL_FSKIT=1` and provide a signed, enabled extension with its host
service running. A successful `pluginkit` exit with no matching enabled extension
is not availability. Registration alone does not establish that probing/mounting
works on a particular macOS release. This backend is not a production replacement
for the validated macFUSE path; the opt-in does not bypass macOS entitlements or
system approval requirements.

## Public mount path

On macOS 27+, the host creates an `FSPathURLResource` for the vault directory and
calls `FSClient.shared.mountSingleVolume`. FSKit creates the mount under `/Volumes`
and returns its actual path; the registry and XPC response use that path. The host
does not attach a trigger disk image or invoke `mount -F`. Older systems receive an
explicit unsupported-system error. Custom mount locations are not supported.

The host entitlement must also be accepted by its signing/provisioning profile;
adding it to a plist alone does not establish runtime permission. Public API
availability and compilation do not prove that an enabled, signed extension can
mount a vault. Keep the experimental opt-in until an end-to-end mount, read/write,
and unmount cycle has been verified on the target system.

Run `bash extension/test-mount-lifecycle.sh` for mount-state and failure-cleanup
tests using injected operations. These tests perform no real mounts or Keychain
changes.
