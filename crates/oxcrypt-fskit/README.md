# oxcrypt-fskit

Swift FFI bindings for Cryptomator vault FSKit integration.

Provides native filesystem integration on macOS 15.4+ via FSKit, using Swift-Rust FFI for seamless system-level encrypted vault mounting without kernel extensions.

## Requirements

- macOS 15.4 or later
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
