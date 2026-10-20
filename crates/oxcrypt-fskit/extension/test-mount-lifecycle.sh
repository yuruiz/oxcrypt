#!/bin/bash
set -euo pipefail
test_root="$(cd "$(dirname "$0")" && pwd)"
test_build="$(mktemp -d "${TMPDIR:-/tmp}/oxcrypt-fskit-tests.XXXXXX")"
trap 'rm -rf "$test_build"' EXIT

# Compile the production registry and protocol; no FSKit mount or Keychain calls.
env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}" \
  /usr/bin/xcrun swiftc -swift-version 5 \
  "$test_root/Shared/OxVaultServiceProtocol.swift" \
  "$test_root/Shared/MountRegistry.swift" \
  "$test_root/Shared/KeychainHelper.swift" \
  "$test_root/Shared/VaultCredentialTransaction.swift" \
  "$test_root/HostApp/DiskutilUnmount.swift" \
  "$test_root/Tests/MountRegistryTests.swift" \
  -o "$test_build/mount-lifecycle"
"$test_build/mount-lifecycle"
