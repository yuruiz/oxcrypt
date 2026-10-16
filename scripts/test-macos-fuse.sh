#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
    echo "This test requires macOS with an enabled macFUSE kernel extension." >&2
    exit 1
fi
if [[ ! -d /Library/Filesystems/macfuse.fs ]]; then
    echo "macFUSE is not installed; refusing to report skipped mounts as passing." >&2
    exit 1
fi
export OXCRYPT_REQUIRE_FUSE=1
cargo nextest run --locked --profile macos-fuse \
    -p oxcrypt-fuse --no-default-features --features fuse-tests \
    --test macos_mount --test macos_xattr --no-tests fail
