#!/usr/bin/env bash
# Build the macOS Touch ID helper binary into bin/agent-vault-presence.
#
# Run on macOS with Xcode Command Line Tools installed (provides `swiftc`).
# Output:  bin/agent-vault-presence  (Mach-O, universal2: arm64 + x86_64)
#
# This script is platform-aware: on non-macOS hosts it prints a warning and
# exits 0 (so `npm run build:native` is safe to invoke during cross-platform
# CI without polluting the build with hard failures). Production releases must
# always run this on a macOS runner — see .github/workflows/publish.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="${REPO_ROOT}/native/macos/agent-vault-presence.swift"
OUT_DIR="${REPO_ROOT}/bin"
OUT="${OUT_DIR}/agent-vault-presence"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "⚠  build:native skipped — not on macOS ($(uname -s))." >&2
    echo "   The Touch ID gate requires the helper at ${OUT}, which is a" >&2
    echo "   macOS Mach-O binary. Building on this host produces nothing." >&2
    exit 0
fi

if ! command -v swiftc >/dev/null 2>&1; then
    echo "✗  swiftc not found. Install Xcode Command Line Tools:" >&2
    echo "      xcode-select --install" >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"

# Universal binary: arm64 (Apple Silicon) + x86_64 (Intel Macs).
# -O for release optimization, -framework LocalAuthentication links the SEP API.
swiftc \
    -O \
    -target arm64-apple-macos11 \
    -framework LocalAuthentication \
    -framework Foundation \
    "${SRC}" \
    -o "${OUT}.arm64"

swiftc \
    -O \
    -target x86_64-apple-macos11 \
    -framework LocalAuthentication \
    -framework Foundation \
    "${SRC}" \
    -o "${OUT}.x86_64"

lipo -create -output "${OUT}" "${OUT}.arm64" "${OUT}.x86_64"
rm -f "${OUT}.arm64" "${OUT}.x86_64"

chmod +x "${OUT}"

echo "✓ Built ${OUT}"
file "${OUT}"
