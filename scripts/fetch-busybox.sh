#!/bin/sh
# SPDX-License-Identifier: MIT
# Download a static busybox binary for rootfs construction.
#
# Usage: ./scripts/fetch-busybox.sh [ARCH]
#   ARCH defaults to x86_64.

set -eu

ARCH="${1:-x86_64}"
BUSYBOX_VERSION="${BUSYBOX_VERSION:-1.36.1}"
OUTDIR="deps"
OUTFILE="${OUTDIR}/busybox"

die()
{
    echo "error: $*" >&2
    exit 1
}

case "$ARCH" in
    x86_64)
        URL="https://busybox.net/downloads/binaries/${BUSYBOX_VERSION}-defconfig-multiarch-musl/busybox-x86_64"
        ;;
    aarch64)
        URL="https://busybox.net/downloads/binaries/${BUSYBOX_VERSION}-defconfig-multiarch-musl/busybox-aarch64"
        ;;
    *)
        die "Unsupported architecture: ${ARCH}"
        ;;
esac

mkdir -p "$OUTDIR"

if [ -x "$OUTFILE" ]; then
    echo "busybox already exists at ${OUTFILE}, skipping download."
    exit 0
fi

echo "Downloading busybox ${BUSYBOX_VERSION} (${ARCH})..."

if command -v curl > /dev/null 2>&1; then
    curl -fL -o "$OUTFILE" "$URL" || die "curl download failed"
elif command -v wget > /dev/null 2>&1; then
    wget -q -O "$OUTFILE" "$URL" || die "wget download failed"
else
    die "Neither curl nor wget found."
fi

chmod +x "$OUTFILE"
echo "OK: ${OUTFILE}"

# Verify it's actually a static binary.
if command -v file > /dev/null 2>&1; then
    file "$OUTFILE"
fi
