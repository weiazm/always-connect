#!/bin/bash
# Bundles the pinned official Hysteria2 client for AlwaysConnect (DESIGN.md §七十).
#
#   scripts/bundle-hysteria.sh <out-dir> [sign-identity]
#
# Downloads the pinned HyNetworks/hysteria release binary for macOS, verifies
# its exact SHA-256 checksum, signs it with the App's codesigning identity,
# and writes <out-dir>/bin/hysteria, <out-dir>/VERSIONS, and
# <out-dir>/licenses/hysteria/LICENSE.md.
#
# Caches the verified download under .local-build/hysteria-cache (or
# HYSTERIA_CACHE_DIR) so local rebuilds do not re-download.
# Users' Macs never download this at install time (install.sh has no new sources).
set -euo pipefail

OUT=${1:?out dir}
IDENTITY=${2:--}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ARCH=$(uname -m)

HYSTERIA_TAG="app/v2.14.0"
case "$ARCH" in
    arm64)
        ASSET="hysteria-darwin-arm64"
        SHA256="c68aa6677f15e572f997b346bcdf193b45a9dc9071b7e9555efffc8694c5ec05"
        ;;
    x86_64)
        ASSET="hysteria-darwin-amd64"
        SHA256="37a3ef3649b5a8fd24799b285d413b1d38afa71e2c4c1d564efe3c3b65880efe"
        ;;
    *)
        echo "unsupported macOS architecture for hysteria: $ARCH" >&2
        exit 2
        ;;
esac

URL="https://github.com/HyNetworks/hysteria/releases/download/${HYSTERIA_TAG}/${ASSET}"
CACHE_DIR=${HYSTERIA_CACHE_DIR:-"$ROOT/.local-build/hysteria-cache"}
CACHED="$CACHE_DIR/${ASSET}-${HYSTERIA_TAG#app/}"

verify_sha256() {
    local file=$1
    local got
    got=$(shasum -a 256 "$file" | awk '{print tolower($1)}')
    [ "$got" = "$SHA256" ]
}

mkdir -p "$CACHE_DIR"
if [ -f "$CACHED" ] && verify_sha256 "$CACHED"; then
    SRC="$CACHED"
else
    TMP=$(mktemp "$CACHE_DIR/.download.XXXXXX")
    trap 'rm -f "$TMP"' EXIT
    echo "downloading $ASSET ($HYSTERIA_TAG)..."
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 -o "$TMP" "$URL"
    if ! verify_sha256 "$TMP"; then
        echo "SHA-256 mismatch for $ASSET ($HYSTERIA_TAG)" >&2
        exit 1
    fi
    mv -f "$TMP" "$CACHED"
    trap - EXIT
    SRC="$CACHED"
fi

rm -rf "$OUT"
mkdir -p "$OUT/bin" "$OUT/licenses/hysteria"
cp "$SRC" "$OUT/bin/hysteria"
chmod 755 "$OUT/bin/hysteria"
codesign --force --sign "$IDENTITY" --timestamp=none "$OUT/bin/hysteria" >/dev/null 2>&1
codesign --verify --strict "$OUT/bin/hysteria"

cp "$ROOT/third_party/licenses/hysteria-MIT.txt" "$OUT/licenses/hysteria/LICENSE.md"
cat > "$OUT/VERSIONS" <<EOF
hysteria ${HYSTERIA_TAG}
asset ${ASSET}
url ${URL}
sha256 ${SHA256}
EOF

echo "bundled hysteria ${HYSTERIA_TAG} (${ASSET}) into $OUT ($(du -sh "$OUT" | cut -f1))"
