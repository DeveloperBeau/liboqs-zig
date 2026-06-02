#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$ROOT/LIBOQS_VERSION")"
DEST="$ROOT/vendor/liboqs"

rm -rf "$DEST/src"
# Preserve a hand-maintained oqsconfig.h across re-vendoring.
if [ -f "$DEST/include/oqs/oqsconfig.h" ]; then
  cp "$DEST/include/oqs/oqsconfig.h" /tmp/oqsconfig.h.bak
fi
rm -rf "$DEST/include/oqs"
mkdir -p "$DEST/src" "$DEST/include/oqs"

TMP="$(mktemp -d)"
curl -sL "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$VERSION.tar.gz" \
  | tar -xz -C "$TMP"
SRC="$TMP/liboqs-$VERSION/src"

# Common runtime (rand incl. NIST-KAT, aes, sha2, sha3) + dispatcher headers.
cp -R "$SRC/common" "$DEST/src/"

# KEM + SIG dispatchers and the three skeleton algorithms.
mkdir -p "$DEST/src/kem" "$DEST/src/sig"
cp "$SRC/kem/kem.c" "$SRC/kem/kem.h" "$DEST/src/kem/"
cp "$SRC/sig/sig.c" "$SRC/sig/sig.h" "$DEST/src/sig/"
cp -R "$SRC/kem/ml_kem" "$DEST/src/kem/"
cp -R "$SRC/sig/ml_dsa" "$DEST/src/sig/"
cp -R "$SRC/sig/mayo"   "$DEST/src/sig/"

# Public headers.
cp "$SRC/oqs.h" "$DEST/include/oqs/"
for h in common/common.h common/rand/rand.h common/rand/rand_nist.h \
         common/aes/aes_ops.h common/aes/aes.h \
         common/sha2/sha2_ops.h common/sha2/sha2.h \
         common/sha3/sha3_ops.h common/sha3/sha3.h \
         common/sha3/sha3x4_ops.h common/sha3/sha3x4.h \
         kem/kem.h sig/sig.h \
         kem/ml_kem/kem_ml_kem.h sig/ml_dsa/sig_ml_dsa.h sig/mayo/sig_mayo.h; do
  cp "$SRC/$h" "$DEST/include/oqs/"
done

rm -rf "$TMP"
[ -f /tmp/oqsconfig.h.bak ] && cp /tmp/oqsconfig.h.bak "$DEST/include/oqs/oqsconfig.h" && rm /tmp/oqsconfig.h.bak
echo "Vendored minimal liboqs $VERSION into $DEST"
