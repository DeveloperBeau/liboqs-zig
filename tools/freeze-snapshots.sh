#!/usr/bin/env bash
# Freeze per-algorithm SHA-256 digests of the liboqs C reference output into
# tests/snapshots/<LIBOQS_VERSION>.txt. These are liboqs reference snapshots
# (drift tripwires for a version bump), NOT NIST KATs. Re-run on a liboqs bump.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LIBOQS_VERSION="$(tr -d ' \n' < LIBOQS_VERSION 2>/dev/null || echo 0.15.0)"
zig build >/dev/null
OUT="tests/snapshots/${LIBOQS_VERSION}.txt"
mkdir -p "$(dirname "$OUT")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "==> Freezing snapshot from C reference (cref), full coverage" >&2
bash tools/run-shards.sh cref >"$tmp/cref.txt"
# Pass the data file as argv. Python reads its script from the heredoc on stdin,
# so the cref output cannot also be piped there. Open the file instead.
python3 - "$OUT" "$tmp/cref.txt" <<'PY'
import sys, hashlib, collections
out_path, data_path = sys.argv[1], sys.argv[2]
fields = collections.defaultdict(dict)
with open(data_path) as fh:
    for line in fh:
        parts = line.split()
        if len(parts) != 3:
            continue
        algo, field, hexv = parts
        fields[algo][field] = bytes.fromhex(hexv)
lines = []
for algo in sorted(fields):
    h = hashlib.sha256()
    for field in sorted(fields[algo]):
        h.update(fields[algo][field])
    lines.append("%s %s" % (algo, h.hexdigest()))
with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
sys.stderr.write("wrote %d snapshot digests to %s\n" % (len(lines), out_path))
PY
echo "Done: $OUT" >&2
