#!/usr/bin/env bash
# Snapshot gate: recompute per-algorithm SHA-256 digests from the Zig wrapper's
# output (sharded, full coverage, live progress) and compare against the frozen
# liboqs reference snapshot tests/snapshots/<LIBOQS_VERSION>.txt. A drift here
# means liboqs output changed since the snapshot was frozen (e.g. a version bump)
# — review, then re-run tools/freeze-snapshots.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LIBOQS_VERSION="$(tr -d ' \n' < LIBOQS_VERSION 2>/dev/null || echo 0.15.0)"
SNAP="tests/snapshots/${LIBOQS_VERSION}.txt"
[ -f "$SNAP" ] || { echo "missing snapshot $SNAP; run tools/freeze-snapshots.sh" >&2; exit 1; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Snapshot: Zig wrapper (zref)"
bash tools/run-shards.sh zref >"$tmp/zref.txt"
echo "==> Comparing against $SNAP ..."

python3 - "$tmp/zref.txt" "$SNAP" <<'PY'
import sys, hashlib, collections
fields = collections.defaultdict(dict)
with open(sys.argv[1]) as f:
    for line in f:
        p = line.split()
        if len(p) != 3:
            continue
        fields[p[0]][p[1]] = bytes.fromhex(p[2])
got = {}
for algo in fields:
    h = hashlib.sha256()
    for field in sorted(fields[algo]):
        h.update(fields[algo][field])
    got[algo] = h.hexdigest()
want = {}
with open(sys.argv[2]) as f:
    for line in f:
        p = line.split()
        if len(p) == 2:
            want[p[0]] = p[1]
bad = False
for algo in sorted(want):
    if algo not in got:
        print("    MISSING FROM ZREF: %s" % algo); bad = True
    elif got[algo] != want[algo]:
        print("    SNAPSHOT DRIFT:    %s" % algo); bad = True
extra = sorted(set(got) - set(want))
for algo in extra:
    print("    NEW ALGORITHM (not in snapshot): %s" % algo); bad = True
print("    checked %d algorithms against the frozen snapshot" % len(want))
if bad:
    print("SNAPSHOT FAILED")
    sys.exit(1)
print("SNAPSHOT OK: zref matches the frozen liboqs reference for all %d algorithms" % len(want))
PY
