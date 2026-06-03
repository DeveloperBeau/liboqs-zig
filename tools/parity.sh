#!/usr/bin/env bash
# Full-coverage parity gate: every enabled algorithm, every operation, compared
# byte-for-byte between the C reference (cref) and the typed Zig wrapper (zref).
# Both runs are sharded across CPUs (tools/run-shards.sh) with live per-algorithm
# progress on stderr. The comparison is order-independent and bidirectional, so a
# dropped or extra algorithm/field on either side fails the gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Parity: C reference (cref)"
bash tools/run-shards.sh cref >"$tmp/cref.txt"
echo "==> Parity: Zig wrapper (zref)"
bash tools/run-shards.sh zref >"$tmp/zref.txt"
echo "==> Comparing ..."

python3 - "$tmp/cref.txt" "$tmp/zref.txt" <<'PY'
import sys
def load(path):
    m = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) != 3:
                continue
            m[(p[0], p[1])] = p[2]
    return m
c = load(sys.argv[1]); z = load(sys.argv[2])
ck, zk = set(c), set(z)
miss_z = sorted(ck - zk)   # in cref, absent from zref
miss_c = sorted(zk - ck)   # in zref, absent from cref
diff = sorted(k for k in (ck & zk) if c[k] != z[k])
algos = sorted({k[0] for k in ck | zk})
print("    %d algorithms, %d (algorithm, field) pairs" % (len(algos), len(ck | zk)))
bad = False
for k in miss_z: print("    MISSING IN ZREF: %s %s" % k); bad = True
for k in miss_c: print("    MISSING IN CREF: %s %s" % k); bad = True
for k in diff:   print("    VALUE DIFF:      %s %s" % k); bad = True
if bad:
    print("PARITY FAILED")
    sys.exit(1)
print("PARITY OK: cref and zref are byte-identical across all %d algorithms" % len(algos))
PY
