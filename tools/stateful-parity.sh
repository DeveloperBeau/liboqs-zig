#!/usr/bin/env bash
# Stateful signature parity gate: XMSS, XMSS^MT and LMS, compared between the raw
# C API (stfl_cref) and the typed Zig wrappers (stfl_zref). Each algorithm gets
# one keygen and one sign under the NIST-KAT seed, and the public key, the
# signature and the signature counts must match byte for byte. The harnesses are
# always built in ReleaseFast. The results stay outside the frozen snapshot.
#
# Only parameter sets with a total tree height of 16 or less run by default
# (29 of 70). Skipped names are printed. OQS_STATEFUL_ALL=1 runs all 70.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Few shards: each shard is a full keygen of one tree at a time.
N="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
[ "$N" -le 4 ] || N=4
export OQS_SHARDS="${OQS_SHARDS:-$N}"

echo "==> Stateful parity: which parameter sets run"
"$ROOT/zig-out/bin/stfl_cref" --list >"$tmp/cref.list"
"$ROOT/zig-out/bin/stfl_zref" --list >"$tmp/zref.list"
echo "==> Stateful parity: C reference (stfl_cref)"
bash tools/run-shards.sh stfl_cref >"$tmp/cref.txt"
echo "==> Stateful parity: typed Zig wrappers (stfl_zref)"
bash tools/run-shards.sh stfl_zref >"$tmp/zref.txt"
echo "==> Comparing ..."
"$ROOT/zig-out/bin/stfl_compare" "$tmp/cref.list" "$tmp/zref.list" "$tmp/cref.txt" "$tmp/zref.txt"
