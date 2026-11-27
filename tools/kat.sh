#!/usr/bin/env bash
# Known-answer gate: every enabled KEM and stateless signature that liboqs has a
# kats.json entry for is run through the Zig wrapper with the liboqs known-answer
# generators. The SHA-256 of the program text is compared with the digest in the
# kats.json of the pinned liboqs. The run is split over a few processes, because
# the liboqs random source is global. OQS_SHARDS sets the count (default 4).
# OQS_KAT_ALL=1 compares the `all` digests. OQS_KAT_FILTER=a,b covers only the
# named algorithms.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
N="${OQS_SHARDS:-4}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> Known answers: Zig wrapper against liboqs kats.json ($N shards)"
pids=()
for i in $(seq 0 $((N - 1))); do
    OQS_SHARD="$i" OQS_TOTAL="$N" "$ROOT/zig-out/bin/kat" run >"$tmp/shard.$i" &
    pids+=($!)
done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" -eq 0 ] || { echo "kat: a shard failed" >&2; exit 1; }
cat "$tmp"/shard.* >"$tmp/lines.txt"
"$ROOT/zig-out/bin/kat" summarize "$tmp/lines.txt"
