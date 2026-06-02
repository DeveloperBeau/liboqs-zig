#!/usr/bin/env bash
# Run a parity harness (cref|zref) sharded across CPUs and print the merged full
# output on stdout. Each shard handles a disjoint subset (combined-index % total
# == shard); per-op KAT re-seeding makes the merge identical to a single full-set
# run. This preserves complete coverage while cutting wall time to roughly the
# slowest shard. Per-algorithm progress streams on stderr (inherited from the
# shards) so a long run visibly advances. Usage: run-shards.sh <cref|zref>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bin="$1"
N="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "  ($bin: $N shards, full coverage)" >&2
pids=()
for i in $(seq 0 $((N - 1))); do
    # stdout (the data) -> per-shard file; stderr (progress) -> inherited terminal.
    OQS_SHARD="$i" OQS_TOTAL="$N" "$ROOT/zig-out/bin/$bin" >"$tmp/shard.$i" &
    pids+=($!)
done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" -eq 0 ] || { echo "run-shards: a $bin shard failed" >&2; exit 1; }
cat "$tmp"/shard.*
