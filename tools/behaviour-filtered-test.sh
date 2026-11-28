#!/usr/bin/env bash
# Test of tools/behaviour.sh itself, run by `zig build test`. A run limited to
# four fast algorithms (two KEMs, two signatures) must exit 0, report that it
# ran all four, and end with BEHAVIOUR FILTERED OK. It must never print the
# BEHAVIOUR OK line of a full run, so a filtered run cannot pass for the gate.
# It needs zig-out/bin/behaviour, which the build step installs first.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

OQS_SHARDS=2 OQS_BEHAVIOUR_ONLY="Kyber512,ML-KEM-512,ML-DSA-44,Falcon-512" bash tools/behaviour.sh >"$out" 2>/dev/null
rc=$?
cat "$out"

fail() {
    echo "BEHAVIOUR FILTERED TEST FAILED: $1"
    exit 1
}
[ "$rc" -eq 0 ] || fail "the filtered run exited $rc, not 0"
grep -q 'BEHAVIOUR FILTERED OK' "$out" || fail "no BEHAVIOUR FILTERED OK line"
if grep -q 'BEHAVIOUR OK:' "$out"; then fail "a filtered run printed the BEHAVIOUR OK line of a full run"; fi
grep -q 'ran 2 KEMs (2 distinct) and 2 signatures (2 distinct), registry 2 and 2' "$out" || fail "the run did not cover all four algorithms"
echo "BEHAVIOUR FILTERED TEST OK"
