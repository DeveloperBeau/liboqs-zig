#!/usr/bin/env bash
# Behaviour gate: every enabled KEM and stateless signature scheme goes through
# the checks in harness/behaviour_checks.zig (correctness, rejection of bad
# input, hostile signatures and a short seeded fuzz pass). The harness runs in
# shards (tools/run-shards.sh) and the build mode is the one `zig build` chose.
# The merged output must name every algorithm the registry lists. A count that
# differs from the registry, or from the 41 KEMs and 221 signatures written out
# here from liboqs 0.16.0, fails the gate, so an algorithm cannot be skipped
# without notice. OQS_SHARDS overrides the shard count (default 4).
# OQS_BEHAVIOUR_SEED sets the base seed of the fuzz pass. OQS_BEHAVIOUR_ONLY (a
# comma separated list of names) runs just those, to try the harness. That run
# still checks every listed name ran, and ends with BEHAVIOUR FILTERED OK, never
# BEHAVIOUR OK, so it cannot pass for the full gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EXPECTED_KEMS=41
EXPECTED_SIGS=221
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export OQS_SHARDS="${OQS_SHARDS:-4}"
start=$SECONDS
echo "==> Behaviour: every enabled KEM and signature"
bash tools/run-shards.sh behaviour >"$tmp/out.txt"

kems=$(grep -c '^KEM ' "$tmp/out.txt" || true)
sigs=$(grep -c '^SIG ' "$tmp/out.txt" || true)
ukems=$(grep '^KEM ' "$tmp/out.txt" | sort -u | wc -l)
usigs=$(grep '^SIG ' "$tmp/out.txt" | sort -u | wc -l)
reg=$(grep '^REGISTRY ' "$tmp/out.txt" | sort -u)
nreg=$(printf '%s\n' "$reg" | wc -l)
if [ "$nreg" -ne 1 ]; then
    echo "BEHAVIOUR FAILED: shards disagree on the registry counts: $reg"
    exit 1
fi
rkems=$(printf '%s\n' "$reg" | awk '{print $2}')
rsigs=$(printf '%s\n' "$reg" | awk '{print $3}')
filtered=no
if printf '%s\n' "$reg" | grep -q FILTERED; then filtered=yes; fi
echo "    ran $kems KEMs ($ukems distinct) and $sigs signatures ($usigs distinct), registry $rkems and $rsigs"
if [ "$kems" -ne "$ukems" ] || [ "$sigs" -ne "$usigs" ] ||
    [ "$ukems" -ne "$rkems" ] || [ "$usigs" -ne "$rsigs" ] ||
    { [ "$filtered" = no ] && { [ "$ukems" -ne "$EXPECTED_KEMS" ] || [ "$usigs" -ne "$EXPECTED_SIGS" ]; }; }; then
    echo "BEHAVIOUR FAILED: the algorithms that ran differ from the registry or from $EXPECTED_KEMS KEMs and $EXPECTED_SIGS signatures"
    exit 1
fi
if [ "$filtered" = yes ]; then
    echo "BEHAVIOUR FILTERED OK: $ukems KEMs and $usigs signatures, not the full set"
    exit 0
fi
echo "BEHAVIOUR OK: $ukems KEMs and $usigs signatures ($((SECONDS - start)) s)"
