#!/usr/bin/env bash
# Bounded soak: publish N entries into a throwaway node and report the rate
# plus a full verify. Usage: ./deploy/drills/soak.sh [N] (default 500)
set -euo pipefail
Datu=${DATU:-./target/release/datu}
N=${1:-500}
Work=$(mktemp -d /tmp/datu-soak.XXXXXX)
trap 'rm -rf "$Work"' EXIT

"$Datu" --data-dir "$Work/node" init >/dev/null
start=$(python3 -c 'import time;print(time.time())')
for i in $(seq 1 "$N"); do
  "$Datu" --data-dir "$Work/node" publish --ns gov.soak \
    --payload "{\"n\":$i,\"pad\":\"$(printf 'x%.0s' $(seq 1 40))\"}" >/dev/null
done
end=$(python3 -c 'import time;print(time.time())')
entries=$("$Datu" --data-dir "$Work/node" status | awk '/^entries:/{print $2}')
rate=$(python3 -c "print(f'{($end-$start):.1f}s, {($N)/($end-$start):.0f} entries/s')")
size=$(du -sh "$Work/node/node.db" | awk '{print $1}')
echo "published $N into a fresh node: $rate, node.db $size, total entries $entries"
"$Datu" --data-dir "$Work/node" verify | tail -2
[ "$entries" = "$((N+1))" ] || { echo "FAIL: expected $((N+1)) entries (genesis + published)"; exit 1; }
echo "PASS: soak batch stored and verified"
