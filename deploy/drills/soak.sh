#!/usr/bin/env bash
# Bounded soak: publish N entries into a throwaway node, report the rate and
# size, a full verify, and the time a fresh observer needs to pull the whole
# history (sync lag at target volume). Usage: ./deploy/drills/soak.sh [N]
set -euo pipefail
Datu=${DATU:-./target/release/datu}
N=${1:-500}
Port=${PORT:-7599}
Work=$(mktemp -d /tmp/datu-soak.XXXXXX)
PIDS=()
cleanup() { kill -9 ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null || true; rm -rf "$Work"; }
trap cleanup EXIT

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

# Sync lag: a fresh observer pulls the whole history over the native p2p
# transport; that wall time is the catch-up cost a new node (or a node
# returning from downtime) pays at this volume.
echo "sync lag: fresh observer pulls $entries entries from the publisher"
"$Datu" --data-dir "$Work/node" node --addr "127.0.0.1:$Port" --every 0 \
  >"$Work/serve.log" 2>&1 & node_pid=$!; PIDS+=("$node_pid")
sleep 1
"$Datu" --data-dir "$Work/observer" init >/dev/null
sync_start=$(python3 -c 'import time;print(time.time())')
"$Datu" --data-dir "$Work/observer" sync --peer "127.0.0.1:$Port" >/dev/null
sync_end=$(python3 -c 'import time;print(time.time())')
pulled=$("$Datu" --data-dir "$Work/observer" status | awk '/^entries:/{print $2}')
lag=$(python3 -c "print(f'{($sync_end-$sync_start):.1f}s, {($pulled)/($sync_end-$sync_start):.0f} entries/s')")
echo "observer caught up: $pulled entries in $lag"
"$Datu" --data-dir "$Work/observer" verify >/dev/null
kill "$node_pid" 2>/dev/null || wait "$node_pid" 2>/dev/null || true
disown "$node_pid" 2>/dev/null || true
echo "PASS: soak batch stored and verified; sync lag measured at this volume"
