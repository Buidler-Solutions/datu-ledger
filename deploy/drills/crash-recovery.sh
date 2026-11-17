#!/usr/bin/env bash
# Crash recovery drill: write entries through a running node, SIGKILL it,
# restart, and prove the store is intact with nothing acknowledged lost.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-crash.XXXXXX)
trap 'rm -rf "$Work"' EXIT
Port=${PORT:-7599}
Http=${HTTP_PORT:-7598}

"$Datu" --data-dir "$Work/node" init >/dev/null
"$Datu" --data-dir "$Work/node" node --addr "127.0.0.1:$Port" \
  --http "127.0.0.1:$Http" --every 0 >"$Work/node.log" 2>&1 &
pid=$!
sleep 1

for i in $(seq 1 20); do
  "$Datu" --data-dir "$Work/node" publish --ns gov.crash \
    --payload "{\"n\":$i}" >/dev/null
done
before=$("$Datu" --data-dir "$Work/node" status | awk '/^entries:/{print $2}')
echo "entries before kill: $before"

kill -9 "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

"$Datu" --data-dir "$Work/node" verify | tail -1
after=$("$Datu" --data-dir "$Work/node" status | awk '/^entries:/{print $2}')
echo "entries after kill -9 and restart-read: $after"
[ "$before" = "$after" ] || { echo "FAIL: acknowledged entries lost on crash"; exit 1; }
echo "PASS: store survives SIGKILL with all entries intact"
