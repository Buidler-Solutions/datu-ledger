#!/usr/bin/env bash
# Fork drill: same author key, same seq, different payloads on two nodes.
# The sync must keep BOTH and record the dispute, never silently pick a winner.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-fork.XXXXXX)
trap 'rm -rf "$Work"' EXIT
Port=${PORT:-7581}
say() { printf '\n== %s\n' "$*"; }

say "node A: three entries"
"$Datu" --data-dir "$Work/a" init >/dev/null
for i in 1 2 3; do
  "$Datu" --data-dir "$Work/a" publish --ns gov.fork --payload "{\"n\":$i}" >/dev/null
done

say "node B: clone then diverge at the next seq"
mkdir -p "$Work/b"
cp -a "$Work/a/." "$Work/b/"
"$Datu" --data-dir "$Work/b" publish --ns gov.fork --payload '{"fork":"B"}' >/dev/null
"$Datu" --data-dir "$Work/a" publish --ns gov.fork --payload '{"fork":"A"}' >/dev/null

say "serve A and sync B from it"
"$Datu" --data-dir "$Work/a" node --addr "127.0.0.1:$Port" --every 0 \
  >"$Work/a.log" 2>&1 &
pid=$!
sleep 1
set +e
"$Datu" --data-dir "$Work/b" sync --peer "127.0.0.1:$Port" >"$Work/sync.log" 2>&1
sync_rc=$?
set -e
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

say "B's sync result"
cat "$Work/sync.log" | tail -2
grep -q "contradicting" "$Work/sync.log" || { echo "FAIL: fork not detected"; exit 1; }
grep -q "prove-fork" "$Work/sync.log" || { echo "FAIL: no evidence guidance"; exit 1; }
[ "$sync_rc" -ne 0 ] || { echo "FAIL: fork sync should fail closed"; exit 1; }
entries=$("$Datu" --data-dir "$Work/b" status | awk '/entries:/{print $2}')
echo "B keeps its own history: entries $entries (genesis + 3 + its own divergent 4th)"
[ "$entries" = "5" ] || { echo "FAIL: local chain was disturbed"; exit 1; }

say "prove-fork evidence"
"$Datu" --data-dir "$Work/a" bundle export --out "$Work/a.bundle" >/dev/null
set +e
"$Datu" --data-dir "$Work/b" prove-fork --against "$Work/a.bundle" --out "$Work/evidence.json" >"$Work/proof.log" 2>&1
proof_rc=$?
set -e
cat "$Work/proof.log" | tail -3
[ -s "$Work/evidence.json" ] || { echo "FAIL: no evidence package written"; exit 1; }
echo
echo "PASS: fork detected, sync refused, evidence package written (rc $proof_rc)"
