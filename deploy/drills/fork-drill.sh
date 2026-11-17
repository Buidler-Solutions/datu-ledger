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
# Each disputant signs its own view before exporting: author-signed roots
# are the evidence the --against path compares.
"$Datu" --data-dir "$Work/a" checkpoint >/dev/null
"$Datu" --data-dir "$Work/b" checkpoint >/dev/null
"$Datu" --data-dir "$Work/a" bundle export --out "$Work/a.bundle" >/dev/null
set +e
"$Datu" --data-dir "$Work/b" prove-fork --against "$Work/a.bundle" --out "$Work/evidence.json" >"$Work/proof.log" 2>&1
proof_rc=$?
set -e
cat "$Work/proof.log" | tail -3
[ -s "$Work/evidence.json" ] || { echo "FAIL: no evidence package written"; exit 1; }
grep -q "verdict: FORK_PROVEN" "$Work/proof.log" || { echo "FAIL: bundle comparison must prove the fork"; exit 1; }
[ "$proof_rc" -eq 2 ] || { echo "FAIL: proven fork must exit 2 (got $proof_rc)"; exit 1; }

say "witness streams: one witness, two incompatible height-0 views"
# A witness vouches for A's history, then (keys cloned onto a wiped store)
# vouches for B's divergent history at the same checkpoint height: the two
# witness streams are cryptographic proof that at least one view is fabricated.
"$Datu" --data-dir "$Work/w1" init >/dev/null
"$Datu" --data-dir "$Work/a" node --addr "127.0.0.1:$Port" --every 0 \
  >"$Work/a2.log" 2>&1 &
pid=$!
sleep 1
"$Datu" --data-dir "$Work/w1" sync --peer "127.0.0.1:$Port" >"$Work/w1-sync.log" 2>&1
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
"$Datu" --data-dir "$Work/w1" witness sign >/dev/null
"$Datu" --data-dir "$Work/w1" witness export --out "$Work/w1.stream" >/dev/null

mkdir -p "$Work/w2"
cp -a "$Work/w1/." "$Work/w2/"
rm -f "$Work/w2"/node.db*
"$Datu" --data-dir "$Work/b" node --addr "127.0.0.1:$((Port + 1))" --every 0 \
  >"$Work/b.log" 2>&1 &
pid=$!
sleep 1
"$Datu" --data-dir "$Work/w2" sync --peer "127.0.0.1:$((Port + 1))" >"$Work/w2-sync.log" 2>&1
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
"$Datu" --data-dir "$Work/w2" witness sign >/dev/null
"$Datu" --data-dir "$Work/w2" witness export --out "$Work/w2.stream" >/dev/null

set +e
"$Datu" prove-fork --a "$Work/w1.stream" --b "$Work/w2.stream" --out "$Work/evidence-witness.json" >"$Work/witness-proof.log" 2>&1
witness_rc=$?
set -e
cat "$Work/witness-proof.log" | tail -3
grep -q "verdict: FORK_PROVEN" "$Work/witness-proof.log" || { echo "FAIL: witness streams show no contradiction"; exit 1; }
grep -q "same-height-fork" "$Work/evidence-witness.json" || { echo "FAIL: no same-height-fork evidence kind"; exit 1; }
[ "$witness_rc" -eq 2 ] || { echo "FAIL: proven fork must exit 2 (got $witness_rc)"; exit 1; }

say "honest witness control: one stream against itself"
set +e
"$Datu" prove-fork --a "$Work/w1.stream" --b "$Work/w1.stream" >"$Work/control.log" 2>&1
control_rc=$?
set -e
grep -q "verdict: NO_CONTRADICTIONS" "$Work/control.log" || { echo "FAIL: identical streams must be clean"; exit 1; }
[ "$control_rc" -eq 0 ] || { echo "FAIL: clean verdict must exit 0 (got $control_rc)"; exit 1; }

echo
echo "PASS: fork detected, sync refused, evidence package written (rc $proof_rc)"
echo "PASS: witness-stream contradiction verdict FORK_PROVEN (rc 2), self-comparison clean (rc 0)"
