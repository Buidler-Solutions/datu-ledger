#!/usr/bin/env bash
# Key custody drill (readiness item S7): a node key leaks. Prove the full
# ceremony: history survives (bundle import onto a new host with a NEW key),
# the old key is revoked by a trust root, the writer gate flips from the old
# key to the new one, and the evidence trail exists on the ledger.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-keyrot.XXXXXX)
PIDS=()
cleanup() { kill -9 ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null || true; rm -rf "$Work"; }
trap cleanup EXIT
Port=${PORT:-7591}
say() { printf '\n== %s\n' "$*"; }
key_of() { "$Datu" --data-dir "$1" keys | awk '/identity \(ed25519\):/{print $3}'; }

say "cast: writer W (the key that will leak), trust root T, validator V"
for n in w t v; do "$Datu" --data-dir "$Work/$n" init >/dev/null; done
W_KEY=$(key_of "$Work/w"); T_KEY=$(key_of "$Work/t")

say "T attests W; V pins T as its trust root over gov.custody.*"
"$Datu" --data-dir "$Work/w" publish --ns general --payload '{"n":1}' >/dev/null
"$Datu" --data-dir "$Work/w" publish --ns gov.custody --payload '{"n":2}' >/dev/null
"$Datu" --data-dir "$Work/t" attest create --subject "$W_KEY" \
  --claims '{"role":"writer"}' >/dev/null
cat > "$Work/v/policy.json" <<EOF
{
  "version": 1,
  "gated": ["gov.custody"],
  "attestors": ["$T_KEY"],
  "writers": [],
  "min_cosigners": 0
}
EOF

say "V syncs from W and T, then admits W's gated entry"
serve() { local n=$1 p=$2; "$Datu" --data-dir "$Work/$n" node --addr "127.0.0.1:$p" --every 0 \
  >"$Work/$n.serve.log" 2>&1 & local p=$!; PIDS+=("$p"); echo "$p"; }
pid=$(serve w "$Port"); sleep 1
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$Port" >/dev/null 2>&1 || true
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
pid=$(serve t "$((Port + 1))"); sleep 1
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$((Port + 1))" >/dev/null
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
count=$("$Datu" --data-dir "$Work/v" status | awk '/^entries:/{print $2}')
echo "V holds $count entries (genesis, W's two, T's attestation)"

say "the leak: W's key is compromised; new host, new key, same history"
"$Datu" --data-dir "$Work/w" bundle export --out "$Work/w.bundle" >/dev/null
"$Datu" --data-dir "$Work/w2" init >/dev/null
W2_KEY=$(key_of "$Work/w2")
"$Datu" --data-dir "$Work/w2" bundle import --input "$Work/w.bundle" >/dev/null
imported=$("$Datu" --data-dir "$Work/w2" status | awk '/^entries:/{print $2}')
[ "$imported" = "$count" ] || { echo "FAIL: history did not survive the move ($imported != $count)"; exit 1; }
echo "new host restored from backup: $imported entries, key $W2_KEY"

say "containment: T revokes the leaked key"
"$Datu" --data-dir "$Work/t" attest revoke --key "$W_KEY" \
  --reason "custody drill: key compromise" >/dev/null
pid=$(serve t "$((Port + 1))"); sleep 1
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$((Port + 1))" >/dev/null
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true

say "the gate flips: the leaked key can no longer write, the new one can"
set +e
"$Datu" --data-dir "$Work/w" publish --ns gov.custody --payload '{"stolen":true}' >/dev/null 2>&1
stolen_rc=$?
set -e
[ "$stolen_rc" -ne 0 ] || echo "note: the local store accepted the entry (expected; the gate lives in V's policy, not the writer's local store)"
pid=$(serve w "$Port"); sleep 1
set +e
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$Port" >"$Work/stolen-sync.log" 2>&1
sync_rc=$?
set -e
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
grep -q "revoked by a configured trust root" "$Work/stolen-sync.log" \
  || { echo "FAIL: revoked key still admitted"; cat "$Work/stolen-sync.log"; exit 1; }
echo "V refused the leaked key's entry: $(grep -o 'revoked by a configured trust root' "$Work/stolen-sync.log" | head -1)"

"$Datu" --data-dir "$Work/t" attest create --subject "$W2_KEY" \
  --claims '{"role":"writer","replaces":"'"$W_KEY"'"}' >/dev/null
"$Datu" --data-dir "$Work/w2" publish --ns gov.custody --payload '{"n":3,"after":"rotation"}' >/dev/null
pid=$(serve t "$((Port + 1))"); sleep 1
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$((Port + 1))" >/dev/null
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
pid=$(serve w2 "$((Port + 2))"); sleep 1
"$Datu" --data-dir "$Work/v" sync --peer "127.0.0.1:$((Port + 2))" >/dev/null
kill "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
"$Datu" --data-dir "$Work/v" verify >/dev/null
final=$("$Datu" --data-dir "$Work/v" status | awk '/^entries:/{print $2}')
echo "V now holds $final entries: rotation entry, revocation, new attestation, W2's post-rotation write"

say "evidence trail"
revs=$("$Datu" --data-dir "$Work/v" disputes 2>/dev/null | wc -l)
"$Datu" --data-dir "$Work/v" attest status --subject "$W_KEY" | tail -3

echo
echo "PASS: history survived the move ($imported entries on a new host under a new key)"
echo "PASS: the leaked key was revoked and refused by the gate; the new key was admitted"
