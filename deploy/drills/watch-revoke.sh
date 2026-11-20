#!/usr/bin/env bash
# Revocation-visibility drill: a citizen (or the registry) must not learn
# about a revocation by luck. `datu watch` polls /v1/identity and reports
# attestation revocations, then exits 2 on a key-level revocation so cron,
# systemd or a monitoring hook can alert.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-watch.XXXXXX)
PIDS=()
cleanup() { kill -9 ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null || true; rm -rf "$Work"; }
trap cleanup EXIT
Port=${PORT:-7593}
say() { printf '\n== %s\n' "$*"; }
key_of() { "$Datu" --data-dir "$1" keys | awk '/identity \(ed25519\):/{print $3}'; }

say "cast: registry R, citizen C (the watched key)"
"$Datu" --data-dir "$Work/r" init >/dev/null
"$Datu" --data-dir "$Work/w" init >/dev/null
W_KEY=$(key_of "$Work/w")
attest=$("$Datu" --data-dir "$Work/r" attest create --subject "$W_KEY" \
  --claims '{"role":"clerk"}' --label "Watcher" | awk '/^attestation /{print $2}')
[ -n "$attest" ] || { echo "FAIL: no attestation"; exit 1; }
echo "R attested C ($attest)"

"$Datu" --data-dir "$Work/r" serve --addr "127.0.0.1:$Port" >"$Work/serve.log" 2>&1 &
PIDS+=("$!")
disown 2>/dev/null || true
for i in $(seq 1 50); do
  if "$Datu" --data-dir "$Work/r" watch --subject "$W_KEY" --node "http://127.0.0.1:$Port" --once >"$Work/base.log" 2>&1; then
    break
  fi
  sleep 0.1
done
grep -q "1 attestation(s)" "$Work/base.log" || { echo "FAIL: baseline missing"; cat "$Work/base.log"; exit 1; }
echo "baseline: $(tail -1 "$Work/base.log")"

say "the attestation is revoked: an unattended check must still see it"
"$Datu" --data-dir "$Work/r" attest revoke --id "$attest" --reason "left the cooperative" >/dev/null
"$Datu" --data-dir "$Work/r" watch --subject "$W_KEY" --node "http://127.0.0.1:$Port" --once --json >"$Work/revoked.json"
grep -q '"revoked_attestations":1' "$Work/revoked.json" \
  || { echo "FAIL: the --once check missed the revocation"; cat "$Work/revoked.json"; exit 1; }
grep -q '"key_revoked":false' "$Work/revoked.json" \
  || { echo "FAIL: an attestation revocation must not read as key revocation"; cat "$Work/revoked.json"; exit 1; }
echo "seen: $(cat "$Work/revoked.json")"

say "the key is revoked: watch must report it and exit 2"
"$Datu" --data-dir "$Work/r" attest revoke --key "$W_KEY" --reason "key compromised" >/dev/null
set +e
"$Datu" --data-dir "$Work/w" watch --subject "$W_KEY" --node "http://127.0.0.1:$Port" --once >"$Work/keyrevoked.log" 2>&1
rc=$?
set -e
[ "$rc" = 2 ] || { echo "FAIL: revoked key must exit 2, got $rc"; cat "$Work/keyrevoked.log"; exit 1; }
grep -q "KEY REVOKED by" "$Work/keyrevoked.log" \
  || { echo "FAIL: the terminal event must be unmistakable"; cat "$Work/keyrevoked.log"; exit 1; }
grep -q "key compromised" "$Work/keyrevoked.log" \
  || { echo "FAIL: the revocation reason is missing"; cat "$Work/keyrevoked.log"; exit 1; }
echo "exit 2: $(tail -1 "$Work/keyrevoked.log")"

say "PASS: revocations are reported, and a revoked key exits 2"
