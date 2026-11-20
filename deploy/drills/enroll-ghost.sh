#!/usr/bin/env bash
# Ghost-enrollment drill (anti-impostor slice 2): a registry wants to enroll
# a citizen key. Prove the two-signature ceremony: it completes only when
# the citizen consents with the very key being enrolled, and every ghost
# path (a third party accepting, missing consent, tampered claims, the
# wrong registry approving) fails with the reason named.
set -euo pipefail
Datu=${DATU:-./target/release/datu}
Work=$(mktemp -d /tmp/datu-enroll.XXXXXX)
cleanup() { rm -rf "$Work"; }
trap cleanup EXIT
say() { printf '\n== %s\n' "$*"; }
key_of() { "$Datu" --data-dir "$1" keys | awk '/identity \(ed25519\):/{print $3}'; }

say "cast: registry R, citizen C (the subject), ghost G (impostor), second registry R2"
for n in r c g r2; do "$Datu" --data-dir "$Work/$n" init >/dev/null; done
C_KEY=$(key_of "$Work/c")

say "R opens the enrollment for C's key (born on C's device, never on R's)"
"$Datu" --data-dir "$Work/r" enroll open --subject "$C_KEY" \
  --claims '{"legal_name":"Acme Ltd","role":"bidder"}' --label "Acme Ltd" \
  --out "$Work/offer.json" >/dev/null
grep -q '"kind": "identity.enroll"' "$Work/offer.json" \
  || { echo "FAIL: offer is not an identity.enroll document"; exit 1; }
echo "offer written, names subject $C_KEY"

say "GHOST 1: G tries to accept for C (consenting for someone else)"
if "$Datu" --data-dir "$Work/g" enroll accept --input "$Work/offer.json" \
  --out "$Work/g-accepted.json" >"$Work/g.log" 2>&1; then
  echo "FAIL: the ghost accepted an enrollment for another key"; exit 1
fi
grep -q "ghost" "$Work/g.log" || { echo "FAIL: refusal must name the ghost:"; cat "$Work/g.log"; exit 1; }
echo "refused: $(tail -1 "$Work/g.log")"

say "GHOST 2: R tries to approve without C's consent"
if "$Datu" --data-dir "$Work/r" enroll approve --input "$Work/offer.json" \
  >"$Work/noconsent.log" 2>&1; then
  echo "FAIL: enrollment approved without subject consent"; exit 1
fi
grep -q "subject" "$Work/noconsent.log" || { echo "FAIL: refusal must name the missing subject signature:"; cat "$Work/noconsent.log"; exit 1; }
echo "refused: $(tail -1 "$Work/noconsent.log")"

say "C accepts with the enrolled key (the ceremony's second signature)"
"$Datu" --data-dir "$Work/c" enroll accept --input "$Work/offer.json" \
  --out "$Work/accepted.json" >/dev/null
echo "accepted: both registrar and subject signatures present"

say "GHOST 3: the claims are edited after C consented"
sed 's/"role":"bidder"/"role":"owner"/; s/"role": "bidder"/"role": "owner"/' \
  "$Work/accepted.json" > "$Work/tampered.json"
if "$Datu" --data-dir "$Work/r" enroll approve --input "$Work/tampered.json" \
  >"$Work/tamper.log" 2>&1; then
  echo "FAIL: tampered claims passed verification"; exit 1
fi
grep -q "verification failed" "$Work/tamper.log" || { echo "FAIL: refusal must name verification:"; cat "$Work/tamper.log"; exit 1; }
echo "refused: $(tail -1 "$Work/tamper.log")"

say "GHOST 4: R2 (a different registry) tries to approve R's ceremony"
if "$Datu" --data-dir "$Work/r2" enroll approve --input "$Work/accepted.json" \
  >"$Work/wrongreg.log" 2>&1; then
  echo "FAIL: a second registry approved an enrollment it did not open"; exit 1
fi
grep -q "registrar" "$Work/wrongreg.log" || { echo "FAIL: refusal must name the registrar:"; cat "$Work/wrongreg.log"; exit 1; }
echo "refused: $(tail -1 "$Work/wrongreg.log")"

say "the honest path: R approves, publishing the ceremony record + attestation"
"$Datu" --data-dir "$Work/r" enroll approve --input "$Work/accepted.json" \
  --min-cosigners 2 >"$Work/approve.log"
enroll_id=$(grep -oE 'enrollment [0-9a-f]{64} published' "$Work/approve.log" | awk '{print $2}')
attest_id=$(grep -oE 'attestation [0-9a-f]{64} published' "$Work/approve.log" | awk '{print $2}')
[ -n "$enroll_id" ] && [ -n "$attest_id" ] \
  || { echo "FAIL: ceremony record or attestation missing"; cat "$Work/approve.log"; exit 1; }
grep -q "0/2 distinct cosigners" "$Work/approve.log" \
  || { echo "FAIL: quorum not reported honestly"; cat "$Work/approve.log"; exit 1; }
echo "attestation $attest_id bound to ceremony $enroll_id (quorum reported 0/2, not faked)"

say "the attestation names the citizen and its ceremony"
"$Datu" --data-dir "$Work/r" attest status --id "$attest_id" >"$Work/attest.log"
grep -q "$C_KEY" "$Work/attest.log" \
  || { echo "FAIL: attestation does not name the citizen"; cat "$Work/attest.log"; exit 1; }
echo "attest status names the enrolled subject"

say "the ceremony record verifies as a party-signed document"
"$Datu" --data-dir "$Work/r" parties show --id "$enroll_id" >"$Work/parties.log"
grep -q "registrar" "$Work/parties.log" && grep -q "subject" "$Work/parties.log" \
  || { echo "FAIL: ceremony record lacks both parties"; cat "$Work/parties.log"; exit 1; }
grep -q "verified" "$Work/parties.log" \
  || { echo "FAIL: party signatures did not verify"; cat "$Work/parties.log"; exit 1; }
echo "registrar + subject signatures verified on the published record"

say "PASS: ghost enrollments never complete; honest two-signature enrollment publishes"
