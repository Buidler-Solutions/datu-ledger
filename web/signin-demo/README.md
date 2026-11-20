# DATU sign-in demo (reference relying party)

A complete dApp-side implementation of QR sign-in: one page issues a
SignetAuth challenge, renders it as a QR, and a callback page verifies the
returned assertion. Deliberately small (node:http + `qrcode`) so it can be
read in one sitting and copied into a real app.

## Run it

```bash
cargo build --release -p datu-cli     # the relying-party verifier
cd web/signin-demo
npm ci
npm start                             # http://0.0.0.0:5176
```

Environment: `PORT` (default 5176), `HOST` (default 0.0.0.0), `DATU_BIN`
(verifier binary), `NODE_URL` (a running `datu serve`, default
`http://127.0.0.1:7474`) used for the identity-chain lookup, and optionally
`REQUIRE_ATTESTATION` - a JSON object in the SDK's `requireAttestation()`
shape, e.g. `{"roots":["<attestor-key>"],"roles":["clerk"],"minCosigners":1}`.
When set, sign-in is refused unless the signing key's chain satisfies it;
the refusal names the reason, and the success page names the vouchers.

## The flow

1. `GET /` issues a challenge (`rp_id` = request hostname, `origin` = the
   exact origin the browser used, 32-hex nonce, 5 minute expiry) and shows
   `datu-auth://sign?…` as a QR plus a copyable link.
2. The phone scans it (DATU Signet app, Login tab), reviews the relying
   party, unlocks with the passphrase, and signs with its vault key.
3. The app opens `http://<host>/auth/callback#datu-assertion=<base64url>`.
   The fragment never reached the server in transit; the page posts it back.
4. `POST /api/verify` runs the relying-party checks: domain, nonce known and
   unused, expiry live, challenge fields equal, then
   `datu signet auth-verify` for the signature itself. The nonce is burned
   whether or not verification succeeds afterwards.
5. The verifier reads the key's identity chain from `/v1/identity/{key}`
   and shows who vouches (attestor, claims, cosigner weight, enrollment),
   or "signed in, unattested". With `REQUIRE_ATTESTATION` set, step 4 is
   only the first gate: the chain must also satisfy the requirement before
   the login is accepted - the pattern a registry-gated dApp uses.

## Verify it without a phone

```bash
npm run smoke
```

gets a challenge, signs it with a throwaway local vault (the same core the
phone runs), and requires: verified result, single-use nonce, forged
signature refused, challenge mismatch refused. It also runs a throwaway
`datu serve` and checks the attestation requirement end to end: an
unattested key is refused, the same key is admitted once a root attests it
(with the voucher named), and a wrong role does not satisfy the
requirement.

## Deploying to a server

See `deploy/signin-demo/` for a compose file with a real validator node and
Caddy for TLS. Two notes for production:

- HTTPS matters here beyond hygiene: some browsers gate camera access on
  secure origins, and the redirect must match the origin you advertise.
- The verifier is stateless; the only state is the open-challenge map, so
  one process per node is fine and restarts only invalidate open QRs.
