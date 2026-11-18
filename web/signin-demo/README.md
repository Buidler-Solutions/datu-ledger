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
`http://127.0.0.1:7474`) used for the attestation lookup.

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
5. The verifier asks the node for `identity.attest` entries naming the key
   and shows the attested claims, or "signed in, unattested".

## Verify it without a phone

```bash
npm run smoke
```

gets a challenge, signs it with a throwaway local vault (the same core the
phone runs), and requires: verified result, single-use nonce, forged
signature refused, challenge mismatch refused.

## Deploying to a server

See `deploy/signin-demo/` for a compose file with a real validator node and
Caddy for TLS. Two notes for production:

- HTTPS matters here beyond hygiene: some browsers gate camera access on
  secure origins, and the redirect must match the origin you advertise.
- The verifier is stateless; the only state is the open-challenge map, so
  one process per node is fine and restarts only invalidate open QRs.
