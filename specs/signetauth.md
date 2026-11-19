# SignetAuth: login with a DATU Signet identity

SignetAuth turns a Signet Personal Vault identity into a login credential.
It replaces bearer tokens (passwords, JWTs, session secrets) with a
challenge-response signature from a key that never leaves the user's wallet.
This document is the wire standard for relying parties.

Status: shipped in datu v0.1.x. License: MIT.

## 1. Why

| Property | JWT + 2FA | Passkey | SignetAuth |
|---|---|---|---|
| Credential | bearer token (stealable, replayable) | key in hardware/OS | key in the Signet vault (never in the page) |
| Phishing resistance | weak-moderate | strong (origin binding) | strong (bridge-enforced origin pinning) |
| Server stores | HMAC secret (leak = forgery) | public keys only | public keys only |
| Replay | short exp + refresh | per-ceremony challenge | per-login nonce + expiry |

## 2. The assertion (datu-auth-v1)

The relying party issues a challenge; the Signet signs it; the RP verifies
one Ed25519 signature. The signed bytes are canonical and
domain-separated, so an assertion can never be replayed as a DATU ledger
signature (entries, checkpoints and party signatures cover borsh encodings
or blake3 digests of ledger structures).

Challenge fields:

| Field | Meaning |
|---|---|
| `rp_id` | Relying party identifier, e.g. `app.example.com` (the WebAuthn rp_id analogue) |
| `origin` | Exact origin the login page ran on, e.g. `https://app.example.com` |
| `nonce` | 128-bit single-use random, 32 hex chars, issued by the RP |
| `expires_at_ms` | Challenge expiry, milliseconds since Unix epoch (60s recommended) |

Canonical signed bytes (UTF-8, field order fixed):

```
datu-auth-v1\n<rp_id>\n<origin>\n<nonce_hex>\n<expires_at_ms>\n
```

The assertion returned by the wallet (bridge route
`POST /v1/wallet/auth-assert`, FFI action `auth-assert`, CLI
`datu signet auth-assert`):

```json
{
  "ok": true,
  "domain": "datu-auth-v1",
  "rp_id": "app.example.com",
  "origin": "https://app.example.com",
  "nonce": "abababababababababababababababab",
  "expires_at_ms": 4102444800000,
  "pubkey": "<ed25519 public key, 64 hex chars>",
  "signature": "<ed25519 signature over the canonical bytes, 128 hex chars>",
  "grant": "<optional session grant>",
  "grant_expires_at_ms": 4102444900000
}
```

## 3. Relying party obligations

Verification is one Ed25519 check plus bookkeeping:

1. The `pubkey` must be registered for the user (out-of-band, or by a
   registration assertion signed during onboarding).
2. The `nonce` must be one this RP issued and has not seen used
   (single-use, server-side store).
3. `expires_at_ms` must be in the future by the RP's clock.
4. `rp_id` must equal the RP's own id and `origin` must be an origin the
   RP actually serves.
5. Verify the Ed25519 signature over the canonical bytes above.

Using the released datu binary (no libraries needed):

```
datu signet auth-verify \
  --rp-id app.example.com --origin https://app.example.com \
  --nonce abab...ab --expires-at-ms 4102444800000 \
  --pubkey <64-hex> --signature <128-hex>
```

Exit status 0 plus `verified` means the assertion is genuine; everything
else prints the reason. In Rust, `datu_core::auth::verify_assertion` does
the same; in the browser, recompute the canonical string and verify with
WebCrypto Ed25519 (the registrar dApp ships a working example).

## 4. Client behavior (what the wallet enforces)

- **First use of an rp_id requires an approval gesture** (`approve: true`,
  the panel's Approve button). This registers the origin for that identity.
- **Origin pinning**: after registration the bridge refuses to sign for any
  other origin under that rp_id, so a phishing site can never obtain a
  valid assertion for the real one.
- **Session grants**: a passphrase-authenticated login mints an in-memory
  15-minute sliding grant; silent re-logins use it instead of re-sending
  the passphrase. Grants unlock only the assertion route.
- **Optional device passkey**: the panel can wrap the vault passphrase
  under a WebAuthn PRF-derived key, so the unlock gesture is biometric.
  This gates the panel only; the RP sees the same assertion either way.

## 5. WebAuthn bridge mode (virtual authenticator)

Signet identities can also act as real WebAuthn credentials: the browser
extension proxies `navigator.credentials` calls (chrome.webAuthenticationProxy,
Chrome 115+) to the Signet bridge, which creates credentials and signs
assertions with the identity's Ed25519 key (COSE alg EdDSA, -8). The proxy
attaches exactly while a panel unlock grant is live and detaches otherwise,
so the browser's ordinary passkeys keep working; the extension supplies the
clientDataJSON (including the requesting origin) itself, because the proxy
API passes only the options dictionary. Validated end-to-end in a real
Chromium: create and get ceremonies, SPKI/-8 exposure, and assertion
signatures verified against the identity key.

Formats (implemented in `datu_core::auth::webauthn`):

- Credential public key: COSE_Key with kty OKP (1), crv Ed25519 (6), alg
  EdDSA (-8), x = the 32-byte public key.
- Assertion: `signature = Ed25519(priv, authenticatorData ||
  SHA-256(clientDataJSON))`, authenticatorData = `SHA-256(rp_id) || flags
  (UP|UV) || signCount (u32 BE)`. No attestation statement, no credential
  protection extensions: this is a synced-credential-grade authenticator
  whose root of trust is the Signet vault passphrase (and optionally the
  device passkey that gates the panel).

An RP cannot distinguish this mode from a platform passkey except by
attestation absence, which is also normal for synced passkeys.

## 6. Provider genuineness handshake (datu-provider-v1)

Before asking a human for anything, a dApp can prove the Signet provider is
genuine. The dApp sends a fresh nonce (32..=128 hex chars) through the
extension's `prove` bridge action; the extension relays it as

```
POST /v1/provider-proof
Authorization: Bearer <pairing token>
{"nonce": "<hex>"}
```

and only a caller holding a valid pairing token gets an answer: the bridge's
own Ed25519 key (`wallet/bridge.key`, distinct from every identity key)
signs

```
datu-provider-v1\n<nonce_hex>\n<origin>\n<version>\n<expires_at_ms>\n
```

where `<origin>` is the requesting extension's chrome-extension:// origin,
`<version>` the bridge version, and expiry ~30 s. The proof proves pairing,
not custody (only `datu-auth-v1` assertions prove a human holds keys), needs
no passphrase, and is rate-limited. `proveGenuine()` in
`@greenarmor/datu-client` verifies the signature locally and TOFU-pins the
bridge key per bridge URL. An impostor extension holds no pairing token, so
it can never obtain a proof: a dApp must treat an answered-but-invalid proof
as a definite impostor (never prompt for a passphrase there), while no answer
at all means the bridge is down, not malicious.

## 7. Test vectors

Canonical bytes for a worked example (also pinned in the Rust, extension
and dApp test suites):

```
rp_id          app.example.com
origin         https://app.example.com
nonce          abababababababababababababababab
expires_at_ms  4102444800000
signed string  datu-auth-v1\napp.example.com\nhttps://app.example.com\nabababababababababababababababab\n4102444800000\n
```

Every implementation must byte-match this string; any deviation changes
the signature and fails verification.

## 8. Phone sign-in (no extension, no bridge)

The same assertion, carried by a QR instead of an extension. The phone runs
the wallet core in-process, so the dApp needs nothing installed and the
phone needs no desktop:

```
datu-auth://sign?rp_id=<rp>&origin=<origin>&nonce=<32 hex>&expires_at_ms=<ms>&redirect=<https or http url>
```

1. The dApp issues a challenge and renders the link as a QR (or a button).
2. The phone app shows `rp_id` and `origin` next to the canonical bytes it is
   about to sign, unlocks with the passphrase, and returns
   `redirect#datu-assertion=<base64url(assertion JSON)>`.
3. The dApp verifies with the same §3 obligations: domain, nonce match and
   single use, expiry, then the Ed25519 signature. The fragment never
   reaches a server in transit.

SDK support (out of the box):

```js
// once installed, an app without the extension still logs in:
const flow = datu.phoneSignIn({ rpId, origin });   // or client.signInAuto()
renderQr(flow.link);                                // any QR library
const result = await flow.completed;                // { ok, pubkey } or { ok:false, reason }
// on the page the phone redirects back to:
const resumed = await datu.resumePhoneSignIn();     // reads #datu-assertion=, burns the nonce
```

React: `usePhoneSignIn()` returns `{ begin, link, result }` and resumes a
redirect-back on mount. Server-verified flows (verification done by the
backend, as in `web/signin-demo`) call `flow.accept(assertion)` with the
assertion the server accepted; the SDK re-checks it locally before resolving.

Rules the SDK enforces for this path: the challenge lives in
sessionStorage keyed by nonce (so a reload mid-flight does not lose it), a
nonce signs in exactly once (burned on success), expiry is checked against
the local clock, and the fragment is scrubbed from the URL after a
successful resume so the assertion does not linger in history.
