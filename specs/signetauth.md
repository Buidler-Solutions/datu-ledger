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

## 5. WebAuthn bridge mode (virtual authenticator, experimental)

Signet identities can also act as real WebAuthn credentials: the browser
extension proxies `navigator.credentials` calls (chrome.webAuthenticationProxy)
to the Signet bridge, which creates credentials and signs assertions with
the identity's Ed25519 key (COSE alg EdDSA, -8).

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

## 6. Test vectors

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
