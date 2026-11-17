# Wallet bridge hardening review (readiness item S5)

Scope: `crates/cli/src/walletd.rs`, the local HTTP bridge between browser
callers (the Signet extension, paired dApps) and the holder's wallet.
Review date: 2026-11-17. Adversarial tests live in the same file, module
`walletd::tests`; this note maps each threat to its mechanism and its test.

## Threat model

The bridge listens on loopback by default and serves anyone who can open a
TCP connection to that port: local tools, the paired extension, and any web
page the holder visits (pages can attempt cross-origin requests to
localhost; browsers attach their true Origin, which cannot be forged by
page script). Keys never leave the process; every custody operation needs
the holder's passphrase, Argon2id-stretched on the wallet side.

## Mechanisms

| Threat | Mechanism | Test |
|---|---|---|
| A web page pairing itself as an "extension" | `/v1/pair` is POST-only and only serves `chrome-extension://` origins (Chromium guarantees the header on extension POSTs) | `pair_tokens_are_bound_to_the_extension_origin` |
| A phished/pasted token replayed by another extension | Pair tokens are minted per origin and compared to the request Origin; a different extension gets 403 (`ForeignPair`) | same |
| The legacy shared token used from a browser | `bridge.token` authorizes only Origin-less local tools; browser callers get 401 | same |
| Unknown or malformed bearer tokens | 401 for unknown, empty, or padding tokens; constant-time compare (`const_eq`) over pair and legacy tokens | `hostile_tokens_and_origins_are_refused` |
| Sandboxed iframes (`Origin: null`), unlisted https origins | Origin allowlist gate before any route logic; 403 with the `--allow-origin` remediation hint | same |
| Passphrase brute force over HTTP | Per-identity counter: 5 misses lock the identity for 15 s; the lockout also blocks the correct passphrase (no retry oracle); success resets the counter | `passphrase_brute_force_locks_the_identity` |
| Stolen auth-assert session grant escalated to custody | Grants are route-scoped by construction: only `auth-assert` (and the WebAuthn routes) consult them; export, sealing, signing and import always demand the passphrase; grants are in-memory, 15 min sliding, name-bound | `grants_never_unlock_custody_routes` |
| Phishing a login assertion for the real rp | Per-identity rp registry: first use needs an explicit approval, then the (rp_id, origin) binding is pinned; a mismatched origin is refused even with `approve: true` | `auth_assert_over_http` |
| Proof-route hammering (token-only endpoint) | Fixed-window limiter, 60 requests per 60 s, per bridge instance (a second bridge keeps its own budget); the limiter sits in front of nonce validation | `provider_proof_route_is_rate_limited` |
| Malformed proof nonces minting signatures | Nonce must be 32..=128 hex chars; rejected before any signing | same |
| Oversized request bodies | 2 MiB body cap, same budget class as the node HTTP surface; over-budget requests are dropped without a response | `oversized_bodies_are_dropped` |

## Reviewed and accepted

- `Access-Control-Allow-Origin: *` on responses: safe because authorization
  is the Bearer pairing token, which page script cannot read (it lives in
  extension storage), and no route answers credentialed GETs with secrets
  absent a valid token. The Origin checks above are the phishing defense;
  CORS here only widens who can *attempt* a call, not who passes.
- No Host-header validation: the token gate is the boundary, not the Host.
  A DNS-rebinding page arrives with no usable token and stops at 401/403.
- Pair tokens of paired extensions grant read access (identity list) and
  the right to *ask* for signatures; custody stays passphrase-gated.
- Lockout state is per process, in memory: restarting the bridge clears it.
  That is acceptable for a single-user local service; the passphrase itself
  remains the real gate, the throttle only slows online guessing.

## Operational notes

- Run the bridge on loopback only. A non-loopback bind prints a warning:
  anyone reaching the port with a token can ask for signatures.
- Pair web dApps explicitly with `--allow-origin https://app.example.com`;
  never widen the allowlist to `*`-shaped patterns.
- The pairing registry (`wallet/bridge.pairs.json`) and the legacy token
  (`wallet/bridge.token`) are secrets in situ: include the data dir in
  backups, exclude it from sync/sharing tools.
