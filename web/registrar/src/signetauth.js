// SignetAuth (Level 1): challenge-response login for the registrar dApp.
//
// The flow: this app (the relying party) mints a one-time challenge, the
// Signet bridge signs it via the extension (panel approval), and the returned
// Ed25519 signature is verified HERE against the identity's public key. The
// canonical signed bytes match crates/core/src/auth.rs exactly:
//   datu-auth-v1\n<rp_id>\n<origin>\n<nonce_hex>\n<expires_at_ms>\n

export const AUTH_DOMAIN = 'datu-auth-v1';
export const NONCE_BYTES = 16;

export function randomNonceHex() {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function newChallenge({ rpId, origin, ttlMs = 60000 }) {
  return {
    rp_id: rpId,
    origin,
    nonce: randomNonceHex(),
    expires_at_ms: Date.now() + ttlMs,
  };
}

export function authSignedBytes({ rp_id, origin, nonce, expires_at_ms }) {
  return new TextEncoder().encode(
    `${AUTH_DOMAIN}\n${rp_id}\n${origin}\n${nonce}\n${expires_at_ms}\n`
  );
}

export function challengeIsLive(challenge, nowMs = Date.now()) {
  return nowMs < challenge.expires_at_ms;
}

// The node serves /coverage.js, which exposes verifyEd25519 (WebCrypto) on
// window.datuCoverage. We reuse it instead of shipping a second verifier.
// Probe with a fetch first so an unreachable node fails fast instead of
// hanging on a script tag that never settles.
let coverageLoading = null;
export function loadCoverageVerifier(nodeUrl) {
  if (typeof window === 'undefined') return Promise.resolve(false);
  if (window.datuCoverage) return Promise.resolve(true);
  if (coverageLoading) return coverageLoading;
  const base = (nodeUrl || '').replace(/\/+$/, '');
  coverageLoading = (async () => {
    try {
      const res = await fetch(`${base}/coverage.js`, { signal: AbortSignal.timeout(3000) });
      if (!res.ok) return false;
      const text = await res.text();
      (0, eval)(text);
      return Boolean(window.datuCoverage);
    } catch {
      return false;
    }
  })();
  return coverageLoading;
}

export async function verifyAssertion(nodeUrl, assertion, challenge) {
  if (assertion.domain !== AUTH_DOMAIN) return { ok: false, reason: `unexpected domain ${assertion.domain}` };
  if (assertion.rp_id !== challenge.rp_id || assertion.origin !== challenge.origin ||
      assertion.nonce !== challenge.nonce || assertion.expires_at_ms !== challenge.expires_at_ms) {
    return { ok: false, reason: 'assertion does not match the challenge this app issued' };
  }
  if (!challengeIsLive(challenge)) return { ok: false, reason: 'challenge expired' };
  const haveVerifier = await loadCoverageVerifier(nodeUrl);
  if (!haveVerifier || !window.datuCoverage?.verifyEd25519) {
    return { ok: null, reason: 'no local Ed25519 verifier (coverage.js unreachable from the node)' };
  }
  const verdict = await window.datuCoverage.verifyEd25519(
    assertion.pubkey,
    authSignedBytes(challenge),
    assertion.signature
  );
  if (verdict === 'ok') return { ok: true };
  return { ok: false, reason: `signature invalid (${verdict})` };
}
