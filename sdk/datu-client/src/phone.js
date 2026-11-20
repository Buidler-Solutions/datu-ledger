import { buildSignInLink, randomNonceHex, readAssertionFragment, verifyAssertion } from './auth.js';

/**
 * Phone sign-in (out of the box): a dApp with no extension and no bridge can
 * still log a user in. It issues a datu-auth-v1 challenge, hands the phone a
 * link (render it as a QR), and completes when the phone returns the
 * assertion: as a URL fragment on this same page, or posted back by a server
 * that did the relying-party check.
 *
 * The challenge is persisted (sessionStorage when available, in-memory
 * otherwise) so a page reload during the round trip does not lose it, and it
 * is deleted the moment it is used: a nonce signs in exactly once.
 */

const CHALLENGE_PREFIX = 'datu.phone.';
const LATEST_KEY = 'datu.phone.latest';
// Tombstone for spent nonces: deleting the stored challenge is not enough,
// because beginPhoneSignIn can re-store the same nonce; a tombstone makes
// single use hold even then.
const SPENT_PREFIX = 'datu.phone.spent.';

function defaultStorage() {
  try {
    if (typeof sessionStorage !== 'undefined') return sessionStorage;
  } catch {
    /* storage can throw in sandboxed iframes */
  }
  const memory = new Map();
  return {
    getItem: (k) => (memory.has(k) ? memory.get(k) : null),
    setItem: (k, v) => memory.set(k, String(v)),
    removeItem: (k) => memory.delete(k),
  };
}

const looksLikeNonce = (s) => typeof s === 'string' && /^[0-9a-f]{32}$/.test(s);

/**
 * Begin a phone sign-in.
 *
 * Returns { challenge, link, accept(assertion), completed } where
 *   - link      is the datu-auth:// URI to render as a QR or button
 *   - accept    verifies an assertion that arrived by another path (a
 *               server that already ran the relying-party check), resolves
 *               `completed` with { ok, pubkey, assertion } or { ok:false, reason }
 *   - completed never rejects; it resolves on success or failure
 *
 * Options: rpId, origin, ttlMs, nonce, redirect (default: this page without
 * its fragment, so the phone returns to the same view), storage (tests).
 */
export function beginPhoneSignIn({
  rpId,
  origin,
  ttlMs = 5 * 60 * 1000,
  nonce,
  redirect,
  storage = defaultStorage(),
} = {}) {
  if (!rpId) throw new Error('rpId is required');
  if (!origin) throw new Error('origin is required');
  const challenge = {
    rp_id: rpId,
    origin,
    nonce: nonce || randomNonceHex(),
    expires_at_ms: Date.now() + ttlMs,
  };
  if (!looksLikeNonce(challenge.nonce)) throw new Error('nonce must be 32 lowercase hex characters');
  const target = redirect || (defaultPageWithoutFragment() || `${origin}/`);
  const link = buildSignInLink({
    rpId: challenge.rp_id,
    origin: challenge.origin,
    nonce: challenge.nonce,
    expiresAtMs: challenge.expires_at_ms,
    redirect: target,
  });

  storage.setItem(CHALLENGE_PREFIX + challenge.nonce, JSON.stringify({ challenge, redirect: target }));
  storage.setItem(LATEST_KEY, challenge.nonce);

  let settle;
  const completed = new Promise((resolve) => {
    settle = resolve;
  });
  let done = false;

  const finish = async (assertion, { burn = true } = {}) => {
    if (done) return { ok: false, reason: 'sign-in already completed' };
    done = true;
    const verdict = await finishPhoneSignIn({ challenge, assertion, storage, burn });
    settle(verdict);
    return verdict;
  };

  return {
    mode: 'phone',
    challenge,
    link,
    redirect: target,
    accept: (assertion) => finish(assertion),
    completed,
  };
}

function defaultPageWithoutFragment() {
  try {
    if (typeof location !== 'undefined') return location.href.split('#')[0];
  } catch {
    /* not a browser */
  }
  return null;
}

/**
 * Verify an assertion against a challenge, enforcing what a relying party
 * must enforce: field match, liveness, single use. Signature verification is
 * verifyAssertion (WebCrypto); `ok:null` is propagated as "no local
 * verifier", which callers must treat as not-verified.
 */
export async function finishPhoneSignIn({
  challenge,
  assertion,
  storage = defaultStorage(),
  burn = true,
  nowMs = Date.now(),
}) {
  if (!challenge || !assertion) return { ok: false, reason: 'missing challenge or assertion' };
  if (!looksLikeNonce(challenge.nonce)) return { ok: false, reason: 'invalid challenge nonce' };
  if (nowMs > challenge.expires_at_ms) return { ok: false, reason: 'challenge expired' };
  if (storage.getItem(SPENT_PREFIX + challenge.nonce)) {
    return { ok: false, reason: 'nonce already used: a challenge signs in exactly once' };
  }
  const stored = storage.getItem(CHALLENGE_PREFIX + challenge.nonce);
  if (!stored) return { ok: false, reason: 'unknown or already used challenge' };

  const verdict = await verifyAssertion(assertion, challenge);
  if (verdict.ok !== true) {
    return { ok: false, reason: verdict.ok === null ? 'no local Ed25519 verifier' : verdict.reason };
  }
  if (burn) {
    storage.setItem(SPENT_PREFIX + challenge.nonce, String(nowMs));
    storage.removeItem(CHALLENGE_PREFIX + challenge.nonce);
    if (storage.getItem(LATEST_KEY) === challenge.nonce) storage.removeItem(LATEST_KEY);
  }
  return { ok: true, pubkey: assertion.pubkey, assertion };
}

/**
 * Resume after the phone redirects back: reads `#datu-assertion=…` (default:
 * this page's URL), pairs it with the stored challenge, verifies, and scrubs
 * the fragment from the address bar so the assertion does not linger in
 * history or get copied by accident. Returns null when there is nothing to
 * resume. Never throws on hostile input.
 */
export async function resumePhoneSignIn({ url, storage = defaultStorage(), nowMs = Date.now() } = {}) {
  const href = url || (typeof location !== 'undefined' ? location.href : null);
  if (!href) return null;
  const assertion = readAssertionFragment(href);
  if (!assertion || !looksLikeNonce(assertion.nonce)) return null;
  const stored = storage.getItem(CHALLENGE_PREFIX + assertion.nonce);
  if (!stored) return null;
  let parsed;
  try {
    parsed = JSON.parse(stored);
  } catch {
    return null;
  }
  const verdict = await finishPhoneSignIn({
    challenge: parsed.challenge,
    assertion,
    storage,
    nowMs,
  });
  if (verdict.ok) {
    scrubFragment(href);
  }
  return verdict;
}

function scrubFragment(href) {
  try {
    if (typeof history !== 'undefined' && typeof location !== 'undefined' && href === location.href) {
      history.replaceState(null, '', location.pathname + location.search);
    }
  } catch {
    /* cosmetic only */
  }
}
