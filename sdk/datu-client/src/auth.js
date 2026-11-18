/**
 * SignetAuth (datu-auth-v1) helpers: challenge construction, the canonical
 * signed byte string, and assertion verification in the browser.
 *
 * The canonical bytes must match crates/core/src/auth.rs exactly:
 *   datu-auth-v1\n<rp_id>\n<origin>\n<nonce_hex>\n<expires_at_ms>\n
 */
import { DatuError, ErrorCode } from './errors.js';

export const AUTH_DOMAIN = 'datu-auth-v1';
export const NONCE_BYTES = 16;
export const DEFAULT_TTL_MS = 60_000;

const SPKI_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const hexToBytes = (hex) =>
  Uint8Array.from(String(hex).match(/../g) || [], (pair) => parseInt(pair, 16));

export function randomNonceHex() {
  const bytes = new Uint8Array(NONCE_BYTES);
  (globalThis.crypto || {}).getRandomValues?.(bytes);
  if (!bytes.some(Boolean)) {
    throw new DatuError(ErrorCode.BAD_ARGUMENT, 'no secure random source (crypto.getRandomValues missing)');
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function newChallenge({ rpId, origin, ttlMs = DEFAULT_TTL_MS, nonce }) {
  if (!rpId) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'rpId is required');
  if (!origin) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'origin is required');
  return {
    rp_id: rpId,
    origin,
    nonce: nonce || randomNonceHex(),
    expires_at_ms: Date.now() + ttlMs,
  };
}

export function authSignedBytes({ rp_id, origin, nonce, expires_at_ms }) {
  return new TextEncoder().encode(
    `${AUTH_DOMAIN}\n${rp_id}\n${origin}\n${nonce}\n${expires_at_ms}\n`,
  );
}

export function challengeIsLive(challenge, nowMs = Date.now()) {
  return nowMs < challenge.expires_at_ms;
}

/** Verify Ed25519 with WebCrypto (Chrome/Edge/Safari current, Node 20+). */
export async function verifyEd25519(pubkeyHex, message, signatureHex) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) return 'unavailable';
  try {
    const der = new Uint8Array([...SPKI_ED25519_PREFIX, ...hexToBytes(pubkeyHex)]);
    const key = await subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify']);
    const ok = await subtle.verify(
      { name: 'Ed25519' },
      key,
      hexToBytes(signatureHex),
      message instanceof Uint8Array ? message : new Uint8Array(message),
    );
    return ok ? 'ok' : 'invalid';
  } catch {
    return 'unavailable';
  }
}

/**
 * Verify an assertion against the challenge this app issued. Returns
 * { ok, reason }. `ok === null` means no local verifier was available and the
 * caller must decide whether to trust the transport.
 */
export async function verifyAssertion(assertion, challenge) {
  if (!assertion || typeof assertion !== 'object') {
    return { ok: false, reason: 'no assertion returned' };
  }
  if (assertion.domain && assertion.domain !== AUTH_DOMAIN) {
    return { ok: false, reason: `unexpected domain ${assertion.domain}` };
  }
  if (
    assertion.rp_id !== challenge.rp_id ||
    assertion.origin !== challenge.origin ||
    assertion.nonce !== challenge.nonce ||
    assertion.expires_at_ms !== challenge.expires_at_ms
  ) {
    return { ok: false, reason: 'assertion does not match the challenge this app issued' };
  }
  if (!challengeIsLive(challenge)) return { ok: false, reason: 'challenge expired' };
  if (!assertion.pubkey || !assertion.signature) {
    return { ok: false, reason: 'assertion is missing pubkey or signature' };
  }
  const verdict = await verifyEd25519(
    assertion.pubkey,
    authSignedBytes(challenge),
    assertion.signature,
  );
  if (verdict === 'ok') return { ok: true };
  if (verdict === 'invalid') return { ok: false, reason: 'signature invalid' };
  return { ok: null, reason: 'no local Ed25519 verifier available' };
}

/**
 * Build the link a phone signer opens (QR, button, deep link). The phone
 * signs the challenge with its own key and returns the assertion in
 * `redirect`'s fragment: no extension, no bridge token, no desktop.
 * Parameters match datu-auth-v1 exactly; `nonce` is the one you generated
 * with newChallenge().
 */
export function buildSignInLink({ rpId, origin, nonce, expiresAtMs, redirect }) {
  if (!rpId || !origin || !nonce || !expiresAtMs || !redirect) {
    throw new Error('buildSignInLink needs rpId, origin, nonce, expiresAtMs and redirect');
  }
  const query = new URLSearchParams({
    rp_id: rpId,
    origin,
    nonce,
    expires_at_ms: String(expiresAtMs),
    redirect,
  });
  return `datu-auth://sign?${query.toString()}`;
}

/**
 * Read the assertion a phone handed back in the redirect fragment:
 * `https://rp/callback#datu-assertion=<base64url(json)>`. Returns null when
 * the fragment is absent or unreadable (never throws on hostile input -
 * pass the result to verifyAssertion, which fails closed).
 */
export function readAssertionFragment(url) {
  let fragment = '';
  try {
    fragment = new URL(String(url)).hash.replace(/^#/, '');
  } catch {
    return null;
  }
  const prefix = 'datu-assertion=';
  if (!fragment.startsWith(prefix)) return null;
  let payload = fragment.slice(prefix.length);
  try {
    payload += '='.repeat((4 - (payload.length % 4)) % 4);
    const json = atob(payload.replaceAll('-', '+').replaceAll('_', '/'));
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}
