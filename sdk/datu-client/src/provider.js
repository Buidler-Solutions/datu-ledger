/**
 * Provider genuineness (datu-provider-v1): the proof a dApp demands from
 * whatever claims to be the Signet extension. The dApp sends a fresh nonce;
 * only a caller holding a valid pairing token gets a bridge-keyed Ed25519
 * signature back, so an impostor extension cannot answer.
 *
 * The canonical bytes must match crates/cli/src/walletd.rs exactly:
 *   datu-provider-v1\n<nonce_hex>\n<origin>\n<version>\n<expires_at_ms>\n
 */
import { verifyEd25519, randomNonceHex } from './auth.js';

export const PROVIDER_DOMAIN = 'datu-provider-v1';

export function providerProofBytes({ nonce, origin, version, expires_at_ms }) {
  return new TextEncoder().encode(
    `${PROVIDER_DOMAIN}\n${nonce}\n${origin}\n${version}\n${expires_at_ms}\n`,
  );
}

export { randomNonceHex };

/**
 * Verify a provider proof against the challenge this app issued.
 * Returns { ok, reason }; ok === null means no local Ed25519 verifier
 * existed (the caller decides whether an answered-but-unverified provider
 * is acceptable).
 */
export async function verifyProviderProof(proof, { nonce, nowMs = Date.now() } = {}) {
  if (!proof || typeof proof !== 'object') {
    return { ok: false, reason: 'no proof returned' };
  }
  if (proof.domain && proof.domain !== PROVIDER_DOMAIN) {
    return { ok: false, reason: `unexpected domain ${proof.domain}` };
  }
  if (proof.nonce !== nonce) {
    return { ok: false, reason: 'proof does not answer the nonce this app issued' };
  }
  if (typeof proof.expires_at_ms !== 'number' || nowMs >= proof.expires_at_ms) {
    return { ok: false, reason: 'proof expired' };
  }
  if (!proof.bridge_pubkey || !proof.signature) {
    return { ok: false, reason: 'proof is missing bridge_pubkey or signature' };
  }
  const verdict = await verifyEd25519(
    proof.bridge_pubkey,
    providerProofBytes(proof),
    proof.signature,
  );
  if (verdict === 'ok') return { ok: true };
  if (verdict === 'invalid') return { ok: false, reason: 'signature invalid' };
  return { ok: null, reason: 'no local Ed25519 verifier available' };
}

const pinKey = (bridgeUrl) => `datu:bridge-key:${bridgeUrl}`;

/**
 * TOFU pinning of the bridge key per bridge URL: the first proof pins it,
 * later proofs must match, so a swapped bridge (or a provider playing one)
 * is caught. `expected` (explicit trust) wins over the pin.
 * Returns { ok, reason?, pinnedNow }.
 */
export function pinBridgeKey(bridgeUrl, bridgePubkey, expected) {
  if (!bridgeUrl) return { ok: true, pinnedNow: false };
  if (expected && expected !== bridgePubkey) {
    return { ok: false, reason: 'bridge key differs from the expected key' };
  }
  let store = null;
  try {
    store = globalThis.localStorage;
  } catch {
    /* some embeddings disallow touching it */
  }
  if (!store) return { ok: true, pinnedNow: false };
  const key = pinKey(bridgeUrl);
  let pinned = null;
  try {
    pinned = store.getItem(key);
  } catch {
    return { ok: true, pinnedNow: false };
  }
  if (pinned && pinned !== bridgePubkey) {
    return {
      ok: false,
      reason: 'the Signet bridge key changed since first use - verify before continuing',
    };
  }
  if (!pinned) {
    try {
      store.setItem(key, bridgePubkey);
    } catch {
      /* private mode: pinning is best-effort */
    }
    return { ok: true, pinnedNow: true };
  }
  return { ok: true, pinnedNow: false };
}
