/**
 * Identity chains: who vouches for a key, from GET /v1/identity/{key}.
 *
 * The node verified the signatures it served; this module applies YOUR
 * policy on top - which roots count, which roles matter, how much cosigned
 * weight is enough - and always names the vouchers. It never returns a bare
 * "verified": an attestation is a signed statement, and which statements you
 * believe is a choice, not a lookup.
 */
import { DatuError, ErrorCode } from './errors.js';

const CHAIN_TIMEOUT_MS = 3000;
const HEX64 = /^[0-9a-f]{64}$/;

const short = (key) => (typeof key === 'string' && key.length > 12 ? `${key.slice(0, 8)}...${key.slice(-4)}` : String(key));

/**
 * Fetch the identity chain for `pubkey` from a ledger node. Throws a typed
 * DatuError (BAD_ARGUMENT, TIMEOUT, NODE_ERROR) rather than returning a
 * half-trusted object: a caller who cannot see the chain cannot judge it.
 */
export async function fetchIdentityChain(nodeUrl, pubkey, { timeoutMs = CHAIN_TIMEOUT_MS, fetchImpl } = {}) {
  if (!HEX64.test(String(pubkey))) {
    throw new DatuError(ErrorCode.BAD_ARGUMENT, 'pubkey must be 64 lowercase hex characters');
  }
  const base = String(nodeUrl || '').replace(/\/+$/, '');
  if (!base) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'nodeUrl is required');
  const doFetch = fetchImpl || globalThis.fetch;
  if (!doFetch) throw new DatuError(ErrorCode.NODE_ERROR, 'no fetch available in this environment');

  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  let res;
  try {
    res = await doFetch(`${base}/v1/identity/${pubkey}`, controller ? { signal: controller.signal } : {});
  } catch (e) {
    if (controller && controller.signal.aborted) {
      throw new DatuError(ErrorCode.TIMEOUT, `node did not answer /v1/identity within ${timeoutMs} ms`);
    }
    throw new DatuError(ErrorCode.NODE_ERROR, `cannot reach node at ${base}: ${String((e && e.message) || e)}`);
  } finally {
    if (timer) clearTimeout(timer);
  }
  if (!res.ok) {
    throw new DatuError(ErrorCode.NODE_ERROR, `node answered ${res.status} for /v1/identity/${short(pubkey)}`);
  }
  const chain = await res.json();
  if (!chain || typeof chain !== 'object' || !Array.isArray(chain.attestations)) {
    throw new DatuError(ErrorCode.NODE_ERROR, 'node returned a malformed identity chain');
  }
  if (chain.key && String(chain.key).toLowerCase() !== pubkey) {
    throw new DatuError(ErrorCode.NODE_ERROR, `chain is for ${short(chain.key)}, not the requested key`);
  }
  return chain;
}

const claimMatches = (claims, want) =>
  Object.entries(want || {}).every(([k, v]) => claims != null && String(claims[k]) === String(v));

/**
 * Does `chain` satisfy this requirement? Pure and synchronous so it can be
 * tested and composed; throws nothing, always returns
 * `{ ok, reason, vouchers }`. A voucher is the attestation that satisfied
 * every filter, so a caller can show exactly who stood behind the decision.
 *
 * Filters (all optional, all ANDed):
 *   roots        - only these attestor keys count (hex, case-insensitive)
 *   roles        - claims.role must be one of these
 *   claims       - every given claim must match exactly (strings)
 *   minCosigners - distinct cosigners required on the attestation
 *
 * A revoked attestation never vouches; a key revoked directly vouches for
 * nothing at all.
 */
export function requireAttestation(chain, options = {}) {
  const { roots = [], roles = [], claims = {}, minCosigners = 0 } = options;
  if (!chain || !Array.isArray(chain.attestations)) {
    return {
      ok: false,
      reason: 'no identity chain: connect a ledger node and look the key up before trusting it',
      vouchers: [],
    };
  }
  const keyRevoke = chain.revoked_by_key;
  if (keyRevoke && keyRevoke.by) {
    return {
      ok: false,
      reason: `key revoked directly by ${short(keyRevoke.by)}${keyRevoke.reason ? ` - ${keyRevoke.reason}` : ''}`,
      vouchers: [],
    };
  }
  const rootSet = new Set(roots.map((r) => String(r).toLowerCase()));
  const roleSet = new Set(roles.map(String));
  const vouchers = [];
  let sawLive = false;
  let sawRevoked = false;
  for (const a of chain.attestations) {
    if (!a || typeof a !== 'object') continue;
    if (a.revoked) {
      sawRevoked = true;
      continue;
    }
    sawLive = true;
    const by = String(a.by || '').toLowerCase();
    if (rootSet.size && !rootSet.has(by)) continue;
    const attestationClaims = a.claims || {};
    if (roleSet.size && !roleSet.has(String(attestationClaims.role))) continue;
    if (!claimMatches(attestationClaims, claims)) continue;
    const cosigners = Array.isArray(a.cosigners) ? a.cosigners.length : 0;
    if (cosigners < minCosigners) continue;
    vouchers.push({
      by,
      label: a.label ?? null,
      claims: attestationClaims,
      cosigners,
      enroll: a.enroll ?? null,
    });
  }
  if (vouchers.length) return { ok: true, reason: null, vouchers };
  if (sawLive) {
    return {
      ok: false,
      reason: 'no attestation on this ledger satisfies the requirement (roots, roles, claims, cosigners)',
      vouchers: [],
    };
  }
  if (sawRevoked) {
    return { ok: false, reason: 'every attestation naming this key is revoked', vouchers: [] };
  }
  return {
    ok: false,
    reason: 'no attestation on this ledger names this key yet: signed in, unattested',
    vouchers: [],
  };
}

/**
 * Convenience composition: fetch the chain and apply the requirement in one
 * call. Transport failures throw (the caller must distinguish "unreachable"
 * from "unattested"); policy failures return `{ ok: false, reason }`.
 */
export async function checkAttestation(nodeUrl, pubkey, options = {}) {
  const chain = await fetchIdentityChain(nodeUrl, pubkey, options);
  return requireAttestation(chain, options);
}
