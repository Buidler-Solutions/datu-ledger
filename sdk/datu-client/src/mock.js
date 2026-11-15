/**
 * Test doubles: a fake Signet extension transport and a fake ledger node, so
 * a dApp's tests never need a wallet, a bridge or a running ledger.
 *
 *   const datu = await connect({ transport: mockTransport({ ... }) });
 */
import { AUTH_DOMAIN, authSignedBytes } from './auth.js';
import { PROVIDER_DOMAIN, providerProofBytes } from './provider.js';
import { DatuError, ErrorCode } from './errors.js';

/**
 * A fake extension transport. The `keys` map is identity name -> { publicKey,
 * privateKey } from node:crypto's generateKeyPairSync('ed25519'), or any object
 * with `sign(bytes)` returning a 64-byte signature and `pubkeyHex`.
 */
export function mockTransport({ identities = [], keys = {}, proofKey = null, state = null, latencyMs = 0 } = {}) {
  const listeners = new Set();
  const calls = [];
  const delay = () => new Promise((resolve) => setTimeout(resolve, latencyMs));

  return {
    calls,
    ping: async () => ({ pong: true, version: 'mock' }),
    identities: async () => ({ identities }),
    prove: async ({ nonce } = {}) => {
      calls.push({ path: '/v1/provider-proof', body: { nonce } });
      await delay();
      if (state && state.fail) throw new Error(state.fail.message);
      if (!proofKey) {
        throw new Error('no Signet paired - open the panel and pair first');
      }
      const proof = {
        ok: true,
        domain: PROVIDER_DOMAIN,
        nonce,
        origin: 'chrome-extension://mock',
        version: '0.2.0',
        expires_at_ms: Date.now() + 30_000,
      };
      return {
        ...proof,
        bridge_pubkey: proofKey.pubkeyHex,
        signature: await proofKey.sign(providerProofBytes(proof)),
        bridgeUrl: 'http://127.0.0.1:7588',
      };
    },
    sign: async ({ path, body }) => {
      calls.push({ path, body });
      await delay();
      // A plain Error on purpose: the SDK maps transport messages to stable
      // codes, and tests should exercise that mapping, not bypass it.
      if (state && state.fail) throw new Error(state.fail.message);
      if (path === '/v1/wallet/auth-assert') {
        const key = keys[body.name];
        if (!key) throw new DatuError(ErrorCode.REJECTED, `unknown identity ${body.name}`);
        const challenge = {
          rp_id: body.rp_id,
          origin: body.origin,
          nonce: body.nonce,
          expires_at_ms: body.expires_at_ms,
        };
        const signature = await key.sign(authSignedBytes(challenge));
        return {
          status: 200,
          body: {
            ok: true,
            domain: AUTH_DOMAIN,
            ...challenge,
            pubkey: key.pubkeyHex,
            signature,
            grant: 'mock-grant',
            grant_expires_at_ms: Date.now() + 900_000,
          },
        };
      }
      return { status: 200, body: { ok: true, path, ...body } };
    },
    onState: (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

/** A fake ledger node: `routes` maps path -> (body) => json. */
export function mockFetch({ routes = {}, nodeUrl = 'http://127.0.0.1:7474' } = {}) {
  const requests = [];
  const fetchImpl = async (url, options = {}) => {
    const path = String(url).replace(nodeUrl, '');
    requests.push({ path, method: options.method || 'GET', body: options.body });
    const handler = routes[path.split('?')[0]];
    if (!handler) {
      return {
        ok: false,
        status: 404,
        text: async () => JSON.stringify({ error: `no route for ${path}` }),
      };
    }
    const json = await handler(options.body ? JSON.parse(options.body) : undefined, path);
    return { ok: true, status: 200, text: async () => JSON.stringify(json) };
  };
  return { fetchImpl, requests };
}
