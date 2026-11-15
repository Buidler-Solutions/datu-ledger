/**
 * Extension transport: talks to the DATU Signet browser extension over the
 * page postMessage bridge (the extension relays to the local Signet service).
 * Keys never enter this page; the extension holds the pairing token, so a dApp
 * never needs one.
 */
import { DatuError, ErrorCode, mapError } from './errors.js';

const PAGE = 'datu-dapp';
const WALLET = 'datu-wallet';
const DEFAULT_TIMEOUT_MS = 5 * 60_000;

function randomId() {
  const c = globalThis.crypto;
  if (c && c.randomUUID) return c.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Create an RPC transport over the extension bridge.
 * Options:
 *   timeoutMs  - per request, default 5 minutes (a human approves each sign)
 *   pingMs     - ping timeout, default 1500
 */
export function createExtensionTransport({ timeoutMs = DEFAULT_TIMEOUT_MS, pingMs = 1500 } = {}) {
  const pending = new Map();
  const stateListeners = new Set();
  let listening = false;

  function ensureListener() {
    if (listening || typeof window === 'undefined') return;
    listening = true;
    window.addEventListener('message', (event) => {
      const data = event && event.data;
      if (!data || data.source !== WALLET) return;
      if (data.kind === 'state' && data.state) {
        for (const fn of stateListeners) {
          try {
            fn(data.state);
          } catch {
            /* a listener must never break the transport */
          }
        }
        return;
      }
      if (!data.id) return;
      const waiter = pending.get(data.id);
      if (!waiter) return;
      pending.delete(data.id);
      clearTimeout(waiter.timer);
      if (data.ok) {
        waiter.resolve({
          status: (data.result && data.result.status) || 200,
          body: (data.result && data.result.body) ?? data.result,
        });
      } else {
        waiter.reject(mapError(data.error || 'wallet rejected the request', ErrorCode.REJECTED));
      }
    });
  }

  function send(action, payload, timeout) {
    ensureListener();
    if (typeof window === 'undefined' || !window.postMessage) {
      return Promise.reject(
        new DatuError(ErrorCode.NOT_CONNECTED, 'no window: the extension transport is browser-only'),
      );
    }
    return new Promise((resolve, reject) => {
      const id = randomId();
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(
          new DatuError(
            ErrorCode.TIMEOUT,
            action === 'identities'
              ? 'no answer from the Signet extension - update it to 1.6.0 or newer (it brokers identity listing) and reload the page'
              : 'no answer from the Signet extension - load it (chrome://extensions) and reload this page',
          ),
        );
      }, timeout);
      pending.set(id, { resolve, reject, timer });
      window.postMessage({ source: PAGE, id, action, payload }, '*');
    });
  }

  return {
    ping: () =>
      send('ping', undefined, pingMs).then(
        (result) => result.body || {},
        () => null,
      ),
    identities: async (bridgeUrl) => {
      const result = await send('identities', { bridgeUrl }, 15_000);
      return result.body || result;
    },
    prove: async ({ bridgeUrl, nonce } = {}) => {
      const result = await send('prove', { bridgeUrl, nonce }, 15_000);
      return result.body || result;
    },
    sign: ({ bridgeUrl, path, body, summary }) =>
      send('sign', { bridgeUrl, path, body, summary }, timeoutMs),
    onState: (fn) => {
      ensureListener();
      stateListeners.add(fn);
      return () => stateListeners.delete(fn);
    },
  };
}
