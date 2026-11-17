// Wallet RPC client: talks to the DATU browser wallet extension through the
// page <-> content-script postMessage bridge (inject.js). The extension queues
// each request, the human confirms it in the side panel with the passphrase,
// and only the signed result comes back here. The dApp never sees keys and
// never asks for a passphrase itself.

const PAGE = 'datu-dapp';
const WALLET = 'datu-wallet';

const pending = new Map();
const stateListeners = new Set();

window.addEventListener('message', (ev) => {
  const d = ev.data;
  if (!d || d.source !== WALLET) return;

  if (d.kind === 'state' && d.state) {
    for (const fn of stateListeners) {
      try {
        fn(d.state);
      } catch {}
    }
    return;
  }

  if (!d.id) return;
  const p = pending.get(d.id);
  if (!p) return;
  pending.delete(d.id);
  clearTimeout(p.timer);
  if (d.ok) {
    p.resolve({
      status: (d.result && d.result.status) || 200,
      body: (d.result && d.result.body) ?? d.result,
    });
  } else {
    p.reject(new Error(d.error || 'wallet rejected the request'));
  }
});

// The extension broadcasts {connected, wallets[], unlocked[]} at page load and
// whenever pairing or unlock state changes - the dApp stays in sync with it.
export function onWalletState(cb) {
  stateListeners.add(cb);
  return () => stateListeners.delete(cb);
}

function randomId() {
  return window.crypto && crypto.randomUUID
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function send(action, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const id = randomId();
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(
        new Error(
          'no answer from the wallet extension - load it (chrome://extensions) and reload this page'
        )
      );
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    window.postMessage({ source: PAGE, id, action, payload }, '*');
  });
}

export function walletPing() {
  return new Promise((resolve) => {
    const id = randomId();
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(false);
    }, 1500);
    pending.set(id, { resolve: () => resolve(true), reject: () => resolve(false), timer });
    window.postMessage({ source: PAGE, id, action: 'ping' }, '*');
  });
}

// One wallet signature. Pass `auto: true` in body for session re-login
// challenges - the extension answers those silently when the passphrase is
// already cached in the panel, and prompts otherwise.
export function walletSign({ bridgeUrl, path, body, summary }) {
  return send('sign', { bridgeUrl, path, body, summary }, 300000);
}

// Read-only identity listing: the extension already holds the bridge token,
// so the dApp never needs one pasted into it. Resolves to
// { identities, bridgeUrl }.
export async function walletIdentities(bridgeUrl) {
  const result = await send('identities', { bridgeUrl }, 15000);
  return result.body || result;
}

// Create a Signet identity for a dApp role (Registrar, Registry signer...).
// The extension relays the request to the bridge: the human chooses the
// passphrase in the side panel, the vault mints the keys, and only the
// public identity record comes back here. The dApp never sees a secret.
export function walletCreateIdentity({ bridgeUrl, name, summary }) {
  return send(
    'create',
    { bridgeUrl, path: '/v1/wallet/create', summary, body: { name } },
    300000
  );
}
