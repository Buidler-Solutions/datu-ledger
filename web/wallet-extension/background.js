// Open the wallet as a docked side panel when the toolbar icon is clicked,
// MetaMask-style: the panel slides in on the right of the current tab.
const enableSidePanel = () =>
  chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: true })
    .catch((e) => console.warn("side panel behavior:", e));

if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
  enableSidePanel();
  chrome.runtime.onInstalled.addListener(enableSidePanel);
  chrome.runtime.onStartup.addListener(enableSidePanel);
}

// ---------- dApp sign-request relay ----------
// A dApp page (content script inject.js) posts {kind:'datu-rpc', action:'sign'}
// here. Sign requests are queued in session storage; the side panel renders
// them, the user confirms with the passphrase, and the result travels back to
// the originating tab. Keys and passphrases never leave the extension/bridge.
const QUEUE_KEY = 'datuRpcQueue';
const STATE_KEY = 'datuWalletState';

const readQueue = async () => {
  const o = await chrome.storage.session.get(QUEUE_KEY);
  return o[QUEUE_KEY] || [];
};
const writeQueue = async (q) => chrome.storage.session.set({ [QUEUE_KEY]: q });
const setBadge = async (n, tabId) => {
  const scoped = tabId != null ? { tabId } : {};
  try {
    await chrome.action.setBadgeText({ ...scoped, text: n ? String(n) : '' });
    if (n) await chrome.action.setBadgeBackgroundColor({ ...scoped, color: '#d29922' });
  } catch {}
};

// What dApps are allowed to know: which wallets exist, which are paired, and
// which identities are unlocked in the panel right now (names only).
async function currentState() {
  const s = await chrome.storage.session.get(['wallets', 'tokens', STATE_KEY]);
  const wallets = s.wallets || [];
  const tokens = s.tokens || {};
  const unlocked = (s[STATE_KEY] || {}).unlocked || [];
  return {
    connected: true,
    version: chrome.runtime.getManifest().version,
    wallets: wallets.map((w) => ({ label: w.label, url: w.url, paired: !!tokens[w.url] })),
    unlocked,
  };
}

function broadcast(state) {
  chrome.tabs.query({}, (tabs) => {
    for (const t of tabs) {
      if (t.id == null) continue;
      try {
        chrome.tabs.sendMessage(t.id, { kind: 'datu-state', state }).catch?.(() => {});
      } catch {}
    }
  });
}

// A dApp request needs the user's attention: slide the side panel open.
// Chrome only permits sidePanel.open() from a service worker in response to an
// extension event (Chrome 116+). If every avenue fails we log the real error
// and flash a tab-scoped badge so the failure is diagnosable, not silent.
async function tryOpenSidePanel(tab, queueLength) {
  if (!chrome.sidePanel || !chrome.sidePanel.open) return;
  const tabId = tab.id;
  try {
    if (chrome.sidePanel.setOptions) {
      await chrome.sidePanel.setOptions({ tabId, enabled: true, path: 'panel.html' });
    }
    await chrome.sidePanel.open({ tabId });
    return;
  } catch (e) {
    console.warn('sidePanel.open failed (tabId):', e?.message || e);
  }
  if (tab.windowId != null) {
    try {
      await chrome.sidePanel.open({ windowId: tab.windowId });
      return;
    } catch (e) {
      console.warn('sidePanel.open failed (windowId):', e?.message || e);
    }
  }
  await setBadge(queueLength, tabId);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.kind === 'datu-hello') {
    currentState().then((state) => sendResponse({ ok: true, result: state }));
    return true;
  }

  if (msg && msg.kind === 'datu-state-changed') {
    (async () => {
      const unlocked = Array.isArray(msg.unlocked) ? msg.unlocked : [];
      await chrome.storage.session.set({ [STATE_KEY]: { unlocked, at: Date.now() } });
      const state = await currentState();
      broadcast(state);
      sendResponse({ ok: true, result: state });
    })();
    return true;
  }

  if (msg && msg.kind === 'datu-rpc') {
    if (msg.action === 'ping') {
      sendResponse({
        ok: true,
        result: { pong: true, version: chrome.runtime.getManifest().version },
      });
      return false;
    }
    // Read-only identity listing: the extension already holds the bridge
    // token, so a dApp never has to paste one. Public keys only, no prompt.
    if (msg.action === 'identities') {
      (async () => {
        try {
          const url = String((msg.payload || {}).bridgeUrl || '')
            .replace(/\/+$/, '');
          const s = await chrome.storage.session.get(['tokens']);
          const token = (s.tokens || {})[url];
          if (!token) {
            // Fall back to any paired Signet when the dApp has no preference.
            const first = Object.entries(s.tokens || {})[0] || [];
            if (!first[0]) throw new Error('no Signet paired - open the panel and pair first');
            const res = await fetch(`${first[0].replace(/\/+$/, '')}/v1/wallet/identities`, {
              headers: { Authorization: `Bearer ${first[1]}` },
            });
            const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
            if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
            sendResponse({ ok: true, result: { identities: json.identities || [], bridgeUrl: first[0] } });
            return;
          }
          const res = await fetch(`${url}/v1/wallet/identities`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
          if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
          sendResponse({ ok: true, result: { identities: json.identities || [], bridgeUrl: url } });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
      })();
      return true;
    }
    (async () => {
      const queue = await readQueue();
      queue.push({
        id: msg.id,
        tabId: sender.tab ? sender.tab.id : null,
        at: Date.now(),
        action: msg.action,
        payload: msg.payload,
      });
      await writeQueue(queue);
      await setBadge(queue.length);
      sendResponse({ queued: true });
      if (sender.tab) {
        await tryOpenSidePanel(sender.tab, queue.length);
      }
    })();
    return true;
  }

  if (msg && msg.kind === 'datu-result') {
    (async () => {
      const queue = await readQueue();
      const req = queue.find((r) => r.id === msg.id);
      const rest = queue.filter((r) => r.id !== msg.id);
      await writeQueue(rest);
      await setBadge(rest.length);
      if (req && req.tabId != null) await setBadge(rest.length, req.tabId);
      if (req && req.tabId != null) {
        try {
          await chrome.tabs.sendMessage(req.tabId, {
            kind: 'datu-rpc-result',
            id: msg.id,
            ok: msg.ok,
            error: msg.error,
            result: msg.result,
          });
        } catch {}
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  return false;
});

// ---------- SignetAuth Level 3a: WebAuthn proxy (virtual authenticator) ----------
// Chrome 133+ exposes chrome.webAuthenticationProxy, letting an extension
// answer navigator.credentials.create/get on behalf of an authenticator. We
// forward to the paired Signet bridge, which signs with the identity's
// Ed25519 key (datu_core::auth_webauthn). The bridge needs an unlocked
// session (a grant minted by a passphrase or passkey unlock in the panel);
// without one, the ceremony fails closed and the Relying Party falls back.
//
// Format notes: our authenticator is synced-credential grade: attestation
// format "none", UP|UV flags set, signCount 0 (no per-credential state).

const b64uToBytes = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
  return Uint8Array.from(atob(t + pad), (c) => c.charCodeAt(0));
};
const bytesToB64u = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const utf8 = (s) => new TextEncoder().encode(s);

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// Minimal CTAP2 canonical CBOR for the fields WebAuthn needs (integers,
// text and byte strings, small maps/arrays).
function cborUint(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 0x100) return [major << 5 | 24, n];
  if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff];
  return [major << 5 | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}
const cborBytes = (bytes) => [...cborUint(2, bytes.length), ...bytes];
const cborText = (text) => {
  const bytes = utf8(text);
  return [...cborUint(3, bytes.length), ...bytes];
};

async function attestationObject(rpId, credentialIdHex, coseB64) {
  const rpIdHash = await sha256(utf8(rpId));
  const authData = new Uint8Array([
    ...rpIdHash,
    0x45, // UP | UV | AT
    0, 0, 0, 0, // signCount
    ...new Uint8Array(16), // AAGUID (all zero: no model identity)
    (credentialIdHex.length / 2) >> 8,
    (credentialIdHex.length / 2) & 0xff,
    ...Uint8Array.from(credentialIdHex.match(/../g).map((h) => parseInt(h, 16))),
    ...Uint8Array.from(atob(coseB64), (c) => c.charCodeAt(0)),
  ]);
  return Uint8Array.from([
    0xa3, // map(3)
    ...cborText('fmt'), ...cborText('none'),
    ...cborText('attStmt'), 0xa0,
    ...cborText('authData'), ...cborBytes(authData),
  ]);
}

// The panel persists its SignetAuth grants here so the proxy can spend one
// without another prompt; the grant itself expires in 15 minutes.
async function activeGrant() {
  const s = await chrome.storage.session.get(['datuGrants', 'wallets', 'activeWallet', 'tokens']);
  const grants = s.datuGrants || {};
  for (const [url, byName] of Object.entries(grants)) {
    const token = (s.tokens || {})[url];
    const [name, grant] = Object.entries(byName || {})[0] || [];
    if (token && name && grant) return { url: url.replace(/\/+$/, ''), token, name, grant };
  }
  return null;
}

async function bridgeCall({ url, token }, path, body) {
  const res = await fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}

function wireWebAuthnProxy() {
  const proxy = chrome.webAuthenticationProxy;
  if (!proxy) return; // older Chrome: the SignetAuth assertion flow still works
  const log = (...args) => console.info('[webauthn-proxy]', ...args);

  proxy.onRequestCreateRequest.addListener(async (details) => {
    try {
      const request = JSON.parse(details.requestDetailsJson || '{}');
      const pk = request.publicKey || request;
      const rpId = pk.rp?.id || new URL(request.origin || `https://${'localhost'}`).hostname;
      const session = await activeGrant();
      if (!session) throw new Error('unlock the DATU Signet panel first (passphrase or passkey)');
      const created = await bridgeCall(session, '/v1/wallet/webauthn-create', {
        name: session.name,
        grant: session.grant,
        rp_id: rpId,
        user_name: pk.user?.name || session.name,
      });
      const attestation = await attestationObject(rpId, created.credential_id, created.public_key_cose_b64);
      const responseJson = {
        id: bytesToB64u(b64uToBytes(created.credential_id)),
        rawId: bytesToB64u(Uint8Array.from(created.credential_id.match(/../g).map((h) => parseInt(h, 16)))),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: request.clientDataJson || pk.challenge || '',
          attestationObject: bytesToB64u(attestation),
          transports: ['internal'],
        },
      };
      await proxy.completeCreateRequest({ requestId: details.requestId, responseJson: JSON.stringify(responseJson) });
      log('created credential for', rpId);
    } catch (e) {
      await proxy.completeCreateRequest({ requestId: details.requestId, error: { name: 'NotAllowedError', message: e.message } });
      log('create failed:', e.message);
    }
  });

  proxy.onRequestGetRequest.addListener(async (details) => {
    try {
      const request = JSON.parse(details.requestDetailsJson || '{}');
      const pk = request.publicKey || request;
      const rpId = pk.rpId || new URL(request.origin || 'https://localhost').hostname;
      const allow = pk.allowCredentials || [];
      if (!allow.length) throw new Error('this authenticator only answers allowCredentials requests');
      const credentialIdHex = Array.from(b64uToBytes(allow[0].id))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const session = await activeGrant();
      if (!session) throw new Error('unlock the DATU Signet panel first (passphrase or passkey)');
      const clientDataJSON = {
        type: 'webauthn.get',
        challenge: allow[0].clientChallenge || pk.challenge,
        origin: request.origin,
        crossOrigin: false,
      };
      const clientDataB64 = btoa(JSON.stringify(clientDataJSON));
      const signed = await bridgeCall(session, '/v1/wallet/webauthn-get', {
        name: session.name,
        grant: session.grant,
        rp_id: rpId,
        credential_id: credentialIdHex,
        client_data_json_b64: clientDataB64,
      });
      const responseJson = {
        id: allow[0].id,
        rawId: allow[0].id,
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: bytesToB64u(utf8(JSON.stringify(clientDataJSON))),
          authenticatorData: signed.authenticator_data_b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
          signature: signed.signature_b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
          userHandle: null,
        },
      };
      await proxy.completeGetRequest({ requestId: details.requestId, responseJson: JSON.stringify(responseJson) });
      log('assertion signed for', rpId);
    } catch (e) {
      await proxy.completeGetRequest({ requestId: details.requestId, error: { name: 'NotAllowedError', message: e.message } });
      log('get failed:', e.message);
    }
  });

  // Attach lazily: attachment without requests is harmless, and Chrome
  // re-attaches on startup when the API is present.
  proxy.attach({}).catch(() => {});
}

try {
  wireWebAuthnProxy();
} catch (e) {
  console.warn('webAuthenticationProxy unavailable:', e.message);
}
