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

  if (msg && (msg.kind === 'datu-webauthn-suspend' || msg.kind === 'datu-webauthn-resume')) {
    // The panel runs its own device-passkey ceremonies with the virtual
    // authenticator detached, so they reach the real platform authenticator.
    (async () => {
      adjustProxySuspension(msg.kind === 'datu-webauthn-suspend' ? 1 : -1);
      await syncProxyAttachment();
      sendResponse({ ok: true });
    })();
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
// Chrome 115+ exposes chrome.webAuthenticationProxy: while this extension is
// attached, every navigator.credentials ceremony in the browser is routed
// here and forwarded to the paired Signet bridge, which answers with the
// identity's Ed25519 key (datu_core::auth_webauthn). The bridge needs an
// unlocked session grant (minted by a passphrase or passkey unlock in the
// panel); while no grant is live the proxy stays detached, so the browser's
// real passkeys keep working.
//
// API shape (developer.chrome.com, webAuthenticationProxy): the events are
// onCreateRequest / onGetRequest and receive { requestId, requestDetailsJson },
// where requestDetailsJson is the toJSON() form of the options dictionary.
// Completion takes { requestId, responseJson } with base64url fields, and
// the extension itself builds clientDataJSON: the options carry no origin,
// so the requesting page's origin is recovered from the active tab.
importScripts('webauthn.js');

const proxy = globalThis.chrome && chrome.webAuthenticationProxy;
const proxyLog = (...args) => console.info('[webauthn-proxy]', ...args);

// The panel persists its SignetAuth grants here so the proxy can spend one
// without another prompt; the grant itself expires in 15 minutes.
async function activeGrant() {
  const s = await chrome.storage.session.get(['datuGrants', 'tokens']);
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

// clientDataJSON must name the requesting page or relying parties reject the
// assertion; the options JSON does not carry it, so use the active tab.
async function ceremonyOrigin() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab && tab.url) return new URL(tab.url).origin;
  } catch {}
  return null;
}

let proxyAttached = false;
let proxySuspended = 0; // the panel's own passkey ceremonies suspend the proxy

function adjustProxySuspension(delta) {
  proxySuspended = Math.max(0, proxySuspended + delta);
}

async function syncProxyAttachment() {
  if (!proxy) return;
  const want = proxySuspended === 0 && !!(await activeGrant());
  if (want === proxyAttached) return;
  try {
    if (want) await proxy.attach();
    else await proxy.detach();
    proxyAttached = want;
    proxyLog(want ? 'attached: passkey ceremonies route to the Signet' : 'detached');
  } catch (e) {
    proxyAttached = false;
    proxyLog('attach/detach failed:', e.message);
  }
}

function wireWebAuthnProxy() {
  if (!proxy) return; // older Chrome: the SignetAuth assertion flow still works
  const W = globalThis.datuWebauthn;

  proxy.onCreateRequest.addListener(async (details) => {
    try {
      const request = JSON.parse(details.requestDetailsJson || '{}');
      proxyLog('create request for rp', (request.rp && request.rp.id) || '(unnamed)');
      const origin = await ceremonyOrigin();
      if (!origin) throw new Error('cannot determine the requesting origin');
      const session = await activeGrant();
      if (!session) throw new Error('unlock the DATU Signet panel first (passphrase or passkey)');
      const rpId = (request.rp && request.rp.id) || new URL(origin).hostname;
      const created = await bridgeCall(session, '/v1/wallet/webauthn-create', {
        name: session.name,
        grant: session.grant,
        rp_id: rpId,
        user_name:
          (request.user && (request.user.name || request.user.displayName)) || session.name,
      });
      const responseJson = await W.createResponseJson({
        request,
        origin,
        credentialIdHex: created.credential_id,
        coseB64: created.public_key_cose_b64,
        alg: typeof created.alg === 'number' ? created.alg : -8,
      });
      await proxy.completeCreateRequest({
        requestId: details.requestId,
        responseJson: JSON.stringify(responseJson),
      });
      proxyLog('created credential for', rpId, 'at', origin);
    } catch (e) {
      await proxy
        .completeCreateRequest({
          requestId: details.requestId,
          error: { name: 'NotAllowedError', message: e.message },
        })
        .catch(() => {});
      proxyLog('create failed:', e.message);
    }
  });

  proxy.onGetRequest.addListener(async (details) => {
    try {
      const request = JSON.parse(details.requestDetailsJson || '{}');
      const allow = request.allowCredentials || [];
      if (!allow.length) throw new Error('this authenticator only answers allowCredentials requests');
      const origin = await ceremonyOrigin();
      if (!origin) throw new Error('cannot determine the requesting origin');
      const session = await activeGrant();
      if (!session) throw new Error('unlock the DATU Signet panel first (passphrase or passkey)');
      const rpId = request.rpId || new URL(origin).hostname;
      const clientData = W.clientData('webauthn.get', request.challenge, origin);
      const signed = await bridgeCall(session, '/v1/wallet/webauthn-get', {
        name: session.name,
        grant: session.grant,
        rp_id: rpId,
        credential_id: W.b64uToHex(allow[0].id),
        client_data_json_b64: W.bytesToB64(W.utf8(JSON.stringify(clientData))),
      });
      const responseJson = W.getResponseJson({
        request,
        origin,
        credentialIdB64u: allow[0].id,
        authenticatorDataB64: signed.authenticator_data_b64,
        signatureB64: signed.signature_b64,
      });
      await proxy.completeGetRequest({
        requestId: details.requestId,
        responseJson: JSON.stringify(responseJson),
      });
      proxyLog('assertion signed for', rpId, 'at', origin);
    } catch (e) {
      await proxy
        .completeGetRequest({
          requestId: details.requestId,
          error: { name: 'NotAllowedError', message: e.message },
        })
        .catch(() => {});
      proxyLog('get failed:', e.message);
    }
  });

  // While attached, isUserVerifyingPlatformAuthenticatorAvailable() would
  // otherwise hang: answer it from unlock state.
  proxy.onIsUvpaaRequest.addListener(async (details) => {
    const isUvpaa = !!(await activeGrant().catch(() => null));
    await proxy.completeIsUvpaaRequest({ requestId: details.requestId, isUvpaa }).catch(() => {});
  });

  proxy.onRequestCanceled.addListener((requestId) => proxyLog('request canceled', requestId));

  // Attach exactly while an unlock is live; grants live in session storage,
  // so expiry or panel lock-out detaches the proxy again.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'session' && (changes.datuGrants || changes.tokens)) syncProxyAttachment();
  });
  syncProxyAttachment();
}

try {
  wireWebAuthnProxy();
} catch (e) {
  console.warn('webAuthenticationProxy unavailable:', e.message);
}
