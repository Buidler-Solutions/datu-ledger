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
const setBadge = async (n) => {
  try {
    await chrome.action.setBadgeText({ text: n ? String(n) : '' });
    if (n) await chrome.action.setBadgeBackgroundColor({ color: '#d29922' });
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
      if (sender.tab && chrome.sidePanel.open) {
        chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
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
