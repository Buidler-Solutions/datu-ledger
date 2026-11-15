// Side panel scoping tests: the panel belongs only to the tab AND origin
// that initialized it (toolbar click there, or a dApp sign request from that
// tab). Chrome has no programmatic close, so the scope is enforced by a
// global enabled:false default plus per-tab opt-ins; Chrome then hides the
// panel on any tab that never opted in. Per-tab options survive navigation,
// so the worker also follows the tab: navigating off the origin disables the
// panel for that tab. These tests stub chrome and boot the real background.js
// service worker script.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const listeners = {
  actionClicked: [],
  onInstalled: [],
  onStartup: [],
  onMessage: [],
  tabUpdated: [],
  tabRemoved: [],
  tabReplaced: [],
};
const calls = {
  setPanelBehavior: [],
  setOptions: [],
  open: [],
  badgeText: [],
  badgeColor: [],
};
const sessionStore = {};
const tabById = {};

// Per-test knobs: make sidePanel.open reject for a given tabId/windowId to
// exercise the fallback chain in tryOpenSidePanel.
let failOpenTabId = null;
let failOpenWindowId = null;

const capture = (name) => async (arg) => {
  calls[name].push(arg);
};
const eventStub = (arr) => ({ addListener: (fn) => arr.push(fn) });

globalThis.chrome = {
  sidePanel: {
    setPanelBehavior: capture('setPanelBehavior'),
    setOptions: capture('setOptions'),
    open: async (o) => {
      calls.open.push(o); // record every attempt, successful or refused
      if (o && o.tabId === failOpenTabId) throw new Error('gesture required');
      if (o && o.windowId === failOpenWindowId) throw new Error('gesture required');
    },
  },
  action: {
    onClicked: eventStub(listeners.actionClicked),
    setBadgeText: capture('badgeText'),
    setBadgeBackgroundColor: capture('badgeColor'),
  },
  runtime: {
    onInstalled: eventStub(listeners.onInstalled),
    onStartup: eventStub(listeners.onStartup),
    onMessage: eventStub(listeners.onMessage),
    getManifest: () => ({ version: 'test' }),
  },
  tabs: {
    query: async () => [],
    get: async (id) => {
      if (!(id in tabById)) throw new Error(`no tab ${id}`);
      return tabById[id];
    },
    sendMessage: async () => {},
    onUpdated: eventStub(listeners.tabUpdated),
    onRemoved: eventStub(listeners.tabRemoved),
    onReplaced: eventStub(listeners.tabReplaced),
  },
  storage: {
    session: {
      get: async (keys) => {
        const out = {};
        for (const k of [].concat(keys)) if (k in sessionStore) out[k] = sessionStore[k];
        return out;
      },
      set: async (o) => Object.assign(sessionStore, o),
    },
    onChanged: eventStub([]),
  },
};
globalThis.importScripts = () => {};

// Pre-seed what a previous worker session persisted: tab 5 enabled the panel
// on http://a.example but has since navigated to b.example (reconcile path),
// tab 6 enabled it and is still on its origin (no-op path).
sessionStore.datuPanelTabs = {
  5: { origin: 'http://a.example', live: true },
  6: { origin: 'http://c.example', live: true },
};
tabById[5] = { id: 5, url: 'https://b.example/page' };
tabById[6] = { id: 6, url: 'http://c.example/still-here' };

const flush = () => new Promise((r) => setTimeout(r, 20));

await import('../background.js');
await flush(); // initSidePanel() runs unawaited at worker startup

test('worker startup disables the side panel globally', () => {
  assert.deepEqual(calls.setOptions[0], { enabled: false });
  const off = calls.setOptions.filter((o) => o.enabled === false && o.tabId === undefined);
  assert.ok(off.length >= 1);
});

test('startup reconcile disables panels whose tab drifted off its origin', () => {
  assert.ok(calls.setOptions.some((o) => o.tabId === 5 && o.enabled === false));
  assert.deepEqual(sessionStore.datuPanelTabs[5], { origin: 'http://a.example', live: false });
  // still on its origin: untouched
  assert.equal(
    calls.setOptions.filter((o) => o.tabId === 6).length,
    0
  );
});

test('a toolbar click opens the panel scoped to that tab and origin', async () => {
  listeners.actionClicked[0]({ id: 7, url: 'http://localhost:5173/registrar' });
  await flush();
  assert.deepEqual(calls.setOptions.at(-1), { tabId: 7, enabled: true, path: 'panel.html' });
  assert.deepEqual(calls.open.at(-1), { tabId: 7 });
  assert.deepEqual(sessionStore.datuPanelTabs[7], {
    origin: 'http://localhost:5173',
    live: true,
  });
});

test('same-origin navigation keeps the panel on the tab', async () => {
  const before = calls.setOptions.length;
  listeners.tabUpdated[0](
    7,
    { url: 'http://localhost:5173/entry/42' },
    { id: 7, url: 'http://localhost:5173/entry/42' }
  );
  await flush();
  assert.equal(calls.setOptions.length, before);
});

test('navigating the tab to another origin disables the panel there', async () => {
  listeners.tabUpdated[0](
    7,
    { url: 'https://example.com/unrelated' },
    { id: 7, url: 'https://example.com/unrelated' }
  );
  await flush();
  assert.deepEqual(calls.setOptions.at(-1), { tabId: 7, enabled: false });
  assert.deepEqual(sessionStore.datuPanelTabs[7], {
    origin: 'http://localhost:5173',
    live: false,
  });
});

test('navigating back to the origin re-enables the panel (no popup)', async () => {
  listeners.tabUpdated[0](
    7,
    { url: 'http://localhost:5173/back' },
    { id: 7, url: 'http://localhost:5173/back' }
  );
  await flush();
  assert.deepEqual(calls.setOptions.at(-1), { tabId: 7, enabled: true, path: 'panel.html' });
  assert.deepEqual(sessionStore.datuPanelTabs[7], {
    origin: 'http://localhost:5173',
    live: true,
  });
});

test('closing the tab forgets its panel entry', async () => {
  listeners.tabRemoved[0](7);
  await flush();
  assert.equal('7' in sessionStore.datuPanelTabs, false);
});

test('a dApp sign request opens the panel for the requesting tab only', async () => {
  const sent = [];
  listeners.onMessage[0](
    { kind: 'datu-rpc', action: 'sign', id: 'req-1', payload: { hello: 1 } },
    { tab: { id: 8, windowId: 1, url: 'http://localhost:5174/dapp' } },
    (r) => sent.push(r)
  );
  await flush();
  assert.deepEqual(calls.setOptions.at(-1), { tabId: 8, enabled: true, path: 'panel.html' });
  assert.deepEqual(calls.open.at(-1), { tabId: 8 });
  assert.deepEqual(sent, [{ queued: true }]);
  const queue = sessionStore.datuRpcQueue;
  assert.equal(queue.length, 1);
  assert.equal(queue[0].tabId, 8);
  assert.deepEqual(sessionStore.datuPanelTabs[8], {
    origin: 'http://localhost:5174',
    live: true,
  });
});

test('a refused per-tab open retries by window, then falls back to a badge', async () => {
  failOpenTabId = 9;
  failOpenWindowId = 2;
  const sent = [];
  listeners.onMessage[0](
    { kind: 'datu-rpc', action: 'sign', id: 'req-2', payload: {} },
    { tab: { id: 9, windowId: 2, url: 'http://localhost:5174/no-gesture' } },
    (r) => sent.push(r)
  );
  await flush();
  // the request still queued and answered
  assert.deepEqual(sent, [{ queued: true }]);
  assert.equal(sessionStore.datuRpcQueue.length, 2);
  // window retry was attempted before giving up
  assert.ok(calls.open.some((o) => o && o.windowId === 2));
  // last resort: a tab-scoped badge so the failure is visible, not silent
  const scoped = calls.badgeText.filter((o) => o.tabId === 9);
  assert.ok(scoped.length >= 1);
  assert.deepEqual(scoped.at(-1), { tabId: 9, text: '2' });
});

test('prove answers a genuineness challenge with a paired bridge POST', async () => {
  const savedFetch = globalThis.fetch;
  const fetched = [];
  const proof = {
    ok: true,
    domain: 'datu-provider-v1',
    nonce: 'ab'.repeat(16),
    origin: 'chrome-extension://t',
    version: '0.2.0',
    expires_at_ms: Date.now() + 30_000,
    bridge_pubkey: '00'.repeat(32),
    signature: '00'.repeat(64),
  };
  globalThis.fetch = async (url, options = {}) => {
    fetched.push({ url, options });
    return { ok: true, status: 200, json: async () => proof };
  };
  try {
    sessionStore.tokens = { 'http://127.0.0.1:7588': 'tok' };
    sessionStore.activeWallet = 'http://127.0.0.1:7588';
    const sent = [];
    listeners.onMessage[0](
      { kind: 'datu-rpc', action: 'prove', id: 'prove-1', payload: { nonce: 'ab'.repeat(16) } },
      { tab: { id: 12, url: 'http://localhost:5174/dapp' } },
      (r) => sent.push(r)
    );
    await flush();
    assert.equal(fetched.length, 1);
    assert.equal(fetched[0].url, 'http://127.0.0.1:7588/v1/provider-proof');
    assert.equal(fetched[0].options.method, 'POST');
    assert.equal(fetched[0].options.headers.Authorization, 'Bearer tok');
    assert.equal(JSON.parse(fetched[0].options.body).nonce, 'ab'.repeat(16));
    assert.deepEqual(sent, [{ ok: true, result: { ...proof, bridgeUrl: 'http://127.0.0.1:7588' } }]);
  } finally {
    globalThis.fetch = savedFetch;
    delete sessionStore.tokens;
    delete sessionStore.activeWallet;
  }
});

test('the panel is never enabled globally and never via setPanelBehavior', () => {
  assert.equal(calls.setPanelBehavior.length, 0);
  for (const o of calls.setOptions) {
    if (o.enabled === true) {
      assert.ok(o.tabId != null, `global enable leaked: ${JSON.stringify(o)}`);
    }
  }
});
