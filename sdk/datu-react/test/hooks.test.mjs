// Hook tests under a jsdom document with a mocked Signet transport, exactly
// how a dApp renders: provider connects, identities load, signIn signs and
// locally verifies, coverage reloads from a mocked node.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', {
  url: 'http://localhost:5173/',
});
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });
Object.defineProperty(globalThis, 'location', { value: dom.window.location, configurable: true });

const React = await import('react');
const { act } = React;
const { createRoot } = await import('react-dom/client');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const { mockTransport, mockFetch } = await import('@greenarmor/datu-client/mock');
const {
  DatuProvider,
  useDatu,
  useIdentities,
  useSignIn,
  usePartySign,
  useCoverage,
} = await import('../src/index.js');

const { createElement, useEffect } = React;

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubkeyHex = publicKey
  .export({ type: 'spki', format: 'der' })
  .toString('hex')
  .slice(-64);
const key = {
  pubkeyHex,
  sign: (bytes) => cryptoSign(null, bytes, privateKey).toString('hex'),
};
const transport = mockTransport({
  identities: [{ name: 'amina', ed_public: pubkeyHex }],
  keys: { amina: key },
});
const node = mockFetch({
  routes: {
    '/v1/coverage/abc123': () => ({
      witnesses: [{ witness: 'demo', checkpoint_id: 'cp1' }],
      stale: [],
    }),
  },
});

const waitFor = async (fn, ms = 1500) => {
  const start = Date.now();
  while (Date.now() - start < ms) {
    let done = false;
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10));
      done = Boolean(fn());
    });
    if (done || fn()) return true;
  }
  return Boolean(fn());
};

function render(element) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  root.render(element);
  return { root, unmount: () => { root.unmount(); container.remove(); }, container };
}

test('provider connects, lists identities, signs in and verifies', async () => {
  const captured = {};
  function Probe() {
    const datu = useDatu();
    const { identities, loading } = useIdentities();
    const { signIn, pending, result, error } = useSignIn();
    useEffect(() => {
      captured.datu = { connecting: datu.connecting, hasClient: !!datu.client };
    }, [datu.client]);
    useEffect(() => {
      if (!datu.client) return;
      signIn({ name: 'amina' }).catch((e) => {});
    }, [datu.client]);
    useEffect(() => {
      if (result) {
        captured.identities = identities;
        captured.loading = loading;
        captured.result = result;
        captured.pending = pending;
        captured.error = error;
      }
    }, [result]);
    return createElement('div', null, 'probe');
  }
  const ui = render(
    createElement(
      DatuProvider,
      { options: { transport, nodeUrl: 'http://127.0.0.1:7474', fetchImpl: node.fetchImpl } },
      createElement(Probe),
    ),
  );
  await waitFor(() => captured.result);
  assert.equal(captured.datu.hasClient, true);
  assert.equal(captured.datu.connecting, false);
  assert.equal(captured.identities.length, 1);
  assert.equal(captured.identities[0].name, 'amina');
  assert.equal(captured.result.verified, true);
  assert.equal(captured.result.assertion.pubkey, pubkeyHex);
  assert.equal(captured.error, null);
  ui.unmount();
});

test('useSignIn surfaces rejection errors from the transport', async () => {
  const captured = {};
  function Probe() {
    const { client } = useDatu();
    const { signIn, error } = useSignIn();
    useEffect(() => {
      if (!client) return;
      signIn({ name: 'ghost' }).catch(() => {});
    }, [client]);
    useEffect(() => {
      if (error) captured.error = error;
    }, [error]);
    return createElement('div');
  }
  const ui = render(
    createElement(
      DatuProvider,
      { options: { transport } },
      createElement(Probe),
    ),
  );
  await waitFor(() => captured.error);
  assert.ok(captured.error);
  assert.match(captured.error.message, /ghost/);
  ui.unmount();
});

test('usePartySign routes through the panel and useCoverage reads the node', async () => {
  const captured = {};
  function Probe() {
    const { client } = useDatu();
    const { partySign, result } = usePartySign();
    const coverage = useCoverage('abc123');
    useEffect(() => {
      if (!client) return;
      partySign({ name: 'amina', role: 'holder', document: 'doc-1' }).catch(() => {});
    }, [client]);
    useEffect(() => {
      if (result) captured.party = result;
    }, [result]);
    useEffect(() => {
      if (coverage.coverage) captured.coverage = coverage.coverage;
    }, [coverage.coverage]);
    return createElement('div');
  }
  const ui = render(
    createElement(
      DatuProvider,
      { options: { transport, fetchImpl: node.fetchImpl } },
      createElement(Probe),
    ),
  );
  await waitFor(() => captured.party && captured.coverage);
  assert.equal(captured.party.ok, true);
  assert.equal(captured.party.role, 'holder');
  assert.equal(captured.coverage.entryId, 'abc123');
  assert.equal(captured.coverage.witnesses[0].witness, 'demo');
  ui.unmount();
});

test('useDatu without a provider throws a clear error', async () => {
  const captured = {};
  class Boundary extends React.Component {
    componentDidCatch(error) {
      captured.error = error;
    }
    render() {
      return this.props.children;
    }
  }
  function Orphan() {
    useDatu();
    return createElement('div');
  }
  const ui = render(createElement(Boundary, null, createElement(Orphan)));
  await waitFor(() => captured.error);
  assert.ok(captured.error);
  assert.match(captured.error.message, /DatuProvider/);
  ui.unmount();
});
