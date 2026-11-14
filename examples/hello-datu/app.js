/**
 * hello-DATU app logic, wired up as an ES module so the same flows run in a
 * browser (with the Signet extension) and in tests (with the SDK mock).
 */
import { connect } from '@greenarmor/datu-client';

export const BRIDGE_URL = 'http://127.0.0.1:7588';

const out = (...parts) => {
  const pre = document.getElementById('out');
  if (pre) pre.textContent = parts.join(' ') + '\n' + pre.textContent;
};
export { out as log };

export async function listIdentities(client) {
  const identities = await client.identities();
  return identities;
}

export async function signIn(client, options) {
  return client.signIn(options);
}

export async function signAsHolder(client, options = {}) {
  return client.partySign({
    role: 'holder',
    kind: 'demo.hello',
    document: options.documentId || 'hello-dat-u-doc-1',
    ...options,
  });
}

async function boot() {
  const status = document.getElementById('status');
  const buttons = {
    reload: document.getElementById('reload'),
    signin: document.getElementById('signin'),
    sign: document.getElementById('sign'),
    mock: document.getElementById('mock'),
  };
  let client = null;
  let identity = null;

  const arm = (on) => {
    buttons.reload.disabled = !on;
    buttons.signin.disabled = !on;
  };
  const pickIdentity = async () => {
    const identities = await listIdentities(client);
    out(`identities: ${identities.map((i) => i.name).join(', ') || '(none)'}`);
    identity = identities[0] || null;
    buttons.signin.disabled = !identity;
    buttons.sign.disabled = !identity;
    return identities;
  };

  try {
    client = await connect({ bridgeUrl: BRIDGE_URL });
    status.textContent = 'Signet extension detected';
    status.className = 'ok';
    arm(true);
    await pickIdentity();
  } catch (e) {
    status.textContent = `${e.message}`;
    status.className = 'err';
    out(`no Signet yet: ${e.message}`);
  }

  buttons.reload.onclick = () => pickIdentity().catch((e) => out(`identities failed: ${e.message}`));

  buttons.signin.onclick = async () => {
    try {
      const { assertion, verified } = await signIn(client, { name: identity.name });
      out(`SignetAuth ok: identity=${assertion.nonce ? identity.name : '?'} verified=${verified}`);
      out(`  pubkey ${assertion.pubkey.slice(0, 16)}... nonce ${assertion.nonce}`);
    } catch (e) {
      out(`sign-in failed: ${e.message}`);
    }
  };

  buttons.sign.onclick = async () => {
    try {
      const result = await signAsHolder(client, { name: identity.name });
      out(`party-sign ok: ${JSON.stringify(result).slice(0, 160)}`);
    } catch (e) {
      out(`party-sign failed: ${e.message}`);
    }
  };

  buttons.mock.onclick = async () => {
    const { mockTransport } = await import('@greenarmor/datu-client/mock');
    const { makeMockKey } = await import('./mock-key.js');
    const key = await makeMockKey();
    const mock = mockTransport({
      identities: [{ name: 'demo', ed_public: key.pubkeyHex }],
      keys: { demo: key },
    });
    const demo = await connect({ transport: mock, detect: false });
    const identities = await listIdentities(demo);
    out(`[mock] identities: ${identities.map((i) => i.name).join(', ')}`);
    const { assertion, verified } = await signIn(demo, { name: 'demo' });
    out(`[mock] SignetAuth verified=${verified} nonce=${assertion.nonce}`);
    const signed = await signAsHolder(demo, { name: 'demo' });
    out(`[mock] party-sign ok (role ${signed.role || 'holder'})`);
    out('[mock] all flows green without a wallet');
  };
}

const inBrowser = typeof document !== 'undefined' && document.getElementById;
if (inBrowser) boot();
