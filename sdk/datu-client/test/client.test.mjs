// The SDK is pinned end to end: SignetAuth round trip against real Ed25519
// keys, error mapping, node reads, and the mocked transports a dApp's own
// tests will use.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { connect, DatuError, ErrorCode, newChallenge, verifyAssertion } from '../src/index.js';
import { mockTransport, mockFetch } from '../src/mock.js';

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubkeyHex = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
  return {
    pubkeyHex,
    sign: (bytes) => nodeSign(null, Buffer.from(bytes), privateKey).toString('hex'),
  };
}

const IDENTITY = { name: 'amina', ed_public: 'aa', seal_public: 'bb' };

test('connect detects the extension and lists identities', async () => {
  const rpc = mockTransport({ identities: [IDENTITY] });
  const datu = await connect({ bridgeUrl: 'http://127.0.0.1:7588', transport: rpc });
  assert.equal((await datu.ping()).pong, true);
  const ids = await datu.identities();
  assert.equal(ids.length, 1);
  assert.equal(ids[0].name, 'amina');
});

test('connect fails closed without an extension', async () => {
  const rpc = mockTransport();
  rpc.ping = async () => null;
  await assert.rejects(connect({ transport: rpc }), (e) => {
    assert.ok(e instanceof DatuError);
    assert.equal(e.code, ErrorCode.NOT_CONNECTED);
    return true;
  });
});

test('signIn mints a challenge, signs it, and verifies locally', async () => {
  const key = keypair();
  const rpc = mockTransport({ identities: [IDENTITY], keys: { amina: key } });
  const datu = await connect({ transport: rpc, rpId: 'app.example.com', origin: 'https://app.example.com' });
  const { assertion, verified, challenge } = await datu.signIn({ name: 'amina' });
  assert.equal(verified, true);
  assert.equal(assertion.domain, 'datu-auth-v1');
  assert.equal(assertion.pubkey, key.pubkeyHex);
  assert.equal(challenge.rp_id, 'app.example.com');
  assert.equal(rpc.calls[0].path, '/v1/wallet/auth-assert');
  assert.equal(rpc.calls[0].body.nonce, challenge.nonce);
  assert.equal(rpc.calls[0].body.approve, true, 'interactive login carries the approval gesture');
});

test('signIn rejects an assertion signed by the wrong key', async () => {
  const key = keypair();
  const rpc = mockTransport({ identities: [IDENTITY], keys: { amina: key } });
  const datu = await connect({ transport: rpc });
  const real = rpc.sign;
  rpc.sign = async (opts) => {
    const out = await real(opts);
    out.body = { ...out.body, signature: '00'.repeat(64) };
    return out;
  };
  await assert.rejects(datu.signIn({ name: 'amina', rpId: 'a', origin: 'https://a' }), /rejected/);
});

test('silent relogin passes a grant and no approval gesture', async () => {
  const key = keypair();
  const rpc = mockTransport({ keys: { amina: key } });
  const datu = await connect({ transport: rpc });
  await datu.signIn({ name: 'amina', rpId: 'app', origin: 'https://app', approve: false, grant: 'g-1' });
  assert.equal(rpc.calls[0].body.approve, false);
  assert.equal(rpc.calls[0].body.grant, 'g-1');
});

test('signIn rejects an assertion for another challenge (replay)', async () => {
  const key = keypair();
  const rpc = mockTransport({ keys: { amina: key } });
  const datu = await connect({ transport: rpc });
  const stolen = await datu.signIn({ name: 'amina', rpId: 'app', origin: 'https://app' });
  const other = newChallenge({ rpId: 'app', origin: 'https://app' });
  const verdict = await verifyAssertion(stolen.assertion, other);
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /does not match/);
});

test('bridge errors map to stable codes', async () => {
  const rpc = mockTransport({ state: { fail: { message: 'origin mismatch: pinned' } } });
  const datu = await connect({ transport: rpc });
  await assert.rejects(datu.partySign({ name: 'amina', role: 'holder', document: {} }), (e) => {
    assert.equal(e.code, ErrorCode.ORIGIN_MISMATCH);
    return true;
  });
});

test('partySign, seal and deferred flows pass through with typed args', async () => {
  const rpc = mockTransport();
  const datu = await connect({ transport: rpc });
  await datu.partySign({ name: 'amina', role: 'holder', document: { a: 1 }, kind: 'land.title.application' });
  await datu.seal({ name: 'registrar', document: { s: 1 }, fields: ['name'], toFields: ['holder_seal'] });
  await datu.sealDeferred({ name: 'registrar', document: { p: 1 }, fields: ['price'], toField: 'holder_seal' });
  await datu.releaseDeferred({ document: { p: 1 }, field: 'price', release: {} });
  await datu.openDeferred({ name: 'amina', document: { p: 1 }, field: 'price', release: {} });
  const paths = rpc.calls.map((c) => c.path);
  assert.deepEqual(paths, [
    '/v1/wallet/party-sign',
    '/v1/wallet/seal',
    '/v1/wallet/seal-deferred',
    '/v1/wallet/release-deferred',
    '/v1/wallet/deferred-open',
  ]);
  assert.deepEqual(rpc.calls[1].body.to_fields, ['holder_seal']);
  assert.equal(rpc.calls[2].body.to_field, 'holder_seal');
});

test('node client reads entries, entry detail and status', async () => {
  const { fetchImpl, requests } = mockFetch({
    routes: {
      '/v1/status': () => ({ entries: 3, checkpoints: 2, policy: { mode: 'open-observer' } }),
      '/v1/entries': () => ({ entries: [{ id: 'aa' }] }),
      '/v1/entry/aa': () => ({ id: 'aa', author: 'cc' }),
      '/v1/coverage/aa': () => ({ witnesses: [{ signer: 'dd', height: 2 }], stale: [] }),
    },
  });
  const datu = await connect({ transport: mockTransport(), fetchImpl, nodeUrl: 'http://127.0.0.1:7474' });
  assert.equal((await datu.node.status()).entries, 3);
  assert.equal((await datu.node.entries({ ns: 'gov.titles', limit: 10 })).entries.length, 1);
  assert.ok(requests[1].path.startsWith('/v1/entries?ns=gov.titles'));
  assert.equal((await datu.node.entry('aa')).author, 'cc');
  const coverage = await datu.verifyCoverage('aa');
  assert.equal(coverage.witnesses.length, 1);
  assert.match(coverage.witnesses[0].verdict, /not checked/);
});

test('node errors surface as NODE_ERROR with status', async () => {
  const { fetchImpl } = mockFetch({ routes: {} });
  const datu = await connect({ transport: mockTransport(), fetchImpl });
  await assert.rejects(datu.node.status(), (e) => {
    assert.equal(e.code, ErrorCode.NODE_ERROR);
    assert.match(e.message, /no route/);
    return true;
  });
});

test('list arguments accept strings, comma lists and arrays', async () => {
  const rpc = mockTransport();
  const datu = await connect({ transport: rpc });
  await datu.seal({ name: 'registrar', document: {}, fields: 'a,b', to: 'key1,key2' });
  assert.deepEqual(rpc.calls[0].body.fields, ['a', 'b']);
  assert.deepEqual(rpc.calls[0].body.to, ['key1', 'key2']);
  await datu.sealDeferred({ name: 'registrar', document: {}, fields: ['p'], to: 'key1' });
  assert.deepEqual(rpc.calls[1].body.fields, ['p']);
  assert.equal(rpc.calls[1].body.to, 'key1');
});

test('strict login refuses an unverifiable assertion', async () => {
  const key = keypair();
  const rpc = mockTransport({ keys: { amina: key } });
  const datu = await connect({ transport: rpc });
  const realVerify = globalThis.crypto;
  const savedSubtle = realVerify.subtle;
  Object.defineProperty(realVerify, 'subtle', { configurable: true, value: undefined });
  try {
    const lax = await datu.signIn({ name: 'amina', rpId: 'a', origin: 'https://a' });
    assert.equal(lax.verified, null);
    await assert.rejects(
      datu.signIn({ name: 'amina', rpId: 'a', origin: 'https://a', strict: true }),
      /could not be verified locally/,
    );
  } finally {
    Object.defineProperty(realVerify, 'subtle', { configurable: true, value: savedSubtle });
  }
});

test('node statuses map to named codes (denied, conflict, quota)', async () => {
  const make = (status, body) => ({
    fetchImpl: async () => ({ ok: false, status, text: async () => JSON.stringify(body) }),
  });
  const cases = [
    [403, { error: 'denied', denied: 'writer not admitted' }, ErrorCode.POLICY_DENIED],
    [409, { error: 'conflict' }, ErrorCode.CONFLICT],
    [429, { error: 'rate limit', retry_after_s: 12 }, ErrorCode.RATE_LIMITED],
    [500, { error: 'boom' }, ErrorCode.NODE_ERROR],
  ];
  for (const [status, body, expected] of cases) {
    const datu = await connect({ transport: mockTransport(), ...make(status, body) });
    await assert.rejects(datu.node.status(), (e) => {
      assert.equal(e.code, expected, `${status} -> ${e.code}`);
      return true;
    });
  }
});

test('argument validation is explicit', async () => {
  const datu = await connect({ transport: mockTransport() });
  await assert.rejects(datu.partySign({ name: 'amina', document: {} }), /role is required/);
  // Sync validation throws immediately; assert.throws is the right tool.
  assert.throws(() => datu.node.entry(), /entry id is required/);
});

test('proveGenuine accepts a valid provider proof (nonce, key, pin)', async () => {
  const bridge = keypair();
  const rpc = mockTransport({ proofKey: bridge });
  const datu = await connect({ transport: rpc });
  const verdict = await datu.proveGenuine();
  assert.equal(verdict.genuine, true);
  assert.equal(verdict.verified, true);
  assert.equal(verdict.reachable, true);
  assert.equal(verdict.bridgeUrl, 'http://127.0.0.1:7588');
  assert.equal(verdict.version, '0.2.0');
  assert.equal(verdict.bridgePubkey, bridge.pubkeyHex);
  assert.match(verdict.nonce, /^[0-9a-f]{32}$/, 'the SDK mints the challenge nonce');
  assert.equal(verdict.proof.domain, 'datu-provider-v1');
  assert.equal(rpc.calls[0].path, '/v1/provider-proof');
  assert.equal(rpc.calls[0].body.nonce, verdict.nonce, 'the proof answers the issued nonce');
});

test('proveGenuine treats an invalid answer as an impostor, not downtime', async () => {
  const bridge = keypair();
  const rpc = mockTransport({ proofKey: bridge });
  const datu = await connect({ transport: rpc });
  const real = rpc.prove;
  rpc.prove = async (opts) => ({ ...(await real(opts)), signature: '00'.repeat(64) });
  const verdict = await datu.proveGenuine({ nonce: 'ab'.repeat(16) });
  assert.equal(verdict.genuine, false);
  assert.equal(verdict.reachable, true, 'it answered, so it is a definite impostor');
  assert.match(verdict.reason, /signature invalid/);
});

test('proveGenuine rejects a proof that answers another nonce', async () => {
  const bridge = keypair();
  const rpc = mockTransport({ proofKey: bridge });
  const datu = await connect({ transport: rpc });
  const real = rpc.prove;
  rpc.prove = async (opts) => ({ ...(await real(opts)), nonce: 'ff'.repeat(32) });
  const verdict = await datu.proveGenuine({ nonce: 'ab'.repeat(16) });
  assert.equal(verdict.genuine, false);
  assert.match(verdict.reason, /does not answer the nonce/);
});

test('proveGenuine rejects a bridge key that differs from the expected key', async () => {
  const bridge = keypair();
  const other = keypair();
  const rpc = mockTransport({ proofKey: bridge });
  const datu = await connect({ transport: rpc });
  const verdict = await datu.proveGenuine({ nonce: 'ab'.repeat(16), expectedBridgePubkey: other.pubkeyHex });
  assert.equal(verdict.genuine, false);
  assert.equal(verdict.reachable, true);
  assert.match(verdict.reason, /expected key/);
});

test('proveGenuine reports no answer as unreachable, never as malicious', async () => {
  const rpc = mockTransport();
  const datu = await connect({ transport: rpc });
  const verdict = await datu.proveGenuine({ nonce: 'ab'.repeat(16) });
  assert.equal(verdict.genuine, false);
  assert.equal(verdict.reachable, false, 'nothing answered: bridge down, not an impostor');
  assert.match(verdict.reason, /no Signet paired/);
});
