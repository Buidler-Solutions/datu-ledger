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

test('argument validation is explicit', async () => {
  const datu = await connect({ transport: mockTransport() });
  await assert.rejects(datu.partySign({ name: 'amina', document: {} }), /role is required/);
  // Sync validation throws immediately; assert.throws is the right tool.
  assert.throws(() => datu.node.entry(), /entry id is required/);
});
