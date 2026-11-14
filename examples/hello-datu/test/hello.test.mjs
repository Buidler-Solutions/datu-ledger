// hello-DATU starter tests: the same flows the page runs, against the SDK
// mock transport, so the example keeps working as the SDK evolves.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { connect } from '@greenarmor/datu-client';
import { mockTransport } from '@greenarmor/datu-client/mock';
import { listIdentities, signIn, signAsHolder } from '../app.js';
import { makeMockKey } from '../mock-key.js';

const nodeKey = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pubkeyHex: publicKey.export({ type: 'spki', format: 'der' }).toString('hex').slice(-64),
    sign: (bytes) => cryptoSign(null, bytes, privateKey).toString('hex'),
  };
};

test('the full demo flow against the mock transport', async () => {
  const key = nodeKey();
  const transport = mockTransport({
    identities: [{ name: 'demo', ed_public: key.pubkeyHex }],
    keys: { demo: key },
  });
  const client = await connect({ transport, detect: false });

  const identities = await listIdentities(client);
  assert.equal(identities.length, 1);
  assert.equal(identities[0].name, 'demo');

  // Node has no window.location, so the RP identity is explicit (in the
  // browser the SDK derives both from location).
  const { assertion, verified } = await signIn(client, {
    name: 'demo',
    rpId: 'localhost',
    origin: 'http://localhost:5174',
  });
  assert.equal(verified, true);
  assert.equal(assertion.pubkey, key.pubkeyHex);
  assert.equal(assertion.nonce.length, 32);

  const signed = await signAsHolder(client, { name: 'demo', documentId: 'doc-42' });
  assert.equal(signed.ok, true);
});

test('the browser mock key works under Node webcrypto too', async () => {
  const key = await makeMockKey();
  assert.equal(key.pubkeyHex.length, 64);
  const signature = await key.sign(new TextEncoder().encode('hello'));
  assert.equal(signature.length, 128);
});
