// The wrapping crypto is pinned here: the AES-GCM blob must open only under
// the same PRF secret, and never under a different salt/secret. These tests
// run under Node's WebCrypto; the WebAuthn ceremony itself is a browser
// gesture and is exercised manually in the panel.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../passkey.js';

const { wrapPassphrase, unwrapPassphrase, prfSalt } = globalThis.datuPasskey;

const SECRET = crypto.getRandomValues(new Uint8Array(32));
const OTHER = crypto.getRandomValues(new Uint8Array(32));

test('wrap/unwrap roundtrip under the same PRF secret', async () => {
  const blob = await wrapPassphrase(SECRET, 'amina-demo');
  assert.notEqual(blob.ct, '');
  assert.equal(await unwrapPassphrase(SECRET, blob.iv, blob.ct), 'amina-demo');
});

test('a different PRF secret cannot unwrap (authentication tag fails)', async () => {
  const blob = await wrapPassphrase(SECRET, 'amina-demo');
  await assert.rejects(unwrapPassphrase(OTHER, blob.iv, blob.ct));
});

test('tampered ciphertext fails closed', async () => {
  const blob = await wrapPassphrase(SECRET, 'amina-demo');
  const bytes = Uint8Array.from(atob(blob.ct), (c) => c.charCodeAt(0));
  bytes[0] ^= 1;
  const tampered = btoa(String.fromCharCode(...bytes));
  await assert.rejects(unwrapPassphrase(SECRET, blob.iv, tampered));
});

test('salts are random and 32 bytes', async () => {
  const a = prfSalt();
  const b = prfSalt();
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, b);
});
