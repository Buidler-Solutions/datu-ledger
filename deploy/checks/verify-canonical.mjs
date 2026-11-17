#!/usr/bin/env node
// Verify the canonical fixture with Node's crypto: the Ed25519 signatures must
// verify over exactly the pinned bytes, and the SignetAuth byte string is
// rebuilt independently here and compared with the Rust output.
import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

const fixture = JSON.parse(
  readFileSync(new URL('../../crates/core/tests/fixtures/canonical_vectors.json', import.meta.url))
);

// Ed25519 SPKI prefix: an OID header that wraps the 32-byte raw key.
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const keyFor = (pubHex) =>
  createPublicKey({
    key: Buffer.concat([SPKI, Buffer.from(pubHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });

function check(name, canonicalHex, sigHex, pubHex) {
  const ok = verify(null, Buffer.from(canonicalHex, 'hex'), keyFor(pubHex), Buffer.from(sigHex, 'hex'));
  if (!ok) throw new Error(`${name}: signature does not verify`);
  console.log(`ok: ${name} signature over pinned bytes`);
}

check('entry', fixture.entry.canonical_hex, fixture.entry.signature_hex, fixture.public_key_hex);
check('auth', fixture.auth.canonical_hex, fixture.auth.signature_hex, fixture.public_key_hex);
check('checkpoint', fixture.checkpoint.canonical_hex, fixture.checkpoint.signature_hex, fixture.public_key_hex);

// Independent rebuild of the auth byte string from its parts.
const rebuilt = [
  'datu-auth-v1',
  fixture.auth.rp_id,
  fixture.auth.origin,
  fixture.auth.nonce_hex,
  String(fixture.auth.expires_at_ms),
  '',
].join('\n');
const expected = Buffer.from(rebuilt, 'utf8').toString('hex');
if (expected !== fixture.auth.canonical_hex) {
  throw new Error('auth canonical bytes differ from the JS rebuild');
}
console.log('ok: auth canonical bytes match the JS rebuild');

// Entry id is blake3(canonical); JS has no native blake3, so id stays pinned
// and Rust-verified. The signature proof above is what cross-language pins.
console.log('PASS: JS verified canonical signatures');
