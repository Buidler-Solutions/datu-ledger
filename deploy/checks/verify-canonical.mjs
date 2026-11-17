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
// A party signs the BLAKE3 digest of the canonical JSON, so the pinned
// digest bytes are what the signature must verify over here.
check('party', fixture.party.digest_hex, fixture.party.signature_hex, fixture.public_key_hex);

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

// Rebuild the party canonical JSON with sorted keys (serde_json's BTree map
// order) and compact separators, then compare against the Rust bytes.
const canon = (v) => {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
};
const party = fixture.party;
const partyRebuilt = canon({
  v: party.v,
  kind: party.kind,
  doc: party.doc,
  role: party.role,
  key: party.key,
});
if (Buffer.from(partyRebuilt, 'utf8').toString('hex') !== party.canonical_hex) {
  throw new Error('party canonical JSON differs from the JS rebuild');
}
console.log('ok: party canonical JSON matches the JS rebuild');

// Entry id and the party digest are blake3 over canonical bytes; JS has no
// native blake3, so both stay pinned and Rust-verified (the Rust test
// recomputes them). The signature proofs above are what cross-language pin.
console.log('PASS: JS verified canonical signatures');
