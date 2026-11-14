// SignetAuth Level 3a format tests: the completion payloads a real Chrome
// accepts from chrome.webAuthenticationProxy.complete{Create,Get}Request.
// Shapes follow the WebAuthn toJSON() serialization (base64url) and mirror
// datu_core::auth_webauthn (COSE Ed25519 key, "none" attestation, UP|UV).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import '../webauthn.js';

const W = globalThis.datuWebauthn;

// The exact 42-byte COSE layout the bridge emits (a4 0101 0327 2006 2158 20 x):
// alg must decode to -8 (0x27), not -7 (0x26), or RPs read ES256.
const X = crypto.getRandomValues(new Uint8Array(32));
const COSE = new Uint8Array([0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20, ...X]);
const COSE_B64 = W.bytesToB64(COSE);
const CRED_ID_HEX = '00112233445566778899aabbccddeeff';

const b64u = (bytes) => W.bytesToB64u(bytes);
const unb64u = (s) => W.b64uToBytes(s);
const sha256Hex = async (s) =>
  Array.from(await W.sha256(W.utf8(s)), (b) => b.toString(16).padStart(2, '0')).join('');

test('hex and base64url round trips', () => {
  const hex = '00ff10f1f0';
  assert.equal(W.bytesToHex(W.hexToBytes(hex)), hex);
  assert.equal(W.b64uToHex(W.hexToB64u(hex)), hex);
  // padding-needing values keep url-safe and unpadded form
  const b = new Uint8Array([0xfb, 0xff, 0xbf, 0xfd]);
  const u = b64u(b);
  assert.match(u, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(Array.from(unb64u(u)), Array.from(b));
  // std base64 (bridge replies) converts to base64url
  assert.equal(W.b64ToB64u('a+b/cd=='), 'a-b_cd');
});

test('spki wraps the raw Ed25519 key in a fixed DER prefix', () => {
  const spki = W.spkiFromCose(COSE);
  assert.equal(W.bytesToHex(spki), `302a300506032b6570032100${W.bytesToHex(X)}`);
  assert.throws(() => W.spkiFromCose(COSE.slice(0, 41)), /42-byte/);
});

test('attestationParts builds CTAP2 none-attestation authData', async () => {
  const { authData, attestationObject } = await W.attestationParts('localhost', CRED_ID_HEX, COSE);
  assert.equal(authData.length, 32 + 1 + 4 + 16 + 2 + 16 + 42);
  assert.equal(W.bytesToHex(authData.slice(0, 32)), await sha256Hex('localhost'));
  assert.equal(authData[32], 0x45); // UP | UV | AT
  assert.equal(authData[33], 0); // signCount 0
  assert.deepEqual(Array.from(authData.slice(37, 53)), new Array(16).fill(0)); // AAGUID
  assert.equal(W.bytesToHex(authData.slice(53, 55)), '0010'); // credentialIdLength u16
  assert.equal(W.bytesToHex(authData.slice(55, 71)), CRED_ID_HEX);
  assert.deepEqual(Array.from(authData.slice(71)), Array.from(COSE));
  // map(3) { fmt: "none", attStmt: {}, authData: bytes }
  const obj = W.bytesToHex(attestationObject);
  assert.ok(obj.startsWith('a363666d74646e6f6e656761747453746d74a0'));
  // authData is the trailing CBOR bytes(113): 0x58 0x71 then the payload
  assert.equal(obj.endsWith(`5871${W.bytesToHex(authData)}`), true);
});

test('createResponseJson matches RegistrationResponseJSON', async () => {
  const request = {
    rp: { id: 'localhost', name: 'Localhost Demo' },
    user: { id: 'AQIDBA', name: 'amina', displayName: 'Amina' },
    challenge: 'AAECAwQFBgcICQ',
    pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
  };
  const json = await W.createResponseJson({
    request,
    origin: 'http://localhost:7591',
    credentialIdHex: CRED_ID_HEX,
    coseB64: COSE_B64,
  });
  assert.equal(json.id, json.rawId);
  assert.equal(json.type, 'public-key');
  assert.equal(json.id, b64u(W.hexToBytes(CRED_ID_HEX)));
  assert.deepEqual(json.response.transports, ['internal']);
  assert.equal(json.response.publicKeyAlgorithm, -8);
  assert.equal(W.bytesToHex(unb64u(json.response.publicKey)), `302a300506032b6570032100${W.bytesToHex(X)}`);
  const clientData = JSON.parse(new TextDecoder().decode(unb64u(json.response.clientDataJSON)));
  assert.deepEqual(clientData, {
    type: 'webauthn.create',
    challenge: 'AAECAwQFBgcICQ',
    origin: 'http://localhost:7591',
    crossOrigin: false,
  });
  const authData = unb64u(json.response.authenticatorData);
  assert.equal(authData.length, 113);
  const att = unb64u(json.response.attestationObject);
  assert.equal(att[0], 0xa3);
  assert.ok(att.length > authData.length);
});

test('getResponseJson matches AuthenticationResponseJSON', () => {
  const request = {
    challenge: 'AQIDBA',
    rpId: 'localhost',
    allowCredentials: [{ type: 'public-key', id: b64u(W.hexToBytes(CRED_ID_HEX)) }],
  };
  // bridge replies use std base64, including + / and padding
  const authDataB64 = W.bytesToB64(new Uint8Array(37).fill(0xfb));
  const sigB64 = W.bytesToB64(new Uint8Array(64).fill(0xbe));
  const json = W.getResponseJson({
    request,
    origin: 'http://localhost:7591',
    credentialIdB64u: request.allowCredentials[0].id,
    authenticatorDataB64: authDataB64,
    signatureB64: sigB64,
  });
  assert.equal(json.id, json.rawId);
  assert.equal(json.rawId, request.allowCredentials[0].id);
  const clientData = JSON.parse(new TextDecoder().decode(unb64u(json.response.clientDataJSON)));
  assert.equal(clientData.type, 'webauthn.get');
  assert.equal(clientData.challenge, 'AQIDBA');
  assert.equal(clientData.origin, 'http://localhost:7591');
  assert.deepEqual(Array.from(unb64u(json.response.authenticatorData)), new Array(37).fill(0xfb));
  assert.deepEqual(Array.from(unb64u(json.response.signature)), new Array(64).fill(0xbe));
  assert.equal('userHandle' in json.response, false);
});

test('b64uToHex decodes what the panel sends as allowCredentials ids', () => {
  assert.equal(W.b64uToHex('AAECAwQFBgcICQ'), '00010203040506070809');
});
