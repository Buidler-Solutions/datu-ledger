// SignetAuth Level 3a: WebAuthn proxy format helpers.
//
// Pure encoding work for the virtual authenticator: while the extension is
// attached via chrome.webAuthenticationProxy, every navigator.credentials
// ceremony is answered by the Signet bridge using the identity's Ed25519 key.
// The completion payloads follow the WebAuthn toJSON() serialization
// (base64url), and the extension itself builds clientDataJSON because Chrome
// passes only the options dictionary, not the requesting origin.
//
// Mirrors datu_core::auth_webauthn: COSE Ed25519 key (kty OKP, alg EdDSA,
// crv Ed25519, 42 bytes), authenticatorData = SHA-256(rp_id) || flags ||
// signCount, attestation format "none", UP|UV set, signCount 0.
(function (root) {
  const utf8 = (s) => new TextEncoder().encode(s);

  const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const hexToBytes = (hex) =>
    Uint8Array.from(String(hex).match(/../g) || [], (h) => parseInt(h, 16));

  const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const bytesToB64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const b64ToB64u = (s) => String(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64uToBytes = (s) => {
    const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
    return b64ToBytes(t + pad);
  };
  const bytesToB64u = (bytes) => b64ToB64u(bytesToB64(bytes));
  const b64uToHex = (s) => bytesToHex(b64uToBytes(s));
  const hexToB64u = (hex) => bytesToB64u(hexToBytes(hex));

  async function sha256(bytes) {
    return new Uint8Array(await root.crypto.subtle.digest('SHA-256', bytes));
  }

  // Minimal CTAP2 canonical CBOR for the fields WebAuthn needs (integers,
  // text and byte strings, small maps/arrays).
  function cborUint(major, n) {
    if (n < 24) return [major << 5 | n];
    if (n < 0x100) return [major << 5 | 24, n];
    if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff];
    return [major << 5 | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  }
  const cborBytes = (bytes) => [...cborUint(2, bytes.length), ...bytes];
  const cborText = (text) => {
    const bytes = utf8(text);
    return [...cborUint(3, bytes.length), ...bytes];
  };

  // SPKI (SubjectPublicKeyInfo) DER for an Ed25519 public key: fixed prefix
  // plus the raw 32-byte key. The COSE key is the fixed 42-byte layout
  // a4 0101 0326 2006 2158 20 <x>, so x is the trailing 32 bytes.
  function spkiFromCose(cose) {
    if (cose.length !== 42) throw new Error('expected the 42-byte COSE Ed25519 key');
    const prefix = hexToBytes('302a300506032b6570032100');
    const out = new Uint8Array(prefix.length + 32);
    out.set(prefix, 0);
    out.set(cose.slice(-32), prefix.length);
    return out;
  }

  // authenticatorData with the AT flag and the new credential embedded:
  // rpIdHash || flags || signCount || AAGUID(zeroed) || credIdLen || credId || COSE key.
  async function attestationParts(rpId, credentialIdHex, coseBytes) {
    const credentialId = hexToBytes(credentialIdHex);
    const rpIdHash = await sha256(utf8(rpId));
    const authData = new Uint8Array([
      ...rpIdHash,
      0x45, // UP | UV | AT
      0, 0, 0, 0, // signCount
      ...new Uint8Array(16), // AAGUID (all zero: no model identity)
      (credentialId.length >> 8) & 0xff,
      credentialId.length & 0xff,
      ...credentialId,
      ...coseBytes,
    ]);
    const attestationObject = Uint8Array.from([
      0xa3, // map(3)
      ...cborText('fmt'), ...cborText('none'),
      ...cborText('attStmt'), 0xa0,
      ...cborText('authData'), ...cborBytes(authData),
    ]);
    return { authData, attestationObject };
  }

  // clientDataJSON the extension supplies for both ceremonies; challenge
  // stays the base64url string the relying party sent.
  function clientData(type, challenge, origin) {
    return { type, challenge, origin, crossOrigin: false };
  }

  // RegistrationResponseJSON for completeCreateRequest: the bridge's
  // credential (hex id + std-base64 COSE key) becomes the base64url fields.
  async function createResponseJson({ request, origin, credentialIdHex, coseB64, alg = -8 }) {
    const rpId = (request.rp && request.rp.id) || new URL(origin).hostname;
    const cose = b64ToBytes(coseB64);
    const { authData, attestationObject } = await attestationParts(rpId, credentialIdHex, cose);
    const id = hexToB64u(credentialIdHex);
    const cd = clientData('webauthn.create', request.challenge, origin);
    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: bytesToB64u(utf8(JSON.stringify(cd))),
        attestationObject: bytesToB64u(attestationObject),
        authenticatorData: bytesToB64u(authData),
        transports: ['internal'],
        publicKeyAlgorithm: alg,
        publicKey: bytesToB64u(spkiFromCose(cose)),
      },
    };
  }

  // AuthenticationResponseJSON for completeGetRequest: the bridge returns
  // std-base64 authenticatorData/signature, the response needs base64url.
  function getResponseJson({ request, origin, credentialIdB64u, authenticatorDataB64, signatureB64 }) {
    const cd = clientData('webauthn.get', request.challenge, origin);
    return {
      id: credentialIdB64u,
      rawId: credentialIdB64u,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: bytesToB64u(utf8(JSON.stringify(cd))),
        authenticatorData: b64ToB64u(authenticatorDataB64),
        signature: b64ToB64u(signatureB64),
      },
    };
  }

  root.datuWebauthn = {
    utf8,
    bytesToHex,
    hexToBytes,
    b64ToBytes,
    bytesToB64,
    b64ToB64u,
    b64uToBytes,
    bytesToB64u,
    b64uToHex,
    hexToB64u,
    sha256,
    spkiFromCose,
    attestationParts,
    clientData,
    createResponseJson,
    getResponseJson,
  };
})(globalThis);
