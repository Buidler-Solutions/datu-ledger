// SignetAuth Level 3b: device passkey unlock for the Signet panel.
//
// A platform passkey (WebAuthn, user verification required: Touch ID /
// Windows Hello / PIN) protects the vault passphrase. The passphrase is
// wrapped with AES-GCM under a key derived (HKDF) from the authenticator's
// PRF extension output, so the stored blob can only be unwrapped after a
// successful passkey gesture. The unwrapped passphrase lives in panel
// memory only and is cleared by the idle auto-lock.
//
// The passkey gates the panel, not the bridge: keys still never leave the
// Signet process, and a lost passkey falls back to typing the passphrase.
(function (root) {
  const enc = new TextEncoder();
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

  const HKDF_SALT = enc.encode('datu-signet-passkey-v1');
  const HKDF_INFO = enc.encode('signet-passphrase-wrap');

  /// HKDF-SHA256 over the PRF secret -> a fresh AES-GCM wrapping key.
  /// Deriving each time means nothing secret is ever persisted.
  async function wrappingKey(prfSecret) {
    const subtle = root.crypto.subtle;
    const base = await subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function wrapPassphrase(prfSecret, passphrase) {
    const subtle = root.crypto.subtle;
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv }, await wrappingKey(prfSecret), enc.encode(passphrase))
    );
    return { iv: b64(iv), ct: b64(ct) };
  }

  async function unwrapPassphrase(prfSecret, ivB64, ctB64) {
    const subtle = root.crypto.subtle;
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(ivB64) },
      await wrappingKey(prfSecret),
      unb64(ctB64)
    );
    return new TextDecoder().decode(plain);
  }

  const randomBytes = (n) => root.crypto.getRandomValues(new Uint8Array(n));
  const prfSalt = () => randomBytes(32); // stored alongside the wrapped blob

  /// WebAuthn glue: create a resident passkey with the PRF extension
  /// enabled. Must be called from the panel page (user gesture).
  async function createPasskey(username) {
    const credential = await root.navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        user: { id: randomBytes(16), name: username, displayName: `DATU Signet - ${username}` },
        rp: { name: 'DATU Signet' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        },
        extensions: { prf: {} },
      },
    });
    return { credentialId: b64(new Uint8Array(credential.rawId)) };
  }

  /// The user-presence + user-verification gesture: assert the passkey and
  /// evaluate the PRF extension to obtain the wrapping secret.
  async function unlockSecret(credentialIdB64, salt) {
    const assertion = await root.navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        allowCredentials: [{ type: 'public-key', id: unb64(credentialIdB64) }],
        userVerification: 'required',
      },
      extensions: { prf: { eval: { first: salt } } },
    });
    const results = assertion?.clientExtensionResults?.prf?.results;
    if (!results?.first) {
      throw new Error('this passkey does not support the PRF extension - recreate it from Settings');
    }
    return new Uint8Array(results.first);
  }

  root.datuPasskey = { wrapPassphrase, unwrapPassphrase, prfSalt, createPasskey, unlockSecret };
})(globalThis);
