/**
 * A browser-and-Node compatible mock identity key for the "run without a
 * wallet" demo: WebCrypto Ed25519, raw public key as hex, sign() -> hex.
 */
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export async function makeMockKey() {
  const subtle = globalThis.crypto.subtle;
  if (!subtle) throw new Error('WebCrypto unavailable for the demo mock key');
  const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const jwk = await subtle.exportKey('jwk', pair.privateKey);
  const priv = await subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
  return {
    pubkeyHex: hex(spki.slice(spki.length - 32)),
    sign: async (bytes) => {
      const signature = await subtle.sign({ name: 'Ed25519' }, priv, bytes);
      return hex(new Uint8Array(signature));
    },
  };
}
