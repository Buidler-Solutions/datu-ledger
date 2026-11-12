// Local verification of a witness coverage answer (GET /v1/coverage/...):
// the Merkle path must reach the checkpoint's signed root, and the
// checkpoint's Ed25519 signature must verify over the exact body bytes the
// server served. With both checks the panel trusts no node for what a
// witness said - the node can only choose which witnesses to relay.
//
// ML-DSA-65 is not verified here: browsers have no ML-DSA verifier. The CLI
// (datu witness verify-proof) checks both signatures; these pages say so.
(function (root) {
  const hexToBytes = (hex) =>
    Uint8Array.from((String(hex).match(/../g) || []), (pair) => parseInt(pair, 16));
  const toHex = (bytes) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

  /// Recompute the Merkle root a leaf supports: mirrors datu_core::merkle.
  function merkleRootFromProof(entryIdHex, index, count, siblingHexes) {
    const blake3 = root.datuBlake3;
    if (!blake3) throw new Error('datuBlake3 is not loaded');
    if (!Number.isInteger(index) || !Number.isInteger(count) || count < 1 || index < 0 || index >= count) {
      throw new Error('proof position is out of range');
    }
    let node = blake3.hash32(hexToBytes(entryIdHex));
    let idx = index;
    let len = count;
    for (const siblingHex of siblingHexes) {
      const sibling = hexToBytes(siblingHex);
      if (sibling.length !== 32) throw new Error('proof sibling is not 32 bytes');
      const pair = new Uint8Array(64);
      if (idx % 2 === 1) {
        pair.set(sibling, 0);
        pair.set(node, 32);
      } else {
        pair.set(node, 0);
        pair.set(sibling, 32);
      }
      node = blake3.hash32(pair);
      idx = Math.floor(idx / 2);
      len = Math.ceil(len / 2);
    }
    if (len !== 1) throw new Error('proof is shorter than the tree height');
    return toHex(node);
  }

  /// 'ok' | 'invalid' | 'unavailable' (no WebCrypto Ed25519 in this context).
  async function verifyEd25519(signerHex, bodyBytes, signatureHex) {
    const subtle = root.crypto && root.crypto.subtle;
    if (!subtle) return 'unavailable';
    const keyBytes = hexToBytes(signerHex);
    if (keyBytes.length !== 32) return 'invalid';
    // Raw Ed25519 public key wrapped in the fixed SPKI prefix.
    const spkiPrefix = hexToBytes('302a300506032b6570032100');
    const der = new Uint8Array(spkiPrefix.length + keyBytes.length);
    der.set(spkiPrefix, 0);
    der.set(keyBytes, spkiPrefix.length);
    try {
      const key = await subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify']);
      const valid = await subtle.verify(
        { name: 'Ed25519' },
        key,
        hexToBytes(signatureHex),
        bodyBytes,
      );
      return valid ? 'ok' : 'invalid';
    } catch {
      return 'unavailable';
    }
  }

  /// Verify one witness entry of a /v1/coverage answer against the entry id
  /// it claims to cover. Returns {ok, signature?, reason?}.
  async function verifyWitness(entryIdHex, witness) {
    try {
      const proof = witness.proof || {};
      if (proof.entry_id && proof.entry_id !== entryIdHex) {
        return { ok: false, reason: 'the proof is for a different entry id' };
      }
      const root = merkleRootFromProof(
        entryIdHex,
        Number(proof.index),
        Number(proof.count),
        proof.siblings || [],
      );
      if (root !== String(witness.entry_ids_root).toLowerCase()) {
        return { ok: false, reason: 'the merkle path does not reach the signed root' };
      }
      if (Number(witness.entries_count) !== Number(proof.count)) {
        return { ok: false, reason: 'proof set size differs from the checkpoint' };
      }
      let signature = 'unavailable';
      if (witness.body_b64 && witness.signature) {
        const bodyBytes = Uint8Array.from(atob(witness.body_b64), (c) => c.charCodeAt(0));
        signature = await verifyEd25519(witness.signer, bodyBytes, witness.signature);
      }
      if (signature === 'invalid') {
        return { ok: false, reason: 'the checkpoint signature does not verify' };
      }
      return { ok: true, signature };
    } catch (e) {
      return { ok: false, reason: e.message };
    }
  }

  root.datuCoverage = { verifyWitness, merkleRootFromProof, verifyEd25519 };
})(typeof globalThis !== 'undefined' ? globalThis : this);
