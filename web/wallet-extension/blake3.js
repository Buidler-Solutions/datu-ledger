// Minimal BLAKE3 for the hashes DATU needs in a browser: single compression
// calls over inputs of at most 64 bytes. Every merkle node in this system is
// BLAKE3 over an entry id (32 bytes) or a left||right pair (64 bytes), and
// the empty-set sentinel is 14 bytes - all inside one block, so there is no
// tree mode, no chunking, and no extendable output to implement.
//
// The vectors in test/blake3.test.js were generated with the Rust blake3
// crate, so this implementation is cross-checked, not self-referential.
(function (root) {
  const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
  const CHUNK_START = 1;
  const CHUNK_END = 2;
  const ROOT = 8;

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  function g(state, a, b, c, d, mx, my) {
    state[a] = (state[a] + state[b] + mx) >>> 0;
    state[d] = rotr(state[d] ^ state[a], 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotr(state[b] ^ state[c], 12);
    state[a] = (state[a] + state[b] + my) >>> 0;
    state[d] = rotr(state[d] ^ state[a], 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotr(state[b] ^ state[c], 7);
  }

  function compress(cv, blockWords, blockLen, flags) {
    const state = new Uint32Array(16);
    for (let i = 0; i < 8; i++) state[i] = cv[i];
    state[8] = IV[0];
    state[9] = IV[1];
    state[10] = IV[2];
    state[11] = IV[3];
    state[12] = 0; // counter low: our messages never cross 4 GiB
    state[13] = 0; // counter high
    state[14] = blockLen;
    state[15] = flags;
    let m = blockWords.slice();
    for (let round = 0; round < 7; round++) {
      g(state, 0, 4, 8, 12, m[0], m[1]);
      g(state, 1, 5, 9, 13, m[2], m[3]);
      g(state, 2, 6, 10, 14, m[4], m[5]);
      g(state, 3, 7, 11, 15, m[6], m[7]);
      g(state, 0, 5, 10, 15, m[8], m[9]);
      g(state, 1, 6, 11, 12, m[10], m[11]);
      g(state, 2, 7, 8, 13, m[12], m[13]);
      g(state, 3, 4, 9, 14, m[14], m[15]);
      if (round < 6) {
        const permuted = new Uint32Array(16);
        for (let i = 0; i < 16; i++) permuted[i] = m[MSG_PERMUTATION[i]];
        m = permuted;
      }
    }
    for (let i = 0; i < 8; i++) {
      state[i] = (state[i] ^ state[i + 8]) >>> 0;
      state[i + 8] = (state[i + 8] ^ cv[i]) >>> 0;
    }
    return state;
  }

  /// BLAKE3 hash of at most 64 bytes; first 32 bytes of output, as Uint8Array.
  function hash32(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (bytes.length > 64) {
      throw new Error('datuBlake3.hash32 covers inputs up to 64 bytes (tree mode is not needed here)');
    }
    const blockWords = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      let word = 0;
      for (let b = 3; b >= 0; b--) {
        const index = i * 4 + b;
        word = (word << 8) | (index < bytes.length ? bytes[index] : 0);
      }
      blockWords[i] = word >>> 0;
    }
    const words = compress(IV, blockWords, bytes.length, CHUNK_START | CHUNK_END | ROOT);
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4] = words[i] & 0xff;
      out[i * 4 + 1] = (words[i] >>> 8) & 0xff;
      out[i * 4 + 2] = (words[i] >>> 16) & 0xff;
      out[i * 4 + 3] = (words[i] >>> 24) & 0xff;
    }
    return out;
  }

  root.datuBlake3 = { hash32 };
})(typeof globalThis !== 'undefined' ? globalThis : this);
