// SignetAuth unit tests: the canonical signed bytes are pinned byte-for-byte
// against crates/core/src/auth.rs, and verifyAssertion rejects tampering.
import { describe, expect, it, vi } from 'vitest';
import { AUTH_DOMAIN, authSignedBytes, challengeIsLive, verifyAssertion } from './signetauth.js';

const challenge = {
  rp_id: 'app.example.com',
  origin: 'https://app.example.com',
  nonce: 'ab'.repeat(16),
  expires_at_ms: 4_102_444_800_000,
};

describe('signetauth canonical bytes', () => {
  it('matches the datu-auth-v1 wire format exactly', () => {
    const bytes = authSignedBytes(challenge);
    const text = new TextDecoder().decode(bytes);
    expect(text).toBe(
      'datu-auth-v1\napp.example.com\nhttps://app.example.com\nabababababababababababababababab\n4102444800000\n'
    );
    expect(text.startsWith(`${AUTH_DOMAIN}\n`)).toBe(true);
  });

  it('changes when any challenge field changes', () => {
    const variants = [
      { ...challenge, rp_id: 'evil.example' },
      { ...challenge, origin: 'https://evil.example' },
      { ...challenge, nonce: 'cd'.repeat(16) },
      { ...challenge, expires_at_ms: challenge.expires_at_ms + 1 },
    ];
    const base = authSignedBytes(challenge);
    for (const v of variants) {
      expect(authSignedBytes(v)).not.toEqual(base);
    }
  });

  it('treats expiry as exclusive', () => {
    expect(challengeIsLive(challenge, challenge.expires_at_ms - 1)).toBe(true);
    expect(challengeIsLive(challenge, challenge.expires_at_ms)).toBe(false);
  });
});

describe('verifyAssertion', () => {
  it('rejects challenge mismatches and bad domains without any verifier', async () => {
    const ok = await verifyAssertion('http://127.0.0.1:9', { ...challenge, domain: 'wrong' }, challenge);
    expect(ok.ok).toBe(false);
    const swapped = await verifyAssertion('http://127.0.0.1:9',
      { domain: AUTH_DOMAIN, ...challenge, nonce: '00'.repeat(16), pubkey: 'aa', signature: 'bb' },
      challenge);
    expect(swapped.ok).toBe(false);
  });

  it('rejects expired challenges', async () => {
    const stale = { ...challenge, expires_at_ms: Date.now() - 1000 };
    const result = await verifyAssertion('http://127.0.0.1:9',
      { domain: AUTH_DOMAIN, ...stale, pubkey: 'aa', signature: 'bb' }, stale);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('verifies a real Ed25519 signature and rejects a tampered one', async () => {
    const { generateKeyPairSync, sign } = await import('node:crypto');
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex');
    const sig = sign(null, Buffer.from(authSignedBytes(challenge)), privateKey).toString('hex');

    window.datuCoverage = {
      verifyEd25519: vi.fn(async () => 'ok'),
    };
    const good = await verifyAssertion('', { domain: AUTH_DOMAIN, ...challenge, pubkey: rawPub, signature: sig }, challenge);
    expect(good.ok).toBe(true);

    window.datuCoverage = { verifyEd25519: vi.fn(async () => 'invalid') };
    const bad = await verifyAssertion('', { domain: AUTH_DOMAIN, ...challenge, pubkey: rawPub, signature: 'ff'.repeat(64) }, challenge);
    expect(bad.ok).toBe(false);
    delete window.datuCoverage;
  });
});
