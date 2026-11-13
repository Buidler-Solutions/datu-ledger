export declare const AUTH_DOMAIN: 'datu-auth-v1';
export declare const NONCE_BYTES: number;
export declare const DEFAULT_TTL_MS: number;
export declare function randomNonceHex(): string;
export declare function newChallenge(opts: { rpId: string; origin: string; ttlMs?: number; nonce?: string }): {
  rp_id: string;
  origin: string;
  nonce: string;
  expires_at_ms: number;
};
export declare function authSignedBytes(challenge: {
  rp_id: string;
  origin: string;
  nonce: string;
  expires_at_ms: number;
}): Uint8Array;
export declare function challengeIsLive(
  challenge: { expires_at_ms: number },
  nowMs?: number,
): boolean;
export declare function verifyEd25519(
  pubkeyHex: string,
  message: Uint8Array | string,
  signatureHex: string,
): Promise<'ok' | 'invalid' | 'unavailable'>;
export declare function verifyAssertion(
  assertion: any,
  challenge: any,
): Promise<{ ok: boolean | null; reason?: string }>;
