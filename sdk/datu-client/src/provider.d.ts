export declare const PROVIDER_DOMAIN: 'datu-provider-v1';
export declare function providerProofBytes(proof: {
  nonce: string;
  origin: string;
  version: string;
  expires_at_ms: number;
}): Uint8Array;
export declare function verifyProviderProof(
  proof: any,
  challenge: { nonce: string; nowMs?: number },
): Promise<{ ok: boolean | null; reason?: string }>;
export declare function pinBridgeKey(
  bridgeUrl: string,
  bridgePubkey: string,
  expected?: string,
): { ok: boolean; reason?: string; pinnedNow: boolean };
