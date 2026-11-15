export interface MockKey {
  pubkeyHex: string;
  sign(bytes: Uint8Array): Promise<string> | string;
}

export declare function mockTransport(opts?: {
  identities?: Array<{ name: string; ed_public: string; seal_public: string }>;
  keys?: Record<string, MockKey>;
  proofKey?: MockKey | null;
  state?: { fail?: { code?: string; message: string } } | null;
  latencyMs?: number;
}): {
  calls: Array<{ path: string; body: any }>;
  ping(): Promise<{ pong: boolean; version: string }>;
  identities(): Promise<{ identities: any[] }>;
  prove(args?: { nonce?: string }): Promise<any>;
  sign(args: { path: string; body: any }): Promise<{ status: number; body: any }>;
  onState(fn: (state: unknown) => void): () => void;
};

export declare function mockFetch(opts?: {
  routes?: Record<string, (body: any, path: string) => any>;
  nodeUrl?: string;
}): { fetchImpl: typeof fetch; requests: Array<{ path: string; method: string; body?: string }> };
