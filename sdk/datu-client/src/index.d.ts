export type Hex = string;

export interface DatuIdentity {
  name: string;
  ed_public: Hex;
  pq_alg?: string;
  pq_public_prefix?: Hex;
  seal_public: Hex;
  created_at_ms?: number;
}

export interface AuthChallenge {
  rp_id: string;
  origin: string;
  nonce: Hex;
  expires_at_ms: number;
}

export interface AuthAssertion {
  ok?: boolean;
  domain?: 'datu-auth-v1';
  rp_id: string;
  origin: string;
  nonce: Hex;
  expires_at_ms: number;
  pubkey: Hex;
  signature: Hex;
  grant?: string;
  grant_expires_at_ms?: number;
}

export interface VerifyResult {
  ok: boolean | null;
  reason?: string;
}

export interface SignResult {
  status: number;
  body: any;
}

export interface ProviderProof {
  ok?: boolean;
  domain?: 'datu-provider-v1';
  nonce: Hex;
  origin: string;
  version: string;
  expires_at_ms: number;
  bridge_pubkey: Hex;
  signature: Hex;
  bridgeUrl?: string;
}

export interface ProveGenuineResult {
  /** True only when a paired provider answered a valid (or unverified) proof. */
  genuine: boolean;
  /** False means no answer at all: the bridge is down, not malicious. */
  reachable: boolean;
  /** True when the signature verified locally; null/false without a verifier. */
  verified?: boolean;
  pinned?: boolean;
  reason?: string;
  bridgeUrl?: string;
  version?: string;
  bridgePubkey?: Hex;
  proof?: ProviderProof;
  nonce: Hex;
}

export interface CoverageWitness {
  signer: Hex;
  timestamp_ms: number;
  height: number;
  [key: string]: unknown;
}

export interface CoverageResult {
  entryId: Hex;
  witnesses: Array<CoverageWitness & { verdict: string }>;
  stale: Array<{ signer: Hex; reason: string }>;
}

export type ErrorCodeValue =
  | 'NOT_CONNECTED'
  | 'NOT_PAIRED'
  | 'NEEDS_APPROVAL'
  | 'NEEDS_PASSPHRASE'
  | 'ORIGIN_MISMATCH'
  | 'GRANT_EXPIRED'
  | 'UNKNOWN_ROUTE'
  | 'REJECTED'
  | 'TIMEOUT'
  | 'BRIDGE_ERROR'
  | 'NODE_ERROR'
  | 'POLICY_DENIED'
  | 'CONFLICT'
  | 'RATE_LIMITED'
  | 'BAD_ARGUMENT';

export declare class DatuError extends Error {
  code: ErrorCodeValue;
  details: Record<string, unknown>;
  constructor(code: ErrorCodeValue, message: string, details?: Record<string, unknown>);
}

export declare const ErrorCode: Record<ErrorCodeValue, ErrorCodeValue>;

export interface ExtensionTransport {
  ping(): Promise<{ pong?: boolean; version?: string } | null>;
  identities(bridgeUrl?: string): Promise<{ identities: DatuIdentity[]; bridgeUrl?: string }>;
  prove(args: { bridgeUrl?: string; nonce?: Hex }): Promise<ProviderProof>;
  sign(args: { bridgeUrl?: string; path: string; body: any; summary?: string }): Promise<SignResult>;
  onState(fn: (state: { connected?: boolean; wallets?: unknown[]; unlocked?: string[] }) => void): () => void;
}

export interface NodeClient {
  url: string;
  status(): Promise<{ entries: number; checkpoints: number; policy?: { mode?: string } }>;
  entries(opts?: { ns?: string; author?: Hex; limit?: number }): Promise<{ entries: any[] }>;
  entry(id: Hex): Promise<any>;
  coverage(entryId: Hex, checkpointId?: Hex): Promise<any>;
  contractStatus(entryId: Hex): Promise<any>;
  feedHead(author: Hex): Promise<any>;
  submit(entry: any): Promise<any>;
  raw(path: string, opts?: { method?: string; body?: any; timeoutMs?: number }): Promise<any>;
}

export interface ConnectOptions {
  bridgeUrl?: string;
  nodeUrl?: string;
  transport?: ExtensionTransport;
  fetchImpl?: typeof fetch;
  rpId?: string;
  origin?: string;
  detect?: boolean;
}

export interface DatuClient {
  bridgeUrl?: string;
  readonly nodeUrl: string;
  setNodeUrl(url: string): void;
  readonly node: NodeClient;
  rpc: ExtensionTransport;
  ping(): Promise<{ pong?: boolean; version?: string } | null>;
  identities(): Promise<DatuIdentity[]>;
  onState(fn: (state: unknown) => void): () => void;
  sign(args: { name?: string; path: string; body: any; summary?: string }): Promise<SignResult>;
  bridge(path: string, body: any, summary?: string): Promise<SignResult>;
  startLogin(opts?: Partial<AuthChallenge> & { rpId?: string; origin?: string; ttlMs?: number; nonce?: Hex }): {
    challenge: AuthChallenge;
    verify(assertion: AuthAssertion): Promise<VerifyResult>;
  };
  signIn(opts?: {
    name?: string;
    rpId?: string;
    origin?: string;
    ttlMs?: number;
    nonce?: Hex;
    summary?: string;
    /** Refuse an assertion that could not be verified locally (default false). */
    strict?: boolean;
    /** Approval gesture for first use of a site (default true). */
    approve?: boolean;
    /** Session grant from a previous login, for silent re-logins. */
    grant?: string;
    /** Trusted-host only (never a browser page): sign in without the extension. */
    passphrase?: string;
  }): Promise<{ assertion: AuthAssertion; verified: boolean | null; challenge: AuthChallenge }>;
  proveGenuine(opts?: {
    bridgeUrl?: string;
    nonce?: Hex;
    /** Explicit trust: reject any other bridge key (wins over the TOFU pin). */
    expectedBridgePubkey?: Hex;
    nowMs?: number;
  }): Promise<ProveGenuineResult>;
  partySign(args: { name?: string; role: string; document: any; kind?: string; summary?: string }): Promise<SignResult>;
  signEntry(args: { name?: string; request: any; summary?: string }): Promise<SignResult>;
  seal(args: { name?: string; document: any; fields: string[] | string; to?: string[] | string; toFields?: string[] | string; summary?: string }): Promise<SignResult>;
  sealDeferred(args: { name?: string; document: any; fields: string[] | string; to?: string | string[]; toField?: string; summary?: string }): Promise<SignResult>;
  releaseDeferred(args: { document: any; field: string; release: any }): Promise<SignResult>;
  openDeferred(args: { name?: string; document: any; field: string; release: any; summary?: string }): Promise<SignResult>;
  openSealed(args: { name?: string; document: any; summary?: string }): Promise<SignResult>;
  verifyEntry(args: { name?: string; entry: any }): Promise<SignResult>;
  verifyCoverage(entryId: Hex, opts?: { coverageVerifier?: any }): Promise<CoverageResult>;
  /** Load the node's /coverage.js verifier (browser only; null elsewhere). */
  loadCoverageVerifier(): Promise<any>;
  onError(e: unknown): DatuError;
}

export declare function connect(opts?: ConnectOptions): Promise<DatuClient>;

export declare function createExtensionTransport(opts?: {
  timeoutMs?: number;
  pingMs?: number;
}): ExtensionTransport;

export declare function createNodeClient(opts?: { nodeUrl?: string; fetchImpl?: typeof fetch }): NodeClient;

export declare const AUTH_DOMAIN: 'datu-auth-v1';
export declare const NONCE_BYTES: number;
export declare const DEFAULT_TTL_MS: number;
export declare function randomNonceHex(): Hex;
export declare function newChallenge(opts: { rpId: string; origin: string; ttlMs?: number; nonce?: Hex }): AuthChallenge;
export declare function authSignedBytes(challenge: AuthChallenge): Uint8Array;
export declare function challengeIsLive(challenge: AuthChallenge, nowMs?: number): boolean;
export declare function verifyEd25519(pubkeyHex: Hex, message: Uint8Array | string, signatureHex: Hex): Promise<'ok' | 'invalid' | 'unavailable'>;
export declare function verifyAssertion(assertion: AuthAssertion, challenge: AuthChallenge): Promise<VerifyResult>;

export declare const PROVIDER_DOMAIN: 'datu-provider-v1';
export declare function providerProofBytes(proof: {
  nonce: string;
  origin: string;
  version: string;
  expires_at_ms: number;
}): Uint8Array;
export declare function verifyProviderProof(proof: any, challenge: { nonce: string; nowMs?: number }): Promise<VerifyResult>;
export declare function pinBridgeKey(bridgeUrl: string, bridgePubkey: string, expected?: string): { ok: boolean; reason?: string; pinnedNow: boolean };

declare const _default: { connect: typeof connect };
export default _default;
