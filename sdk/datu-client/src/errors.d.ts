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
export declare function mapError(error: unknown, fallback?: ErrorCodeValue): DatuError;
