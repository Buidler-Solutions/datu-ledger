/**
 * Typed errors for DATU integrations. The `code` is stable; the message is for
 * humans. Every transport failure is mapped here so apps can branch on `code`
 * instead of matching strings.
 */
export const ErrorCode = Object.freeze({
  NOT_CONNECTED: 'NOT_CONNECTED',
  NOT_PAIRED: 'NOT_PAIRED',
  NEEDS_APPROVAL: 'NEEDS_APPROVAL',
  NEEDS_PASSPHRASE: 'NEEDS_PASSPHRASE',
  ORIGIN_MISMATCH: 'ORIGIN_MISMATCH',
  GRANT_EXPIRED: 'GRANT_EXPIRED',
  UNKNOWN_ROUTE: 'UNKNOWN_ROUTE',
  REJECTED: 'REJECTED',
  TIMEOUT: 'TIMEOUT',
  BRIDGE_ERROR: 'BRIDGE_ERROR',
  NODE_ERROR: 'NODE_ERROR',
  POLICY_DENIED: 'POLICY_DENIED',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  BAD_ARGUMENT: 'BAD_ARGUMENT',
});

export class DatuError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'DatuError';
    this.code = code;
    this.details = details;
  }
}

const RULES = [
  [/not paired|pairing token/i, ErrorCode.NOT_PAIRED],
  [/needs_approval|approve it once|first login/i, ErrorCode.NEEDS_APPROVAL],
  [/missing 'passphrase'|passphrase must be|wrong passphrase|too many wrong/i, ErrorCode.NEEDS_PASSPHRASE],
  [/origin mismatch/i, ErrorCode.ORIGIN_MISMATCH],
  [/grant unknown|grant expired|for another identity/i, ErrorCode.GRANT_EXPIRED],
  [/no route for/i, ErrorCode.UNKNOWN_ROUTE],
  [/rate limit|retry_after/i, ErrorCode.RATE_LIMITED],
  [/no answer from the wallet extension|not detected|reloaded/i, ErrorCode.NOT_CONNECTED],
  [/timed out|timeout/i, ErrorCode.TIMEOUT],
  [/rejected in the signet|rejected/i, ErrorCode.REJECTED],
];

export function mapError(error, fallback = ErrorCode.BRIDGE_ERROR) {
  if (error instanceof DatuError) return error;
  const message = String((error && error.message) || error || 'unknown error');
  for (const [pattern, code] of RULES) {
    if (pattern.test(message)) return new DatuError(code, message);
  }
  return new DatuError(fallback, message);
}
