import type {
  AuthAssertion,
  AuthChallenge,
  CoverageResult,
  DatuClient,
  DatuIdentity,
  DatuError,
  VerifyResult,
} from '@greenarmor/datu-client';

export interface DatuContextValue {
  client: DatuClient | null;
  connecting: boolean;
  error: DatuError | Error | null;
  extensionState: unknown | null;
}

export interface DatuProviderProps {
  options?: Record<string, unknown>;
  children?: React.ReactNode;
}

export declare function DatuProvider(props: DatuProviderProps): React.ReactElement;
export declare function useDatu(): DatuContextValue;

export interface UseIdentitiesResult {
  identities: DatuIdentity[];
  loading: boolean;
  error: DatuError | Error | null;
  reload: () => Promise<DatuIdentity[]>;
}

export declare function useIdentities(opts?: { bridgeUrl?: string }): UseIdentitiesResult;

export interface SignInOutcome {
  assertion: AuthAssertion;
  verified: boolean | null;
  challenge: AuthChallenge;
}

export interface UseSignInResult {
  signIn: (args?: Parameters<DatuClient['signIn']>[0]) => Promise<SignInOutcome>;
  pending: boolean;
  result: SignInOutcome | null;
  error: DatuError | Error | null;
  reset: () => void;
}

export declare function useSignIn(): UseSignInResult;

export interface UsePartySignResult {
  partySign: (args?: Parameters<DatuClient['partySign']>[0]) => Promise<Record<string, unknown>>;
  pending: boolean;
  result: Record<string, unknown> | null;
  error: DatuError | Error | null;
}

export declare function usePartySign(): UsePartySignResult;

export interface UseCoverageResult {
  coverage: CoverageResult | null;
  loading: boolean;
  error: DatuError | Error | null;
  reload: () => Promise<CoverageResult | null>;
}

export declare function useCoverage(
  entryId: string | null | undefined,
  opts?: { enabled?: boolean },
): UseCoverageResult;
