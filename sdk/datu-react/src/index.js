/**
 * @greenarmor/datu-react - React hooks for the DATU SDK.
 *
 * Thin, build-free bindings over @greenarmor/datu-client (plain
 * React.createElement, no JSX step): a provider that owns the client
 * connection, plus hooks for SignetAuth sign-in, identity listing,
 * party signing and coverage checks. Keys still never leave the Signet
 * extension; every hook just routes to it.
 */
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { connect } from '@greenarmor/datu-client';

const DatuContext = createContext(null);

/**
 * Owns the SDK client. `options` are the connect() options (bridgeUrl,
 * nodeUrl, rpId, origin, transport, fetchImpl...); changing them reconnects.
 */
export function DatuProvider({ options, children }) {
  const [client, setClient] = useState(null);
  const [error, setError] = useState(null);
  const [extensionState, setExtensionState] = useState(null);
  // Functions inside options (transport, fetchImpl) cannot live in a effect
  // key, so the key is the JSON-serializable part and connect() always sees
  // the latest options object via the ref.
  const optionsRef = useRef(options);
  optionsRef.current = options;
  const optionsKey = useMemo(
    () => JSON.stringify(options, (_name, value) => (typeof value === 'function' ? undefined : value)) || '{}',
    [options],
  );

  useEffect(() => {
    let cancelled = false;
    let unsubscribe;
    setClient(null);
    setError(null);
    connect(optionsRef.current)
      .then((connected) => {
        if (cancelled) return;
        setClient(connected);
        if (connected.onState) unsubscribe = connected.onState(setExtensionState);
      })
      .catch((e) => {
        if (!cancelled) setError(e);
      });
    return () => {
      cancelled = true;
      try {
        if (unsubscribe) unsubscribe();
      } catch {}
    };
  }, [optionsKey]);

  const value = useMemo(
    () => ({
      client,
      error,
      connecting: !client && !error,
      extensionState,
    }),
    [client, error, extensionState],
  );
  return createElement(DatuContext.Provider, { value }, children);
}

/** The client connection: { client, connecting, error, extensionState }. */
export function useDatu() {
  const ctx = useContext(DatuContext);
  if (!ctx) throw new Error('useDatu requires a <DatuProvider> ancestor');
  return ctx;
}

/** Identity list from the paired Signet: { identities, loading, error, reload }. */
export function useIdentities({ bridgeUrl } = {}) {
  const { client } = useDatu();
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    if (!client) return [];
    setLoading(true);
    setError(null);
    try {
      const listed = await client.identities(bridgeUrl);
      setIdentities(listed);
      return listed;
    } catch (e) {
      setError(e);
      return [];
    } finally {
      setLoading(false);
    }
  }, [client, bridgeUrl]);

  useEffect(() => {
    reload();
  }, [reload]);
  return { identities, loading, error, reload };
}

/**
 * SignetAuth sign-in: { signIn, pending, result, error, reset }.
 * signIn(args) forwards to client.signIn (approve defaults to true in the
 * SDK, matching a human clicking your Sign in button).
 */
export function useSignIn() {
  const { client } = useDatu();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const signIn = useCallback(
    async (args = {}) => {
      if (!client) throw new Error('not connected yet');
      setPending(true);
      setError(null);
      try {
        const outcome = await client.signIn(args);
        setResult(outcome);
        return outcome;
      } catch (e) {
        setError(e);
        throw e;
      } finally {
        setPending(false);
      }
    },
    [client],
  );

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);
  return { signIn, pending, result, error, reset };
}

/** Party signing: { partySign, pending, result, error } over client.partySign. */
export function usePartySign() {
  const { client } = useDatu();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const partySign = useCallback(
    async (args = {}) => {
      if (!client) throw new Error('not connected yet');
      setPending(true);
      setError(null);
      try {
        const outcome = await client.partySign(args);
        setResult(outcome);
        return outcome;
      } catch (e) {
        setError(e);
        throw e;
      } finally {
        setPending(false);
      }
    },
    [client],
  );
  return { partySign, pending, result, error };
}

/**
 * Coverage for one entry: { coverage, loading, error, reload }. Resolves
 * once the client is connected and entryId is set; pass enabled: false to
 * skip (for example until the user opens the record).
 */
export function useCoverage(entryId, { enabled = true } = {}) {
  const { client } = useDatu();
  const [coverage, setCoverage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    if (!client || !entryId) return null;
    setLoading(true);
    setError(null);
    try {
      const answer = await client.verifyCoverage(entryId);
      setCoverage(answer);
      return answer;
    } catch (e) {
      setError(e);
      return null;
    } finally {
      setLoading(false);
    }
  }, [client, entryId]);

  useEffect(() => {
    if (enabled) reload();
  }, [reload, enabled]);
  return { coverage, loading, error, reload };
}
