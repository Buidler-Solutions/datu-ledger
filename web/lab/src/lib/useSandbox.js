import { useCallback, useEffect, useState } from 'react';
import { sandbox } from './api';

// One hook for every lesson and the lab: ensure a node exists, keep its
// entries in sync, and give mutations a common busy/error wrapper.
export function useSandbox() {
  const [node, setNode] = useState(null);
  const [entries, setEntries] = useState([]);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const n = await sandbox.ensure();
    setNode(n);
    const data = await sandbox.entries(n.id);
    setEntries(data.entries || []);
    return n;
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const run = useCallback(
    async (fn) => {
      setBusy(true);
      setError(null);
      try {
        const result = await fn();
        await refresh();
        return result;
      } catch (e) {
        setError(e.message);
        throw e;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  return { node, entries, error, busy, refresh, run, setError };
}
