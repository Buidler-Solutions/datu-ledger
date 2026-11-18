import { useCallback, useEffect, useState } from 'react';

// Curriculum: the eight hands-on lessons, distilled from the DATU user
// manual. Order is pedagogical: identity, records, verification, trust,
// witnessing, sync, offline channels, and finally evidence of misbehavior.
export const lessons = [
  {
    id: 1,
    slug: 'genesis',
    title: 'A ledger is born',
    blurb: 'Spin up your own node. Meet the genesis record every ledger from this code begins with, and your identity.',
    minutes: 4,
  },
  {
    id: 2,
    slug: 'publish',
    title: 'Publish and read',
    blurb: 'Sign your first records. Watch them chain into a feed and land in the DAG.',
    minutes: 6,
  },
  {
    id: 3,
    slug: 'verify',
    title: 'Verify everything',
    blurb: 'What a signature actually covers, why entries form a chain, and what verify proves.',
    minutes: 6,
  },
  {
    id: 4,
    slug: 'trust',
    title: 'Attestations: trust as a graph',
    blurb: 'Bind a key to a role. Gate a namespace on who trusts whom. Revoke a key, not a person.',
    minutes: 7,
  },
  {
    id: 5,
    slug: 'witness',
    title: 'Checkpoints and witnesses',
    blurb: 'Sign a Merkle root over everything you have seen. Two witnesses make deletion and rewriting detectable.',
    minutes: 6,
  },
  {
    id: 6,
    slug: 'sync',
    title: 'Two nodes, one history',
    blurb: 'Create a second node, sync it, and see reconciliation move only what is missing.',
    minutes: 6,
  },
  {
    id: 7,
    slug: 'offline',
    title: 'Offline channels',
    blurb: 'Bundles travel by USB, email, or any file channel. Import one and history survives.',
    minutes: 5,
  },
  {
    id: 8,
    slug: 'forks',
    title: 'Forks and evidence',
    blurb: 'What happens when a signer lies. Same-height contradictions, witness streams, and prove-fork.',
    minutes: 8,
  },
];

const DONE_KEY = 'datu-lab-progress';

export function useProgress() {
  const [done, setDone] = useState(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem(DONE_KEY) || '[]'));
    } catch {
      return new Set();
    }
  });
  const mark = useCallback((id) => {
    setDone((prev) => {
      const next = new Set(prev);
      next.add(id);
      localStorage.setItem(DONE_KEY, JSON.stringify([...next]));
      return next;
    });
  }, []);
  const reset = useCallback(() => {
    localStorage.removeItem(DONE_KEY);
    setDone(new Set());
  }, []);
  return { done, mark, reset };
}

export function useLocalFlag(key) {
  const [value, setValue] = useState(() => localStorage.getItem(key) === '1');
  const set = useCallback(
    (v) => {
      setValue(v);
      if (v) localStorage.setItem(key, '1');
      else localStorage.removeItem(key);
    },
    [key],
  );
  useEffect(() => {}, []);
  return [value, set];
}
