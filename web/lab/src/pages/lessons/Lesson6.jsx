import { useState } from 'react';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { peerSandbox, sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson6({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const [peer, setPeer] = useState(null);
  const [log, setLog] = useState([]);
  const [publishedId, setPublishedId] = useState(null);

  const push = (cmd, out, err) =>
    setLog((prev) => [...prev, { kind: 'cmd', text: cmd }, ...(out ? [{ kind: 'out', text: out }] : []), ...(err ? [{ kind: 'err', text: err }] : [])]);

  const ensurePeer = async () => {
    const p = await peerSandbox.ensure();
    setPeer(p);
    push('sandbox B created', `identity ${p.identity}`);
    return p;
  };

  const publishHere = async () => {
    const r = await sandbox.publish(node.id, 'general', '{"travel":"by sync"}');
    setPublishedId(r.id);
    await run(async () => {});
    push('datu publish --ns general', r.output);
  };

  const sync = async (p) => {
    try {
      const r = await sandbox.sync(p.id, node.id);
      push('datu sync --peer http://127.0.0.1:<A>   (run on B)', r.output);
    } catch (e) {
      push('datu sync', null, e.message);
    }
  };

  return (
    <LessonShell
      id={6}
      kicker="Lesson 06 · networking"
      title="Two nodes, one history"
      lede="Sync is pull-only and reconciliation is a Bloom filter exchange: a node asks a peer for what it lacks, verifies every record on arrival, and skips what it already has. There is no gossip, no broadcast, no leader."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>Setup</h3>
          <div className="btn-row">
            {peer ? (
              <span className="badge ok"><span className="dot live" /> sandbox B: <Hash value={peer.identity} /></span>
            ) : (
              <button className="btn ghost" type="button" onClick={ensurePeer}>Create sandbox B</button>
            )}
            <button className="btn ghost" type="button" onClick={publishHere}>Publish on A</button>
            <button className="btn" type="button" disabled={!peer || busy} onClick={() => sync(peer)}>
              B syncs from A
            </button>
          </div>
          <p className="small dim" style={{ marginTop: 10, marginBottom: 0 }}>
            Both sandboxes are real nodes with independent stores. The peer address is the other
            sandbox's loopback HTTP endpoint; the browser never sees it.
          </p>
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="sync" height={220} />
      </Reveal>

      <Reveal>
        <div className="grid cols-3">
          <div className="card">
            <span className="tag">pull, never push</span>
            <p className="small">Nothing arrives uninvited. A node decides what to ask for and verifies every answer locally.</p>
          </div>
          <div className="card">
            <span className="tag">bloom, not bloat</span>
            <p className="small">The requester sends a Bloom filter of ids it holds; the peer answers with the rest, paged and bounded.</p>
          </div>
          <div className="card">
            <span className="tag">verify on arrival</span>
            <p className="small">A record that fails verification aborts the pull with fork evidence, not a silent drop.</p>
          </div>
        </div>
      </Reveal>

      <Exercise
        title="Reconcile two histories"
        solved={done}
        onSolved={() => mark(6)}
        check={async () => {
          const p = peer || (await peerSandbox.ensure());
          setPeer(p);
          const mine = await sandbox.entries(node.id);
          const target = mine.entries.find((e) => e.namespace === 'general' && e.payload_preview?.includes('travel')) || mine.entries.find((e) => e.namespace === 'general');
          if (!target) return { ok: false, message: 'publish something on A first' };
          const theirs = await sandbox.entries(p.id);
          if (!theirs.entries.some((e) => e.id === target.id)) {
            return { ok: false, message: 'B does not hold A\'s record yet: run the sync' };
          }
          return { ok: true, message: `B holds ${theirs.entries.length} entries, including A's ${target.id.slice(0, 12)}…` };
        }}
      >
        Publish a record on A, then sync B from A. The check requires B to hold that exact entry id.
        Run it twice and note that the second sync transfers nothing: known ids are suppressed.
      </Exercise>
    </LessonShell>
  );
}
