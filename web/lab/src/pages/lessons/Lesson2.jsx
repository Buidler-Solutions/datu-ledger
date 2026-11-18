import { useState } from 'react';
import DagCanvas from '../../components/DagCanvas';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { sandbox, timeAgo } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson2({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const [ns, setNs] = useState('general');
  const [payload, setPayload] = useState('{"notice":"first record"}');
  const [log, setLog] = useState([]);
  const [selected, setSelected] = useState(null);

  const mine = entries.filter((e) => e.author === node?.identity).sort((a, b) => a.seq - b.seq);

  const publish = async () => {
    try {
      const r = await run(() => sandbox.publish(node.id, ns, payload));
      setLog((prev) => [...prev, { kind: 'cmd', text: `datu publish --ns ${ns} --payload '${payload}'` }, { kind: 'out', text: r.output }]);
    } catch (e) {
      setLog((prev) => [...prev, { kind: 'cmd', text: `datu publish --ns ${ns} --payload '${payload}'` }, { kind: 'err', text: e.message }]);
    }
  };

  return (
    <LessonShell
      id={2}
      kicker="Lesson 02 · publish"
      title="Publish and read"
      lede="A record is a claim, signed. Publishing appends it to your feed: a per-author chain where seq counts up and prev points at the record before it. Break the chain and verification notices."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>Sign a record</h3>
          <div className="grid cols-2">
            <label className="field">
              <span>namespace</span>
              <input value={ns} onChange={(e) => setNs(e.target.value)} />
            </label>
            <label className="field">
              <span>payload</span>
              <textarea value={payload} onChange={(e) => setPayload(e.target.value)} />
            </label>
          </div>
          <button className="btn" type="button" disabled={busy} onClick={publish}>
            Publish
          </button>
          <p className="small dim" style={{ marginBottom: 0, marginTop: 10 }}>
            Namespaces are free-form labels (<code>gov.records</code>, <code>general</code>); policy,
            not the protocol, decides which ones are gated.
          </p>
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="publish" height={200} />
      </Reveal>

      <Reveal>
        <div className="panel">
          <h3>Your feed</h3>
          <p className="small">
            Records from the same author chain together. Each entry's <code>prev</code> is the id of
            the one before it, so reordering or removing any record invalidates everything after it.
          </p>
          <DagCanvas entries={entries} selected={selected} onSelect={(e) => setSelected(e.id)} />
          <div style={{ marginTop: 14 }}>
            <table className="data">
              <thead><tr><th>seq</th><th>namespace</th><th>id</th><th>prev</th><th>age</th></tr></thead>
              <tbody>
                {mine.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{e.seq}</td>
                    <td className="mono">{e.namespace}</td>
                    <td className="mono"><Hash value={e.id} /></td>
                    <td className="mono dim">{e.prev ? <Hash value={e.prev} /> : 'null'}</td>
                    <td className="dim small">{timeAgo(e.timestamp_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Reveal>

      <Exercise
        title="Grow a feed"
        solved={done}
        onSolved={() => mark(2)}
        check={async () => {
          const data = await sandbox.entries(node.id);
          const mine = data.entries.filter((e) => e.namespace === 'general' && e.author !== undefined).sort((a, b) => a.seq - b.seq);
          if (mine.length < 2) return { ok: false, message: 'publish at least two records in namespace general' };
          const [a, b] = mine;
          if (b.prev !== a.id) return { ok: false, message: 'the second record does not point at the first (prev mismatch)' };
          if (b.seq !== a.seq + 1) return { ok: false, message: 'seq did not increment' };
          return { ok: true, message: `chain verified: seq ${a.seq} -> ${b.seq}, prev matches` };
        }}
      >
        Publish two records in namespace <code>general</code>. The check reads your feed and requires
        the second record's <code>prev</code> to be the first record's id, with <code>seq</code> incremented
        by exactly one.
      </Exercise>

      <Reveal>
        <div className="ok-box small">
          <strong>Mind the order:</strong> publish is local and instant; nothing is broadcast. Peers
          pull what they lack when they sync, which is lesson six.
        </div>
      </Reveal>
    </LessonShell>
  );
}
