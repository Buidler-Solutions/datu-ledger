import { useState } from 'react';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson3({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const [detail, setDetail] = useState(null);
  const [log, setLog] = useState([]);

  const pick = entries.find((e) => e.namespace === 'general') || entries.find((e) => e.namespace !== 'genesis');
  const id = pick?.id;

  const inspect = async () => {
    if (!id) return;
    setLog((prev) => [...prev, { kind: 'cmd', text: `datu get --id ${id.slice(0, 12)}…` }]);
    const full = await sandbox.entry(node.id, id);
    setDetail(full);
    setLog((prev) => [...prev, { kind: 'out', text: JSON.stringify(full, null, 2) }]);
  };

  const verify = async () => {
    try {
      const r = await run(() => sandbox.verify(node.id));
      setLog((prev) => [...prev, { kind: 'cmd', text: 'datu verify' }, { kind: 'out', text: r.output }]);
    } catch (e) {
      setLog((prev) => [...prev, { kind: 'cmd', text: 'datu verify' }, { kind: 'err', text: e.message }]);
    }
  };

  return (
    <LessonShell
      id={3}
      kicker="Lesson 03 · verification"
      title="Verify everything"
      lede="A DATU record is content-addressed and doubly signed: the id is BLAKE3 over the entry body, and the body carries Ed25519 and ML-DSA-65 signatures from the author. verify recomputes all of it, offline, from bytes you control."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>Anatomy of an entry</h3>
          <div className="btn-row">
            <button className="btn ghost" type="button" onClick={inspect} disabled={!id}>
              Inspect one of your records
            </button>
            <button className="btn ghost" type="button" onClick={verify} disabled={busy}>
              Run verify
            </button>
          </div>
          <div className="grid cols-3" style={{ marginTop: 16 }}>
            <div className="card">
              <span className="tag">identity is content</span>
              <p className="small">The id is the BLAKE3 hash of the canonical entry body. Change one byte of the body and the id changes.</p>
            </div>
            <div className="card">
              <span className="tag">order is chained</span>
              <p className="small"><code>prev</code> points at the previous record from the same author; <code>refs</code> point anywhere in the graph.</p>
            </div>
            <div className="card">
              <span className="tag">two signatures</span>
              <p className="small">Ed25519 for today, ML-DSA-65 for the quantum era. Both must verify, on every node, forever.</p>
            </div>
          </div>
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="datu get / datu verify" height={340} />
      </Reveal>

      <Reveal>
        <div className="panel">
          <h3>What verification is not</h3>
          <p className="small" style={{ marginBottom: 0 }}>
            It is not consensus. No node asks another for permission to accept a record. Each node
            recomputes hashes and signatures from raw bytes, so a peer can be offline, dishonest,
            or gone; the math either holds or it does not.
          </p>
        </div>
      </Reveal>

      <Exercise
        title="Read the proof yourself"
        solved={done}
        onSolved={() => mark(3)}
        check={async () => {
          const data = await sandbox.entries(node.id);
          const e = data.entries.find((x) => x.namespace !== 'genesis');
          if (!e) return { ok: false, message: 'publish a record in lesson 2 first' };
          const full = await sandbox.entry(node.id, e.id);
          if (!/^[0-9a-f]{64}$/.test(full.signature || '')) return { ok: false, message: 'entry has no Ed25519 signature' };
          if (!full.pq_signature) return { ok: false, message: 'entry has no ML-DSA-65 signature' };
          if (!/^[0-9a-f]{64}$/.test(full.id)) return { ok: false, message: 'entry id is not a 64 hex hash' };
          const v = await sandbox.verify(node.id);
          if (!/^OK:/.test(v.output || '')) return { ok: false, message: 'verify did not report OK' };
          return { ok: true, message: 'entry carries both signatures; full verify is clean' };
        }}
      >
        Inspect a record and confirm it carries both signatures, then run verify. The check fetches
        the entry over the node API and inspects the raw fields, the same thing an auditor would do
        with <code>datu get --id</code>.
      </Exercise>

      {detail && (
        <Reveal>
          <div className="panel">
            <h3>Selected entry</h3>
            <div className="row small"><span className="dim" style={{ width: 110 }}>id</span><Hash value={detail.id} full /></div>
            <div className="row small" style={{ marginTop: 6 }}><span className="dim" style={{ width: 110 }}>author</span><Hash value={detail.author} /></div>
            <div className="row small" style={{ marginTop: 6 }}><span className="dim" style={{ width: 110 }}>payload</span><code>{detail.payload}</code></div>
          </div>
        </Reveal>
      )}
    </LessonShell>
  );
}
