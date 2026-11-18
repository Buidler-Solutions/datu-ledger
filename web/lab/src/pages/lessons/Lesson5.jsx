import { useEffect, useState } from 'react';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson5({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const [witnesses, setWitnesses] = useState([]);
  const [log, setLog] = useState([]);

  const load = async () => {
    if (!node) return;
    const data = await sandbox.checkpoints(node.id);
    setWitnesses(data.witnesses || []);
  };

  useEffect(() => {
    load();
  }, [node?.id, entries.length]);

  const checkpoint = async () => {
    try {
      const r = await run(() => sandbox.checkpoint(node.id));
      setLog((prev) => [...prev, { kind: 'cmd', text: 'datu checkpoint' }, { kind: 'out', text: r.output }]);
      await load();
    } catch (e) {
      setLog((prev) => [...prev, { kind: 'cmd', text: 'datu checkpoint' }, { kind: 'err', text: e.message }]);
    }
  };

  return (
    <LessonShell
      id={5}
      kicker="Lesson 05 · witnessing"
      title="Checkpoints and witnesses"
      lede="A checkpoint is a signed Merkle root over every entry id a node has seen, at a height. One checkpoint proves what you had. Two witnesses that disagree prove someone is lying, and the proof is a few hundred bytes."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>Sign a checkpoint</h3>
          <p className="small">
            The root changes when your view of the ledger changes. The height counts the checkpoints
            you have signed, so a later checkpoint supersedes an earlier one without deleting it.
          </p>
          <button className="btn" type="button" disabled={busy} onClick={checkpoint}>
            Run datu checkpoint
          </button>
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="datu checkpoint" height={180} />
      </Reveal>

      <Reveal>
        <div className="panel">
          <h3>Witnesses on your node</h3>
          <table className="data">
            <thead><tr><th>signer</th><th>height</th><th>entries</th><th>merkle root</th></tr></thead>
            <tbody>
              {witnesses.map((w) => (
                <tr key={w.signer + w.height}>
                  <td className="mono">{w.signer === node?.identity ? 'you' : <Hash value={w.signer} />}</td>
                  <td className="mono">{w.height}</td>
                  <td className="mono">{w.entries_count}</td>
                  <td className="mono dim"><Hash value={w.entry_ids_root} /></td>
                </tr>
              ))}
              {witnesses.length === 0 && <tr><td colSpan={4} className="dim small">no checkpoints yet</td></tr>}
            </tbody>
          </table>
        </div>
      </Reveal>

      <Reveal>
        <div className="grid cols-3">
          <div className="card">
            <span className="tag">detect deletion</span>
            <p className="small">A node that hides records after a witness checkpoint contradicts that checkpoint's root. The evidence travels as a stream of signed checkpoints.</p>
          </div>
          <div className="card">
            <span className="tag">detect rewriting</span>
            <p className="small">Rewrite one record and every root that covered it changes. Same signer, same height, different root is cryptographic proof of a fork.</p>
          </div>
          <div className="card">
            <span className="tag">no coordination</span>
            <p className="small">Witnesses never vote. Each one signs what it saw, on its own schedule. Disagreement is data, not a deadlock.</p>
          </div>
        </div>
      </Reveal>

      <Exercise
        title="Witness your own ledger"
        solved={done}
        onSolved={() => mark(5)}
        check={async () => {
          const data = await sandbox.checkpoints(node.id);
          const mine = (data.witnesses || []).filter((w) => w.signer === node.identity);
          if (!mine.length) return { ok: false, message: 'no checkpoint by your key yet: run datu checkpoint' };
          const latest = mine.reduce((a, b) => (a.height >= b.height ? a : b));
          const entryCount = (await sandbox.entries(node.id)).entries.length;
          if (latest.entries_count < 2) return { ok: false, message: 'checkpoint covers too few entries' };
          if (latest.entries_count > entryCount) return { ok: false, message: 'checkpoint claims more entries than the node holds' };
          return { ok: true, message: `checkpoint height ${latest.height} covers ${latest.entries_count} entries, root ${latest.entry_ids_root.slice(0, 12)}…` };
        }}
      >
        Run <code>datu checkpoint</code>. The check reads the witness list and requires your key to
        appear with a root covering at least two entries. Run it again after publishing something
        new and watch height and root change while the old checkpoint stays.
      </Exercise>
    </LessonShell>
  );
}
