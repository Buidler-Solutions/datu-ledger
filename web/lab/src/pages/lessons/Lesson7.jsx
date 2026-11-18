import { useState } from 'react';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { peerSandbox, sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson7({ mark, done }) {
  const { node, entries, busy } = useSandbox();
  const [peer, setPeer] = useState(null);
  const [log, setLog] = useState([]);
  const [exported, setExported] = useState(null);

  const push = (cmd, out, err) =>
    setLog((prev) => [...prev, { kind: 'cmd', text: cmd }, ...(out ? [{ kind: 'out', text: out }] : []), ...(err ? [{ kind: 'err', text: err }] : [])]);

  const ensurePeer = async () => {
    const p = await peerSandbox.ensure();
    setPeer(p);
    push('sandbox B created', `identity ${p.identity}`);
    return p;
  };

  const doExport = async () => {
    try {
      const r = await sandbox.exportBundle(node.id);
      setExported(r);
      push('datu bundle export --out history.bundle', `${r.output}\n${r.size} bytes, base64-encoded for the browser`);
    } catch (e) {
      push('datu bundle export', null, e.message);
    }
  };

  const doImport = async (p) => {
    if (!exported) return;
    try {
      const r = await sandbox.importBundle(p.id, exported.bundle);
      push('datu bundle import --input history.bundle   (on B)', r.output);
    } catch (e) {
      push('datu bundle import', null, e.message);
    }
  };

  return (
    <LessonShell
      id={7}
      kicker="Lesson 07 · offline transfer"
      title="Offline channels"
      lede="Not every movement of history happens over a network. A bundle is the complete ledger in one file: carry it on a USB stick, attach it to an email, mail a DVD. Import verifies every record before accepting any of it."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>Three ways to move history</h3>
          <table className="data">
            <thead><tr><th>channel</th><th>what moves</th><th>when</th></tr></thead>
            <tbody>
              <tr><td className="mono">sync</td><td>what the peer lacks (Bloom reconciliation)</td><td>both online, LAN or WAN</td></tr>
              <tr><td className="mono">bundle</td><td>the entire store plus checkpoints</td><td>one-way copy, air-gapped handoff</td></tr>
              <tr><td className="mono">delta</td><td>have/want request and answer files</td><td>sneakernet with smaller payloads</td></tr>
            </tbody>
          </table>
        </div>
      </Reveal>

      <Reveal>
        <div className="btn-row">
          <button className="btn ghost" type="button" disabled={busy} onClick={doExport}>Export A</button>
          {peer ? (
            <>
              <span className="badge ok"><span className="dot live" /> B: <Hash value={peer.identity} /></span>
              <button className="btn" type="button" disabled={!exported || busy} onClick={() => doImport(peer)}>
                Import into B
              </button>
            </>
          ) : (
            <button className="btn ghost" type="button" onClick={ensurePeer}>Create sandbox B</button>
          )}
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="datu bundle" height={220} />
      </Reveal>

      <Exercise
        title="Carry history by hand"
        solved={done}
        onSolved={() => mark(7)}
        check={async () => {
          const p = peer || (await peerSandbox.ensure());
          setPeer(p);
          const mine = await sandbox.entries(node.id);
          const target = mine.entries.find((e) => e.namespace !== 'genesis');
          if (!target) return { ok: false, message: 'publish something on A first' };
          const theirs = await sandbox.entries(p.id);
          if (!theirs.entries.some((e) => e.id === target.id)) {
            return { ok: false, message: 'B does not hold A\'s history yet: export from A and import into B' };
          }
          return { ok: true, message: `B restored ${theirs.entries.length} entries from the bundle, no network involved` };
        }}
      >
        Export a bundle from A and import it into B (no sync). The check requires B to hold a record
        that originated on A. Import is idempotent: importing twice reports entries already present.
      </Exercise>

      <Reveal>
        <div className="ok-box small">
          <strong>Why this matters:</strong> an institution can run for months without a working
          network, exchanging signed history by hand, then reconcile when connectivity returns.
          Nothing about the ledger assumes a live peer.
        </div>
      </Reveal>
    </LessonShell>
  );
}
