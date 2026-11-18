import { useState } from 'react';
import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { peerSandbox, sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson4({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const [peer, setPeer] = useState(null);
  const [log, setLog] = useState([]);

  const attestations = entries.filter((e) => e.namespace === 'identity.attest' || e.namespace === 'identity.revoke');

  const push = (cmd, out, err) =>
    setLog((prev) => [...prev, { kind: 'cmd', text: cmd }, ...(out ? [{ kind: 'out', text: out }] : []), ...(err ? [{ kind: 'err', text: err }] : [])]);

  const ensurePeer = async () => {
    const p = await peerSandbox.ensure();
    setPeer(p);
    push('sandbox B created', `identity ${p.identity}\n(this is the key you will attest, then revoke)`);
    return p;
  };

  const attest = async (p) => {
    try {
      const r = await run(() => sandbox.attest(node.id, p.identity, { role: 'clerk', legal_name: 'Example Registry' }));
      push('datu attest create --subject <B> --claims role=clerk', r.output);
    } catch (e) {
      push('datu attest create', null, e.message);
    }
  };

  const revoke = async (p) => {
    try {
      const r = await run(() => sandbox.revoke(node.id, p.identity, 'left the registry'));
      push('datu attest revoke --key <B> --reason "left the registry"', r.output);
    } catch (e) {
      push('datu attest revoke', null, e.message);
    }
  };

  return (
    <LessonShell
      id={4}
      kicker="Lesson 04 · attestations"
      title="Trust as a graph"
      lede="DATU has no accounts and no directory. Instead, keys attest claims about other keys, and those attestations are records like any other. Revocation is a new record too: you never edit history, you extend it."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>The cast</h3>
          <div className="grid cols-2">
            <div className="card">
              <span className="tag">you (attestor)</span>
              <div className="row" style={{ marginTop: 8 }}><Hash value={node?.identity} /></div>
              <p className="small" style={{ marginTop: 8 }}>Publishes attestations and revocations into <code>identity.attest</code> and <code>identity.revoke</code>.</p>
            </div>
            <div className="card">
              <span className="tag">subject</span>
              <div className="row" style={{ marginTop: 8 }}>
                {peer ? <Hash value={peer.identity} /> : <button className="btn ghost small" type="button" onClick={ensurePeer}>Create sandbox B</button>}
              </div>
              <p className="small" style={{ marginTop: 8 }}>A second key that will be attested, then revoked.</p>
            </div>
          </div>
          <div className="btn-row" style={{ marginTop: 14 }}>
            <button className="btn" type="button" disabled={!peer || busy} onClick={() => attest(peer)}>
              Attest B as a clerk
            </button>
            <button className="btn danger" type="button" disabled={!peer || busy} onClick={() => revoke(peer)}>
              Revoke B
            </button>
          </div>
        </div>
      </Reveal>

      <Reveal>
        <Terminal lines={log} title="datu attest" height={220} />
      </Reveal>

      <Reveal>
        <div className="panel">
          <h3>Attestation records on your ledger</h3>
          {attestations.length === 0 && <p className="dim small">none yet: attest B above</p>}
          <table className="data">
            <tbody>
              {attestations.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.namespace}</td>
                  <td className="mono"><Hash value={e.id} /></td>
                  <td className="dim small" style={{ maxWidth: 340 }}>{e.payload_preview}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="small muted" style={{ marginTop: 12, marginBottom: 0 }}>
            Any validator that pins your key as a trust root over a namespace reads these records
            when it decides whether to admit another key's entries. Revocation takes effect the next
            time that validator syncs.
          </p>
        </div>
      </Reveal>

      <Exercise
        title="Attest, then revoke"
        solved={done}
        onSolved={() => mark(4)}
        check={async () => {
          const data = await sandbox.entries(node.id);
          const held = data.entries.filter((e) => e.namespace === 'identity.attest' || e.namespace === 'identity.revoke');
          if (held.length < 2) return { ok: false, message: 'need both an attestation and a revocation on this ledger' };
          const details = await Promise.all(held.map((e) => sandbox.entry(node.id, e.id)));
          const hasAttest = details.some((d) => d.namespace === 'identity.attest');
          const hasRevoke = details.some((d) => d.namespace === 'identity.revoke');
          if (!hasAttest) return { ok: false, message: 'no identity.attest record found' };
          if (!hasRevoke) return { ok: false, message: 'no identity.revoke record found' };
          return { ok: true, message: 'attestation and revocation both on the ledger, in order' };
        }}
      >
        Create sandbox B, attest it, then revoke it. The check requires both record kinds to exist
        on your ledger. Note what did not happen: nothing was deleted, and the attestation still
        exists, exactly as it should as history.
      </Exercise>

      <Reveal>
        <div className="warn-box small">
          <strong>Revocation is a fact, not a filter.</strong> A node that has not yet synced the
          revocation will keep admitting the key. That is why witnesses exist, and why the next
          lesson is about checkpoints.
        </div>
      </Reveal>
    </LessonShell>
  );
}
