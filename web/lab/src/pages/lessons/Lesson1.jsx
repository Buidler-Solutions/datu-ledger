import Exercise from '../../components/Exercise';
import Hash from '../../components/Hash';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';
import { sandbox } from '../../lib/api';
import { useSandbox } from '../../lib/useSandbox';

export default function Lesson1({ mark, done }) {
  const { node, entries, run, busy } = useSandbox();
  const genesis = entries.find((e) => e.namespace === 'genesis');

  return (
    <LessonShell
      id={1}
      kicker="Lesson 01 · genesis"
      title="A ledger is born"
      lede="Before you sign anything, a ledger has to exist. DATU starts every store from the same founder-signed genesis record: a lineage mark, not an authority. Your node is already running; this lesson shows you what it began with."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <div className="row">
            <h3 style={{ margin: 0 }}>Your identity</h3>
            <span className="spacer" />
            <span className="badge ok"><span className="dot live" /> node live</span>
          </div>
          <p className="small muted" style={{ marginTop: 10 }}>
            <code>datu init</code> generated two private keys: Ed25519 for speed and ML-DSA-65 for
            quantum resistance. The ledger records your public Ed25519 key, and every entry you
            publish carries both signatures.
          </p>
          <div className="row">
            <span className="dim small" style={{ width: 96 }}>public key</span>
            <Hash value={node?.identity} />
          </div>
        </div>
      </Reveal>

      <Reveal delay={80}>
        <div className="panel">
          <h3>The genesis record</h3>
          <p className="small">
            Every ledger seeded from this code begins with the same entry, authored by the founder key
            hardcoded in <code>crates/core/genesis.rs</code>. It proves lineage: your store was not
            quietly seeded by foreign software. It grants the founder nothing.
          </p>
          {genesis ? (
            <Terminal
              title="genesis"
              lines={[
                { kind: 'cmd', text: 'datu get --id ' + genesis.id.slice(0, 16) },
                { kind: 'out', text: `author    ${genesis.author}\nnamespace ${genesis.namespace}\nid        ${genesis.id}` },
              ]}
            />
          ) : (
            <p className="dim small">loading genesis…</p>
          )}
        </div>
      </Reveal>

      <Exercise
        title="Prove the lineage"
        solved={done}
        onSolved={() => mark(1)}
        check={async () => {
          const data = await sandbox.entries(node.id);
          const first = data.entries[0];
          if (!first) return { ok: false, message: 'no entries found' };
          if (first.namespace !== 'genesis') return { ok: false, message: 'the first entry is not the genesis record' };
          const v = await sandbox.verify(node.id);
          if (!/^OK:/.test(v.output || '')) return { ok: false, message: 'verify did not report OK' };
          if (!/lineage: intact/.test(v.output || '')) return { ok: false, message: 'lineage is not intact' };
          return { ok: true, message: 'genesis is the first entry and verify reports intact lineage' };
        }}
      >
        Run <code>datu verify</code> against your node. It must report an OK line and
        <code> lineage: intact</code>, with the genesis record as the first entry of the ledger.
        Use the button below, or hit Verify in the laboratory.
      </Exercise>

      <Reveal>
        <div className="ok-box small">
          <strong>What just happened:</strong> a store, two private keys, a signed genesis, and a full
          verification. There is no account, no registration, no server. That is the entire trust
          bootstrap.
        </div>
      </Reveal>
    </LessonShell>
  );
}
