import Reveal from '../components/Reveal';
import { lessons } from '../lib/lessons';

export default function Home({ progress }) {
  return (
    <div>
      <header className="hero">
        <div className="kicker rise">an interactive manual</div>
        <h1 className="rise delay-1">
          Learn a ledger by <span className="gradient-text">running one</span>.
        </h1>
        <p className="lede rise delay-2">
          DATU is a tokenless, quantum-resistant accountability ledger: signed records in a graph,
          no miners, no staking, no global consensus. This manual does not describe it. It spins up a
          real node for your browser and asks you to publish, attest, witness, sync and verify.
          Everything you see below happens against the actual <code>datu</code> binary.
        </p>
        <div className="btn-row rise delay-3" style={{ marginTop: 28 }}>
          <a className="btn" href="#/lesson/1">Start the first lesson</a>
          <a className="btn ghost" href="#/lab">Open the laboratory</a>
        </div>
      </header>

      <Reveal>
        <div className="stats" style={{ marginTop: 36 }}>
          <div className="stat">
            <div className="value">0</div>
            <div className="label">tokens, miners, validators-to-bribe</div>
          </div>
          <div className="stat">
            <div className="value">2</div>
            <div className="label">signatures per record (Ed25519 + ML-DSA-65)</div>
          </div>
          <div className="stat">
            <div className="value">243</div>
            <div className="label">tests behind the binary you are using</div>
          </div>
          <div className="stat">
            <div className="value">8</div>
            <div className="label">hands-on lessons, each with graded exercises</div>
          </div>
        </div>
      </Reveal>

      <Reveal>
        <h2>How this laboratory works</h2>
        <div className="split">
          <div className="panel">
            <h3>Your node is real, and temporary</h3>
            <p className="small">
              When you start a lesson the server runs <code>datu init</code> in a throwaway directory,
              generates a fresh Ed25519 + ML-DSA-65 identity, and starts <code>datu serve</code> on a
              loopback port. Every button in this manual shells out to the same release binary an
              operator would run. Nothing is simulated.
            </p>
            <p className="small" style={{ marginBottom: 0 }}>
              Sandboxes expire after 30 idle minutes. You can reset yours from the Laboratory at any
              time. The production network is never touched: your node has no peers unless you create
              a second sandbox and sync them.
            </p>
          </div>
          <div className="panel">
            <h3>What you will be able to do</h3>
            <ul className="small" style={{ paddingLeft: 18, margin: 0, color: '#c6d2e2' }}>
              <li>publish hybrid-signed records and read them back with proof</li>
              <li>build a trust graph with attestations, then revoke a key</li>
              <li>sign checkpoints and see why witnesses make erasure detectable</li>
              <li>sync two nodes and reconcile only the missing records</li>
              <li>move history offline with bundles, and audit a fork</li>
            </ul>
          </div>
        </div>
      </Reveal>

      <Reveal>
        <h2>The curriculum</h2>
        <div className="grid cols-2">
          {lessons.map((l, i) => (
            <a key={l.id} className="card" href={`#/lesson/${l.id}`} style={{ textDecoration: 'none', color: 'inherit' }}>
              <span className="tag">
                lesson {String(l.id).padStart(2, '0')} · {l.minutes} min
                {progress?.has(l.id) ? ' · done' : ''}
              </span>
              <h3>{l.title}</h3>
              <p>{l.blurb}</p>
            </a>
          ))}
        </div>
      </Reveal>

      <Reveal>
        <div className="panel" style={{ marginTop: 28 }}>
          <h3>If you would rather read than click</h3>
          <p className="small" style={{ marginBottom: 0 }}>
            This laboratory distills the DATU user manual, which remains the complete reference for
            every command, flag and runbook, including WSL2, Linux and macOS install paths, the Signet
            wallet, parties and contracts, policies, and the projection layer.
          </p>
        </div>
      </Reveal>

      <footer className="foot">
        DATU Laboratory. Records are append-only; so is what you learn here.
      </footer>
    </div>
  );
}
