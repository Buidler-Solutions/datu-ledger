import { useState } from 'react';
import LessonShell from '../../components/LessonShell';
import Reveal from '../../components/Reveal';
import Terminal from '../../components/Terminal';

const QUESTIONS = [
  {
    q: 'Two witnesses report different histories. Which pair actually proves a fork?',
    options: [
      'Any two checkpoint streams, whatever the signers',
      'Streams where the same signer key reports the same height with different Merkle roots',
      'A single bundle from the accused node',
      'A screenshot of the dispute in a chat',
    ],
    answer: 1,
    why: 'Contradiction is only evidence when one key signed both sides. Different signers seeing different things is just a partial view.',
  },
  {
    q: 'A node quietly rewrites an old record and recomputes its ids. What catches it?',
    options: [
      'Nothing, ids are derived from content',
      'Its own signature on the new record',
      'An earlier witness checkpoint whose Merkle root covered the original record',
      'The firewall',
    ],
    answer: 2,
    why: 'The rewritten record changes every root above it, so any checkpoint signed before the rewrite contradicts the new history.',
  },
  {
    q: 'prove-fork exits with code 2. What did it just tell you?',
    options: [
      'It could not read the files',
      'NO_CONTRADICTIONS: the histories agree',
      'FORK_PROVEN: contradictory signed histories exist, evidence written',
      'The peer was offline',
    ],
    answer: 2,
    why: 'Exit 0 is NO_CONTRADICTIONS, exit 2 is FORK_PROVEN. The verdict is an exit code so scripts and courts can both consume it.',
  },
];

function Quiz({ onSolved }) {
  const [picked, setPicked] = useState({});
  const allCorrect = QUESTIONS.every((q, i) => picked[i] === q.answer);
  const [checked, setChecked] = useState(false);

  return (
    <div className="exercise">
      <h4><span className="tag">final exercise</span>Evidence, not vibes</h4>
      <div className="stack">
        {QUESTIONS.map((q, i) => (
          <div key={i}>
            <div className="small" style={{ marginBottom: 8, color: '#dbe5f2' }}>{i + 1}. {q.q}</div>
            <div className="btn-row" style={{ gap: 8 }}>
              {q.options.map((opt, j) => (
                <button
                  key={j}
                  type="button"
                  className={`btn ghost small ${picked[i] === j ? 'selected' : ''}`}
                  style={picked[i] === j ? { borderColor: 'var(--teal)', color: 'var(--teal)' } : undefined}
                  onClick={() => setPicked({ ...picked, [i]: j })}
                >
                  {opt}
                </button>
              ))}
            </div>
            {checked && picked[i] !== q.answer && (
              <div className="small" style={{ color: 'var(--rose)', marginTop: 6 }}>{q.why}</div>
            )}
          </div>
        ))}
      </div>
      <div className="btn-row" style={{ marginTop: 14 }}>
        <button
          className="btn ghost"
          type="button"
          onClick={() => {
            setChecked(true);
            if (allCorrect) onSolved?.();
          }}
        >
          {allCorrect ? 'submit' : 'check answers'}
        </button>
        {checked && (
          <span className={`badge ${allCorrect ? 'ok' : 'err'}`}>
            {allCorrect ? 'all three correct' : 'not yet'}
          </span>
        )}
      </div>
    </div>
  );
}

export default function Lesson8({ mark, done }) {
  return (
    <LessonShell
      id={8}
      kicker="Lesson 08 · forks"
      title="Forks and evidence"
      lede="An append-only ledger cannot stop a signer from signing two different histories. What it can do is make that contradiction carry a proof: two signed checkpoints, same key, same height, different roots. Detection is not resolution, and the ledger only claims the former."
      done={done}
    >
      <Reveal>
        <div className="panel">
          <h3>The anatomy of a provable fork</h3>
          <div className="dag-wrap" style={{ padding: '26px 18px' }}>
            <svg viewBox="0 0 720 220" role="img" aria-label="fork diagram">
              <defs>
                <linearGradient id="forkA" x1="0" x2="1">
                  <stop offset="0" stopColor="#4cd6c8" stopOpacity="0.1" />
                  <stop offset="1" stopColor="#4cd6c8" stopOpacity="0.7" />
                </linearGradient>
              </defs>
              {[0, 1, 2].map((i) => (
                <g key={i}>
                  <circle cx={90 + i * 70} cy={60} r={8} fill="#4cd6c8" />
                  <circle cx={90 + i * 70} cy={160} r={8} fill="#4cd6c8" fillOpacity={0.55} />
                  {i > 0 && <line x1={90 + (i - 1) * 70} y1={60} x2={90 + i * 70} y2={60} stroke="url(#forkA)" strokeWidth="2" />}
                  {i > 0 && <line x1={90 + (i - 1) * 70} y1={160} x2={90 + i * 70} y2={160} stroke="rgba(76,214,200,0.35)" strokeWidth="2" />}
                </g>
              ))}
              <circle cx={300} cy={110} r={13} fill="#ffb454" />
              <text x={300} y={88} textAnchor="middle" fontSize="10" fill="#ffb454" fontFamily="var(--mono)">checkpoint h=7</text>
              <line x1={300} y1={110} x2={370} y2={60} stroke="#ffb454" strokeWidth="1.4" strokeDasharray="5 4" className="dag-edge" />
              <line x1={300} y1={110} x2={370} y2={160} stroke="#ff6b81" strokeWidth="1.4" strokeDasharray="5 4" className="dag-edge" />
              <rect x={370} y={38} width={250} height={44} rx={10} fill="rgba(76,214,200,0.08)" stroke="rgba(76,214,200,0.35)" />
              <text x={384} y={56} fontSize="10.5" fill="#9fe8df" fontFamily="var(--mono)">root A: history with record X</text>
              <text x={384} y={72} fontSize="10.5" fill="#7fb0a8" fontFamily="var(--mono)">signer 3f9a…  height 7</text>
              <rect x={370} y={138} width={250} height={44} rx={10} fill="rgba(255,107,129,0.08)" stroke="rgba(255,107,129,0.4)" />
              <text x={384} y={156} fontSize="10.5" fill="#ffb3bf" fontFamily="var(--mono)">root B: history without X</text>
              <text x={384} y={172} fontSize="10.5" fill="#c98b96" fontFamily="var(--mono)">signer 3f9a…  height 7</text>
            </svg>
          </div>
          <p className="small muted" style={{ marginBottom: 0 }}>
            Same key, same height, different roots. Anything else is a partial view, and partially
            informed witnesses disagree all the time without anyone lying.
          </p>
        </div>
      </Reveal>

      <Reveal>
        <div className="panel">
          <h3>The tools</h3>
          <Terminal
            title="witness streams and prove-fork"
            lines={[
              { kind: 'cmd', text: 'datu witness sign && datu witness export --out w1.stream' },
              { kind: 'out', text: 'checkpoint signed and exported (carry the file to anyone)' },
              { kind: 'cmd', text: 'datu prove-fork --a w1.stream --b w2.stream' },
              { kind: 'out', text: 'FORK_PROVEN  same-signer, same-height contradiction\n  signer 3f9a…  height 7  root 48d567… vs 7b2e11…\n  evidence package written: fork-evidence.json\n(exit code 2)' },
              { kind: 'cmd', text: 'datu prove-fork --a w1.stream --b w1.stream' },
              { kind: 'out', text: 'NO_CONTRADICTIONS (exit 0)' },
              { kind: 'cmd', text: 'datu prove-fork --against history.bundle' },
              { kind: 'out', text: 'checks stored checkpoints against the bundle: mismatch = history-mismatch (exit 2)' },
            ]}
          />
          <p className="small muted" style={{ marginTop: 12, marginBottom: 0 }}>
            The fork drill in the repository runs this end to end on real nodes:
            <code> deploy/drills/fork-drill.sh</code>. It also keeps an honest control: a stream
            compared with itself must report NO_CONTRADICTIONS, so the tool cannot be accused of
            finding forks everywhere.
          </p>
        </div>
      </Reveal>

      <Quiz onSolved={() => mark(8)} />

      <Reveal>
        <div className="grid cols-2">
          <div className="card">
            <span className="tag">detection</span>
            <p className="small">prove-fork names the contradiction and writes evidence both sides can keep. It does not decide who is right.</p>
          </div>
          <div className="card">
            <span className="tag">resolution</span>
            <p className="small">Humans, contracts, or courts decide which history stands. The ledger's job is to make lying expensive to hide, not impossible to attempt.</p>
          </div>
        </div>
      </Reveal>
    </LessonShell>
  );
}
