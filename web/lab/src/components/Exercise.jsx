import { useState } from 'react';
import Reveal from './Reveal';

// An exercise card. The check runs against the learner's live sandbox, so
// passing means the ledger actually did the thing, not that a quiz was
// answered. Solved state is reported upward for the progress rail.
export default function Exercise({ title, children, check, onSolved, solved = false, cta = 'Check my work' }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setResult(null);
    try {
      const r = await check();
      setResult(r);
      if (r?.ok) onSolved?.();
    } catch (e) {
      setResult({ ok: false, message: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Reveal>
      <div className={`exercise ${solved ? 'solved' : ''}`}>
        <h4>
          <span className="tag">exercise</span>
          {title}
          {solved && <span className="badge ok" style={{ marginLeft: 'auto' }}>done</span>}
        </h4>
        <div className="small" style={{ color: '#c3cfe0' }}>{children}</div>
        <div className="btn-row" style={{ marginTop: 12 }}>
          <button className="btn ghost" type="button" onClick={run} disabled={busy}>
            {busy ? 'checking…' : solved ? 'check again' : cta}
          </button>
        </div>
        {result && (
          <div className={`result ${result.ok ? 'ok' : 'bad'}`}>
            {result.ok ? 'PASS  ' : 'TRY   '}
            {result.message}
          </div>
        )}
      </div>
    </Reveal>
  );
}
