import { useEffect, useRef, useState } from 'react';

// Terminal that types the most recent command and prints outputs below it.
// lines: [{ kind: 'cmd' | 'out' | 'err', text }]
export default function Terminal({ lines, title = 'datu', height }) {
  const [typed, setTyped] = useState('');
  const lastCmd = useRef('');
  const bodyRef = useRef(null);

  useEffect(() => {
    const cmds = lines.filter((l) => l.kind === 'cmd');
    const latest = cmds.length ? cmds[cmds.length - 1].text : '';
    if (!latest || latest === lastCmd.current) {
      setTyped(latest);
      return;
    }
    lastCmd.current = latest;
    let i = 0;
    setTyped('');
    const timer = setInterval(() => {
      i += 1;
      setTyped(latest.slice(0, i));
      if (i >= latest.length) clearInterval(timer);
    }, 18);
    return () => clearInterval(timer);
  }, [lines]);

  useEffect(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, typed]);

  const cmdIndexes = new Set();
  lines.forEach((l, i) => {
    if (l.kind === 'cmd') cmdIndexes.add(i);
  });
  const lastCmdIndex = Math.max(...[...cmdIndexes], -1);

  return (
    <div className="terminal">
      <div className="bar"><i /><i /><i /><span className="dim mono small" style={{ marginLeft: 8 }}>{title}</span></div>
      <div className="body" ref={bodyRef} style={height ? { maxHeight: height } : undefined}>
        {lines.length === 0 && <span className="dim">run something to see output</span>}
        {lines.map((l, i) => {
          if (l.kind === 'cmd') {
            const text = i === lastCmdIndex ? typed : l.text;
            return (
              <div key={i} className="cmd">
                {text}
                {i === lastCmdIndex && <span className="caret" />}
              </div>
            );
          }
          return (
            <div key={i} className={l.kind === 'err' ? 'err' : 'out'}>
              {l.text}
            </div>
          );
        })}
      </div>
    </div>
  );
}
