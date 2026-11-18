import { useMemo } from 'react';

// The DAG, drawn honestly: one lane per author (feed), left to right by
// seq, edges are prev links (solid) and refs (dashed). Records from the
// genesis are marked separately. Clicking a node selects it for inspection.
const TONES = ['#ffb454', '#4cd6c8', '#8f7bff', '#7fb0ff', '#ff8aa0'];

export default function DagCanvas({ entries, selected, onSelect }) {
  const { lanes, W, H, edges } = useMemo(() => {
    const byAuthor = new Map();
    for (const e of entries) {
      if (!byAuthor.has(e.author)) byAuthor.set(e.author, []);
      byAuthor.get(e.author).push(e);
    }
    const authors = [...byAuthor.keys()];
    const laneH = 74;
    const pad = 46;
    const W = 720;
    const H = Math.max(160, authors.length * laneH + 60);
    const maxLen = Math.max(1, ...[...byAuthor.values()].map((v) => v.length));
    const stepX = Math.min(120, (W - pad * 2) / maxLen);
    const pos = new Map();
    const lanes = authors.map((author, i) => {
      const list = byAuthor.get(author).sort((a, b) => a.seq - b.seq);
      const nodes = list.map((e, idx) => {
        const x = pad + idx * stepX;
        const y = 42 + i * laneH;
        pos.set(e.id, { x, y });
        return { e, x, y, tone: TONES[i % TONES.length], genesis: e.namespace === 'genesis' };
      });
      return { author, y: 42 + i * laneH, nodes, tone: TONES[i % TONES.length] };
    });
    const edges = [];
    for (const e of entries) {
      const to = pos.get(e.id);
      if (!to) continue;
      if (e.prev && pos.has(e.prev)) edges.push({ from: pos.get(e.prev), to, kind: 'prev' });
      for (const r of e.refs || []) {
        if (pos.has(r) && r !== e.prev) edges.push({ from: pos.get(r), to, kind: 'ref' });
      }
    }
    return { lanes, W, H, edges };
  }, [entries]);

  if (!entries.length) {
    return (
      <div className="dag-wrap" style={{ padding: '38px 20px' }}>
        <p className="dim center small" style={{ margin: 0 }}>the graph appears as soon as records exist</p>
      </div>
    );
  }

  return (
    <div className="dag-wrap">
      <div className="dag-legend">
        <span><i style={{ background: '#ffb454' }} /> record</span>
        <span><i style={{ background: '#4cd6c8' }} /> second feed</span>
        <span><i style={{ background: '#8f7bff', borderRadius: 2 }} /> attest / checkpoint</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="ledger graph">
        {edges.map((edge, i) => {
          const mid = `M ${edge.from.x + 8} ${edge.from.y} C ${edge.from.x + 40} ${edge.from.y}, ${edge.to.x - 40} ${edge.to.y}, ${edge.to.x - 8} ${edge.to.y}`;
          return (
            <path
              key={i}
              d={mid}
              fill="none"
              stroke={edge.kind === 'prev' ? 'rgba(140, 175, 215, 0.35)' : 'rgba(143, 123, 255, 0.5)'}
              strokeWidth={1.2}
              className={edge.kind === 'ref' ? 'dag-edge' : ''}
              strokeDasharray={edge.kind === 'ref' ? '3 5' : undefined}
            />
          );
        })}
        {lanes.map((lane) => (
          <g key={lane.author}>
            <text x={8} y={lane.y + 4} fill="rgba(140,160,190,0.6)" fontSize="10" fontFamily="var(--mono)">
              {lane.author.slice(0, 6)}
            </text>
            <line x1={34} y1={lane.y} x2={W - 10} y2={lane.y} stroke="rgba(120,150,190,0.08)" />
            {lane.nodes.map(({ e, x, y, tone, genesis }, idx) => (
              <g
                key={e.id}
                className={`dag-node ${selected === e.id ? 'selected' : ''}`}
                onClick={() => onSelect?.(e)}
                style={{ animation: idx === lane.nodes.length - 1 ? 'rise 0.5s ease both' : undefined }}
              >
                <title>{`${e.namespace} seq ${e.seq}  ${e.id.slice(0, 12)}`}</title>
                {genesis && <circle cx={x} cy={y} r={12} fill="none" stroke="rgba(255,180,84,0.35)" strokeDasharray="2 3" />}
                <circle cx={x} cy={y} r={genesis ? 9 : 6.5} fill={tone} fillOpacity={0.92} stroke="rgba(5,8,13,0.9)" strokeWidth="1.4" />
                {e.namespace !== 'genesis' && (
                  <text x={x} y={y - 12} textAnchor="middle" fontSize="8.5" fill="rgba(160,180,205,0.7)" fontFamily="var(--mono)">
                    {e.namespace.split('.').pop()}
                  </text>
                )}
              </g>
            ))}
          </g>
        ))}
      </svg>
    </div>
  );
}
