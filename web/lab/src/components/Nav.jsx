import { lessons } from '../lib/lessons';

export default function Nav({ route, progress }) {
  const activeLesson = route.page === 'lesson' ? route.lesson : null;
  return (
    <aside className="rail">
      <a className="brand" href="#/">
        <div className="brand-mark" />
        <div>
          <div className="brand-name">DATU Lab</div>
          <div className="brand-sub">interactive manual</div>
        </div>
      </a>

      <div className="rail-group">Laboratory</div>
      <nav>
        <a href="#/lab" className={route.page === 'lab' ? 'active' : ''}>
          <span className="num">*</span> Playground
        </a>
      </nav>

      <div className="rail-group">Curriculum</div>
      <nav>
        {lessons.map((l) => (
          <a key={l.id} href={`#/lesson/${l.id}`} className={activeLesson === l.id ? 'active' : ''}>
            <span className="num">{String(l.id).padStart(2, '0')}</span>
            <span>{l.title}</span>
            {progress?.has(l.id) && <span className="tick" aria-label="completed">✓</span>}
          </a>
        ))}
      </nav>

      <div className="rail-group">Reference</div>
      <nav>
        <a href="#/lesson/8"><span className="num">?</span> Forks and evidence</a>
      </nav>

      <div style={{ marginTop: 28, padding: '0 10px' }} className="small dim">
        <p style={{ margin: 0 }}>
          Every exercise runs against a real <code>datu</code> node created for this browser.
          Sandboxes expire after 30 idle minutes.
        </p>
      </div>
    </aside>
  );
}
