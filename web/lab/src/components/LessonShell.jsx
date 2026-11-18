import { lessons } from '../lib/lessons';
import Reveal from './Reveal';

// Lesson chrome: hero, prose column, and prev/next navigation that keeps the
// learner moving through the curriculum.
export default function LessonShell({ id, kicker, title, lede, children, done }) {
  const index = lessons.findIndex((l) => l.id === id);
  const prev = lessons[index - 1];
  const next = lessons[index + 1];

  return (
    <article>
      <header className="hero">
        <div className="kicker rise">{kicker || `Lesson ${id}`}</div>
        <h1 className="rise delay-1">
          {title}
          {done && <span className="badge ok" style={{ marginLeft: 16, verticalAlign: 'middle' }}>completed</span>}
        </h1>
        <p className="lede rise delay-2">{lede}</p>
      </header>
      <Reveal>{children}</Reveal>
      <nav className="lesson-nav">
        {prev ? (
          <a href={`#/lesson/${prev.id}`}>
            <span className="dir">previous</span>
            {prev.title}
          </a>
        ) : (
          <a href="#/">
            <span className="dir">back</span>
            All lessons
          </a>
        )}
        {next ? (
          <a className="next" href={`#/lesson/${next.id}`}>
            <span className="dir">next</span>
            {next.title}
          </a>
        ) : (
          <a className="next" href="#/lab">
            <span className="dir">next</span>
            Open the Laboratory
          </a>
        )}
      </nav>
    </article>
  );
}
