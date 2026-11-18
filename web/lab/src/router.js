import { useEffect, useState } from 'react';

// Hash router: the lab is entirely static files, so routes live in the hash
// and any static host works. Grammar: #/ (home), #/lab, #/lesson/<n>.
export function parse(hash) {
  const clean = (hash || '').replace(/^#\/?/, '');
  if (!clean) return { page: 'home' };
  if (clean === 'lab') return { page: 'lab' };
  const lesson = /^lesson\/(\d+)$/.exec(clean);
  if (lesson) return { page: 'lesson', lesson: Number(lesson[1]) };
  return { page: 'home' };
}

export function useRoute() {
  const [route, setRoute] = useState(() => parse(window.location.hash));
  useEffect(() => {
    const onChange = () => {
      setRoute(parse(window.location.hash));
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

export const go = (path) => {
  window.location.hash = path.startsWith('#') ? path : `#/${path.replace(/^\//, '')}`;
};
