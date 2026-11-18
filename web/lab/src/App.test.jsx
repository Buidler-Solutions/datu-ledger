import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { short, timeAgo } from './lib/api';
import { lessons } from './lib/lessons';
import { parse } from './router';

// These tests never touch a real backend: fetch is stubbed to answer the
// sandbox API shape, so what is verified is that the UI mounts and renders
// without crashing, and that the pure helpers behave.

const json = (body, ok = true) =>
  Promise.resolve({ ok, status: ok ? 200 : 400, json: () => Promise.resolve(body) });

beforeEach(() => {
  window.matchMedia = window.matchMedia || ((q) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
  global.fetch = vi.fn((url, opts) => {
    const path = String(url);
    if (path.endsWith('/api/sandbox') && opts?.method === 'POST') {
      return json({ id: 'sb-1', identity: 'a'.repeat(64) }, true);
    }
    if (path.includes('/entries')) {
      return json({
        entries: [
          { id: 'b'.repeat(64), author: 'a'.repeat(64), namespace: 'genesis', seq: 0, prev: null, refs: [], timestamp_ms: Date.now(), payload_preview: '{}' },
          { id: 'c'.repeat(64), author: 'a'.repeat(64), namespace: 'general', seq: 0, prev: 'b'.repeat(64), refs: [], timestamp_ms: Date.now(), payload_preview: '{"a":1}' },
        ],
      });
    }
    if (path.includes('/checkpoints')) return json({ witnesses: [] });
    return json({ id: 'sb-1', identity: 'a'.repeat(64), status: { entries: 2, checkpoints: 0 } });
  });
  localStorage.clear();
  window.location.hash = '';
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('router', () => {
  it('parses every route shape', () => {
    expect(parse('')).toEqual({ page: 'home' });
    expect(parse('#/')).toEqual({ page: 'home' });
    expect(parse('#/lab')).toEqual({ page: 'lab' });
    expect(parse('#/lesson/3')).toEqual({ page: 'lesson', lesson: 3 });
    expect(parse('#/nonsense')).toEqual({ page: 'home' });
  });
});

describe('curriculum', () => {
  it('has eight unique lessons with required fields', () => {
    expect(lessons).toHaveLength(8);
    const ids = new Set(lessons.map((l) => l.id));
    expect(ids.size).toBe(8);
    for (const l of lessons) {
      expect(l.title.length).toBeGreaterThan(3);
      expect(l.blurb.length).toBeGreaterThan(10);
      expect(l.minutes).toBeGreaterThan(0);
    }
  });
});

describe('helpers', () => {
  it('shortens hashes and formats ages', () => {
    expect(short('abcdef0123456789')).toBe('abcdef01…6789');
    expect(short(null)).toBe('');
    expect(timeAgo(Date.now() - 5000)).toBe('5s ago');
    expect(timeAgo(Date.now() - 120000)).toBe('2m ago');
  });
});

describe('App', () => {
  it('renders the home page without a backend', async () => {
    const div = document.createElement('div');
    document.body.appendChild(div);
    const root = createRoot(div);
    await act(async () => {
      root.render(<App />);
    });
    expect(div.innerHTML).toContain('Learn a ledger by');
    expect(div.innerHTML).toContain('The curriculum');
    await act(async () => {
      root.unmount();
    });
    div.remove();
  });

  it('renders the laboratory route and creates a sandbox', async () => {
    window.location.hash = '#/lab';
    const div = document.createElement('div');
    document.body.appendChild(div);
    const root = createRoot(div);
    await act(async () => {
      root.render(<App />);
    });
    expect(div.innerHTML).toContain('Playground');
    expect(global.fetch).toHaveBeenCalled();
    await act(async () => {
      root.unmount();
    });
    div.remove();
  });
});
