// End-to-end smoke test for the laboratory backend. Spawns the server with
// a real datu binary, drives one full learner journey against two sandboxes,
// and fails loudly on any drift. Run: npm run smoke (needs the release
// binary built: cargo build --release -p datu-cli).
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.resolve(HERE, '..', 'server', 'index.mjs');

const server = spawn('node', [SERVER], {
  env: { ...process.env, PORT: '0' },
  stdio: ['ignore', 'pipe', 'inherit'],
});

let base = null;
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error('server did not start')), 10000);
  server.on('message', (m) => {
    if (m?.port) {
      clearTimeout(t);
      base = `http://127.0.0.1:${m.port}`;
      resolve();
    }
  });
  server.stdout.on('data', (d) => {
    const text = d.toString();
    const m = /http:\/\/127\.0\.0\.1:(\d+)/.exec(text);
    if (m && !base) {
      clearTimeout(t);
      base = `http://127.0.0.1:${m[1]}`;
      resolve();
    }
  });
});

const call = async (method, route, body) => {
  const res = await fetch(base + route, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`${method} ${route}: ${res.status} ${json.error || ''}`);
  return json;
};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`);
  if (!ok) failures += 1;
};

try {
  const a = await call('POST', '/api/sandbox');
  check('sandbox A created', /^[0-9a-f]{64}$/.test(a.identity), a.identity.slice(0, 12));

  const b = await call('POST', '/api/sandbox');
  check('sandbox B created', /^[0-9a-f]{64}$/.test(b.identity), b.identity.slice(0, 12));

  const first = await call('POST', `/api/sandbox/${a.id}/publish`, { namespace: 'general', payload: '{"hello":"lab"}' });
  check('publish returns an entry id', /^[0-9a-f]{64}$/.test(first.id || ''));

  for (let i = 0; i < 2; i += 1) {
    await call('POST', `/api/sandbox/${a.id}/publish`, { namespace: 'gov.lab', payload: `{"n":${i}}` });
  }

  const entriesA = await call('GET', `/api/sandbox/${a.id}/entries`);
  check('A holds genesis + 3 entries', entriesA.entries.length === 4, `count=${entriesA.entries.length}`);
  check('entries carry prev links', entriesA.entries.some((e) => e.prev));

  const cp = await call('POST', `/api/sandbox/${a.id}/checkpoint`);
  check('checkpoint signed', /checkpoint [0-9a-f]{64}/.test(cp.output || ''));

  const att = await call('POST', `/api/sandbox/${a.id}/attest`, {
    subject: b.identity,
    claims: { role: 'lab-peer' },
  });
  check('attestation created', /attestation|published/.test(att.output || ''), att.output?.split('\n')[0]);

  const rev = await call('POST', `/api/sandbox/${a.id}/revoke`, { key: b.identity, reason: 'smoke test' });
  check('revocation recorded', /revoke|revoked|published/i.test(rev.output || ''));

  const sync = await call('POST', `/api/sandbox/${b.id}/sync`, { peer: a.id });
  check('B synced from A', /new entries/.test(sync.output || ''), sync.output?.split('\n')[0]);
  const entriesB = await call('GET', `/api/sandbox/${b.id}/entries`);
  check('B now holds A history', entriesB.entries.length >= 4, `count=${entriesB.entries.length}`);

  const bundle = await call('POST', `/api/sandbox/${a.id}/bundle/export`);
  check('bundle exported', (bundle.size || 0) > 0, `${bundle.size} bytes`);
  const imp = await call('POST', `/api/sandbox/${b.id}/bundle/import`, { bundle: bundle.bundle });
  check('bundle import is idempotent', /already present|new entries/.test(imp.output || ''), imp.output?.split('\n')[0]);

  const verify = await call('POST', `/api/sandbox/${a.id}/verify`);
  check('verify is clean', /^OK:/.test(verify.output || ''), verify.output?.split('\n')[0]);

  const status = await call('GET', `/api/sandbox/${a.id}`);
  check('status reports entries', status.status.entries >= 4, `entries=${status.status.entries}`);

  const denied = await fetch(base + `/api/sandbox/${a.id}/publish`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ namespace: 'BAD NAMESPACE', payload: '{}' }),
  });
  check('bad namespace is refused', denied.status === 400);

  await call('DELETE', `/api/sandbox/${a.id}`);
  await call('DELETE', `/api/sandbox/${b.id}`);
  const gone = await fetch(base + `/api/sandbox/${a.id}`);
  check('deleted sandbox is gone', gone.status === 404);
} catch (e) {
  console.error('smoke failed:', e.message);
  failures += 1;
} finally {
  server.kill('SIGTERM');
}

console.log(failures === 0 ? 'PASS: laboratory backend smoke' : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
