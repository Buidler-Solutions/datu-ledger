// End-to-end check of the relying party without a phone: fetch the QR page,
// extract its challenge, sign it with a local vault (the same core the phone
// runs), post the assertion, and require a verified, single-use result.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const DATU = process.env.DATU_BIN || new URL('../../target/release/datu', import.meta.url).pathname;
const server = spawn('node', ['server.mjs'], { env: { ...process.env, PORT: '0' }, stdio: ['ignore', 'pipe', 'inherit'] });

let base = null;
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error('server did not start')), 10000);
  const onData = (d) => {
    const m = /http:\/\/[^:]+:(\d+)/.exec(d.toString());
    if (m) {
      clearTimeout(t);
      base = `http://127.0.0.1:${m[1]}`;
      resolve();
    }
  };
  server.stdout.on('data', onData);
  server.on('exit', (c) => reject(new Error(`server exited ${c}`)));
});

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`);
  if (!ok) failures += 1;
};

const dataDir = await mkdtemp(path.join(os.tmpdir(), 'datu-rp-'));
const run = (args) =>
  new Promise((resolve, reject) => {
    const p = spawn(DATU, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(err || out))));
  });

try {
  await run(['--data-dir', dataDir, 'signet', 'create', '--name', 'rp-smoke', '--passphrase', 'smoke-pass']);

  const freshChallenge = async () => {
    const page = await fetch(base + '/').then((r) => r.text());
    const link = /datu-auth:\/\/sign\?[^"<]+/.exec(page)?.[0]?.replaceAll('&amp;', '&');
    const q = new URL(link).searchParams;
    return {
      rp_id: q.get('rp_id'),
      origin: q.get('origin'),
      nonce: q.get('nonce'),
      expires_at_ms: Number(q.get('expires_at_ms')),
      redirect: q.get('redirect'),
    };
  };

  const sign = async (challenge) => {
    const signed = await run([
      '--data-dir', dataDir, 'signet', 'auth-assert',
      '--name', 'rp-smoke', '--passphrase', 'smoke-pass',
      '--rp-id', challenge.rp_id, '--origin', challenge.origin,
      '--nonce', challenge.nonce, '--expires-at-ms', String(challenge.expires_at_ms),
    ]);
    return JSON.parse(signed.slice(signed.indexOf('{'), signed.lastIndexOf('}') + 1));
  };

  const challenge = await freshChallenge();
  check('page renders a sign-in link', Boolean(challenge.nonce));
  check('challenge is complete', Boolean(challenge.rp_id && challenge.origin && challenge.expires_at_ms));
  check('redirect points at the callback', challenge.redirect.endsWith('/auth/callback'));

  const assertion = await sign(challenge);
  check('vault signed the challenge', typeof assertion.signature === 'string' && assertion.signature.length === 128);

  const first = await fetch(base + '/api/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ assertion }),
  }).then((r) => r.json());
  check('server verifies the assertion', first.ok === true, first.ok ? first.pubkey?.slice(0, 12) : first.error);

  const replay = await fetch(base + '/api/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ assertion }),
  }).then((r) => r.json());
  check('nonce is single use', replay.ok === false && /used/.test(replay.error || ''), replay.error);

  const forgedChallenge = await freshChallenge();
  const forged = { ...(await sign(forgedChallenge)), signature: 'ab'.repeat(64) };
  const bad = await fetch(base + '/api/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ assertion: forged }),
  }).then((r) => r.json());
  check('forged signature refused', bad.ok === false && !/nonce/.test(bad.error || ''), bad.error);

  const mismatched = { ...(await sign(await freshChallenge())), origin: 'https://evil.example' };
  const mismatch = await fetch(base + '/api/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ assertion: mismatched }),
  }).then((r) => r.json());
  check('challenge mismatch refused', mismatch.ok === false && /does not match/.test(mismatch.error || ''), mismatch.error);
} catch (e) {
  console.error('smoke failed:', e.message);
  failures += 1;
} finally {
  server.kill('SIGTERM');
  await rm(dataDir, { recursive: true, force: true });
}

console.log(failures === 0 ? 'PASS: relying-party demo smoke' : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
