// End-to-end check of the relying party without a phone: fetch the QR page,
// extract its challenge, sign it with a local vault (the same core the phone
// runs), post the assertion, and require a verified, single-use result.
//
// Then the attestation requirement: the same server, started with
// REQUIRE_ATTESTATION, must refuse an unattested key, and must accept it
// once a trust root attests it - with the voucher named in the answer.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const DATU = process.env.DATU_BIN || new URL('../../target/release/datu', import.meta.url).pathname;

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });

const spawnServer = async (env) => {
  const proc = spawn('node', ['server.mjs'], {
    env: { ...process.env, PORT: '0', ...env },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const base = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server did not start')), 10000);
    const onData = (d) => {
      const m = /http:\/\/[^:]+:(\d+)/.exec(d.toString());
      if (m) {
        clearTimeout(t);
        resolve(`http://127.0.0.1:${m[1]}`);
      }
    };
    proc.stdout.on('data', onData);
    proc.on('exit', (c) => reject(new Error(`server exited ${c}`)));
  });
  return { proc, base };
};

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`);
  if (!ok) failures += 1;
};

const dataDir = await mkdtemp(path.join(os.tmpdir(), 'datu-rp-'));
const nodeDir = await mkdtemp(path.join(os.tmpdir(), 'datu-rp-node-'));
const run = (args) =>
  new Promise((resolve, reject) => {
    const p = spawn(DATU, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(err || out))));
  });

const servers = [];
const procs = [];
try {
  // A real ledger node for the trust-graph lookup, empty to begin with.
  await run(['--data-dir', nodeDir, 'init']);
  const nodePort = await freePort();
  const nodeUrl = `http://127.0.0.1:${nodePort}`;
  const nodeProc = spawn(DATU, ['--data-dir', nodeDir, 'serve', '--addr', `127.0.0.1:${nodePort}`], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(nodeProc);
  for (let i = 0; i < 50; i++) {
    try {
      const st = await fetch(nodeUrl + '/v1/status');
      if (st.ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }

  await run(['--data-dir', dataDir, 'signet', 'create', '--name', 'rp-smoke', '--passphrase', 'smoke-pass']);

  const freshChallenge = async (base) => {
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

  const verify = (base, assertion) =>
    fetch(base + '/api/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assertion }),
    }).then((r) => r.json());

  // ---- phase A: the plain relying party, node attached ----
  const a = await spawnServer({ NODE_URL: nodeUrl });
  servers.push(a.proc);
  const challenge = await freshChallenge(a.base);
  check('page renders a sign-in link', Boolean(challenge.nonce));
  check('challenge is complete', Boolean(challenge.rp_id && challenge.origin && challenge.expires_at_ms));
  check('redirect points at the callback', challenge.redirect.endsWith('/auth/callback'));

  const assertion = await sign(challenge);
  check('vault signed the challenge', typeof assertion.signature === 'string' && assertion.signature.length === 128);

  const first = await verify(a.base, assertion);
  check('server verifies the assertion', first.ok === true, first.ok ? first.pubkey?.slice(0, 12) : first.error);
  check('unattested key is reported honestly', first.node_reachable === true && (first.vouchers || []).length === 0 &&
    /not a verdict/.test(first.note || ''), first.note);

  const replay = await verify(a.base, assertion);
  check('nonce is single use', replay.ok === false && /used/.test(replay.error || ''), replay.error);

  const forgedChallenge = await freshChallenge(a.base);
  const forged = { ...(await sign(forgedChallenge)), signature: 'ab'.repeat(64) };
  const bad = await verify(a.base, forged);
  check('forged signature refused', bad.ok === false && !/nonce/.test(bad.error || ''), bad.error);

  const mismatched = { ...(await sign(await freshChallenge(a.base))), origin: 'https://evil.example' };
  const mismatch = await verify(a.base, mismatched);
  check('challenge mismatch refused', mismatch.ok === false && /does not match/.test(mismatch.error || ''), mismatch.error);

  // ---- phase B: the same relying party, now demanding attestation ----
  const b = await spawnServer({
    NODE_URL: nodeUrl,
    REQUIRE_ATTESTATION: '{"roles":["rp-smoke"],"minCosigners":0}',
  });
  servers.push(b.proc);

  const unattested = await verify(b.base, await sign(await freshChallenge(b.base)));
  check('requirement refuses an unattested key', unattested.ok === false && /unattested/.test(unattested.error || ''), unattested.error);

  // A trust root attests the key; the same server must now admit it, naming
  // the voucher.
  await run(['--data-dir', nodeDir, 'attest', 'create', '--subject', assertion.pubkey,
    '--claims', '{"role":"rp-smoke","legal_name":"Acme Ltd"}', '--label', 'Acme Ltd']);
  const attested = await verify(b.base, await sign(await freshChallenge(b.base)));
  check('requirement admits an attested key', attested.ok === true, attested.ok ? '' : attested.error);
  check('the voucher is named', (attested.vouchers || []).length === 1 &&
    attested.vouchers[0].claims.role === 'rp-smoke' && /^[0-9a-f]{64}$/.test(attested.vouchers[0].by || ''),
    JSON.stringify(attested.vouchers?.[0]?.claims || null));

  // A different role does not satisfy the requirement: same key, still refused.
  const c = await spawnServer({ NODE_URL: nodeUrl, REQUIRE_ATTESTATION: '{"roles":["clerk"]}' });
  servers.push(c.proc);
  const wrongRole = await verify(c.base, await sign(await freshChallenge(c.base)));
  check('a wrong role does not satisfy the requirement', wrongRole.ok === false && /satisfies/.test(wrongRole.error || ''), wrongRole.error);
} catch (e) {
  console.error('smoke failed:', e.message);
  failures += 1;
} finally {
  for (const p of servers) p.kill('SIGTERM');
  for (const p of procs) p.kill('SIGTERM');
  await rm(dataDir, { recursive: true, force: true });
  await rm(nodeDir, { recursive: true, force: true });
}

console.log(failures === 0 ? 'PASS: relying-party demo smoke' : `${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
