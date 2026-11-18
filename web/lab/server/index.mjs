// DATU Laboratory sandbox backend.
//
// Each browser session gets its own throwaway node: a temp data dir with a
// freshly generated identity and a `datu serve` process on a loopback port.
// Mutations run the real CLI; reads proxy the node's HTTP API. Nothing the
// visitor does can touch a real ledger, and every session dies on a timer.
//
// Zero npm dependencies on purpose: the lab ships a real node interface, so
// the server that fronts it should have no supply chain of its own.
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, readFile, writeFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, '..', 'dist');
const DATU = process.env.DATU_BIN || path.resolve(HERE, '..', '..', '..', 'target', 'release', 'datu');
const PORT = Number(process.env.PORT || 5175);

const TTL_MS = 30 * 60 * 1000; // idle session lifetime
const MAX_SESSIONS = 64;
const MAX_SESSIONS_PER_IP = 4;
const MAX_BODY = 8 * 1024 * 1024; // bundles travel base64-encoded
const CMD_TIMEOUT_MS = 15000;
const MAX_ENTRIES = 500;
const NS_RE = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,4}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const RATE_PER_MIN = 120;

const sessions = new Map();
const rate = new Map(); // ip -> {windowStart, count}

const log = (...args) => console.log(new Date().toISOString(), ...args);

function checkRate(ip) {
  const now = Date.now();
  const slot = rate.get(ip) || { windowStart: now, count: 0 };
  if (now - slot.windowStart > 60_000) {
    slot.windowStart = now;
    slot.count = 0;
  }
  slot.count += 1;
  rate.set(ip, slot);
  return slot.count <= RATE_PER_MIN;
}

function run(args, { timeout = CMD_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(DATU, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`command timed out after ${timeout}ms`));
    }, timeout);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(new Error(`cannot run ${DATU}: ${e.message}`));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(err.trim() || out.trim() || `exit ${code}`));
      } else {
        resolve(out);
      }
    });
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function nodeGet(port, route) {
  const res = await fetch(`http://127.0.0.1:${port}${route}`);
  if (!res.ok) throw new Error(`node answered ${res.status} for ${route}`);
  return res.json();
}

async function waitReady(port) {
  for (let i = 0; i < 60; i += 1) {
    try {
      await nodeGet(port, '/v1/status');
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error('sandbox node did not come up');
}

function sessionOf(id) {
  const s = sessions.get(id);
  if (!s) return null;
  s.lastUsed = Date.now();
  return s;
}

async function killSession(id) {
  const s = sessions.get(id);
  if (!s) return false;
  sessions.delete(id);
  try {
    s.proc?.kill('SIGKILL');
  } catch {}
  await rm(s.dir, { recursive: true, force: true }).catch(() => {});
  return true;
}

const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastUsed > TTL_MS) {
      log('sandbox expired', id.slice(0, 8));
      killSession(id);
    }
  }
}, 60_000);
sweeper.unref?.();

function send(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('body must be JSON'));
      }
    });
    req.on('error', reject);
  });
}

async function createSession(ip) {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastUsed > TTL_MS) await killSession(id);
  }
  const mine = [...sessions.values()].filter((s) => s.ip === ip).length;
  if (mine >= MAX_SESSIONS_PER_IP) throw new Error('too many sandboxes for this address, delete one first');
  if (sessions.size >= MAX_SESSIONS) throw new Error('laboratory is at capacity, try again shortly');

  const dir = await mkdtemp(path.join(os.tmpdir(), 'datu-lab-'));
  await run(['--data-dir', dir, 'init']);
  const keysOut = await run(['--data-dir', dir, 'keys']);
  const identity = /identity \(ed25519\): ([0-9a-f]{64})/.exec(keysOut)?.[1];
  if (!identity) throw new Error('sandbox identity missing');

  const port = await freePort();
  const proc = spawn(DATU, ['--data-dir', dir, 'serve', '--addr', `127.0.0.1:${port}`, '--submit-per-min', '120'], {
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  proc.stderr.on('data', () => {});
  const id = randomUUID();
  sessions.set(id, { id, dir, port, proc, identity, ip, createdAt: now, lastUsed: now });
  await waitReady(port);
  log('sandbox created', id.slice(0, 8), 'for', ip);
  return sessions.get(id);
}

// ---- route handlers -------------------------------------------------------

async function handleApi(req, res, ip) {
  const url = new URL(req.url, 'http://lab');
  const parts = url.pathname.split('/').filter(Boolean); // api, sandbox, :id, ...
  const method = req.method || 'GET';

  if (parts[1] !== 'sandbox') return send(res, 404, { error: 'unknown route' });

  // POST /api/sandbox
  if (parts.length === 2 && method === 'POST') {
    const s = await createSession(ip);
    return send(res, 201, { id: s.id, identity: s.identity });
  }

  const id = parts[2];
  if (!id) return send(res, 404, { error: 'unknown route' });
  if (method === 'DELETE' && parts.length === 3) {
    const gone = await killSession(id);
    return send(res, gone ? 200 : 404, { ok: gone });
  }
  const s = sessionOf(id);
  if (!s) return send(res, 404, { error: 'sandbox not found or expired' });

  const action = parts[3];

  if (method === 'GET' && !action) {
    const status = await nodeGet(s.port, '/v1/status');
    return send(res, 200, { id: s.id, identity: s.identity, status });
  }
  if (method === 'GET' && action === 'entries') {
    const limit = Math.min(Number(url.searchParams.get('limit') || 200) || 200, MAX_ENTRIES);
    const offset = Math.max(Number(url.searchParams.get('offset') || 0) || 0, 0);
    const data = await nodeGet(s.port, `/v1/entries?limit=${limit}&offset=${offset}`);
    return send(res, 200, data);
  }
  if (method === 'GET' && action === 'entry' && parts[4]) {
    if (!HEX64_RE.test(parts[4])) return send(res, 400, { error: 'entry id must be 64 hex characters' });
    return send(res, 200, await nodeGet(s.port, `/v1/entry/${parts[4]}`));
  }
  if (method === 'GET' && action === 'checkpoints') {
    return send(res, 200, await nodeGet(s.port, '/v1/checkpoints'));
  }
  if (method === 'GET' && action === 'conflicts') {
    return send(res, 200, await nodeGet(s.port, '/v1/conflicts'));
  }

  if (method !== 'POST') return send(res, 405, { error: 'method not allowed' });
  const body = await readBody(req);

  if (action === 'publish') {
    const ns = String(body.namespace || 'general');
    if (!NS_RE.test(ns)) return send(res, 400, { error: 'namespace must look like gov.records or general' });
    const payload = typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload ?? {});
    if (Buffer.byteLength(payload) > 2048) return send(res, 400, { error: 'payload is limited to 2048 bytes here' });
    const out = await run(['--data-dir', s.dir, 'publish', '--ns', ns, '--payload', payload]);
    const id = /published ([0-9a-f]{64})/.exec(out)?.[1];
    return send(res, 200, { id, output: out.trim() });
  }
  if (action === 'attest') {
    const subject = String(body.subject || '');
    if (!HEX64_RE.test(subject)) return send(res, 400, { error: 'subject must be a 64 hex character key' });
    const claims = body.claims && typeof body.claims === 'object' ? body.claims : {};
    if (Buffer.byteLength(JSON.stringify(claims)) > 1024) return send(res, 400, { error: 'claims are limited to 1024 bytes' });
    const out = await run(['--data-dir', s.dir, 'attest', 'create', '--subject', subject, '--claims', JSON.stringify(claims)]);
    return send(res, 200, { output: out.trim() });
  }
  if (action === 'revoke') {
    const key = String(body.key || '');
    if (!HEX64_RE.test(key)) return send(res, 400, { error: 'key must be 64 hex characters' });
    const reason = String(body.reason || 'laboratory exercise').slice(0, 200);
    const out = await run(['--data-dir', s.dir, 'attest', 'revoke', '--key', key, '--reason', reason]);
    return send(res, 200, { output: out.trim() });
  }
  if (action === 'checkpoint') {
    const out = await run(['--data-dir', s.dir, 'checkpoint']);
    return send(res, 200, { output: out.trim() });
  }
  if (action === 'verify') {
    const out = await run(['--data-dir', s.dir, 'verify']);
    return send(res, 200, { output: out.trim() });
  }
  if (action === 'bundle' && parts[4] === 'export') {
    const file = path.join(s.dir, 'lab-bundle.bin');
    const out = await run(['--data-dir', s.dir, 'bundle', 'export', '--out', file]);
    const bytes = await readFile(file);
    return send(res, 200, { output: out.trim(), bundle: bytes.toString('base64'), size: bytes.length });
  }
  if (action === 'bundle' && parts[4] === 'import') {
    const b64 = String(body.bundle || '');
    if (!b64 || b64.length > 8 * 1024 * 1024) return send(res, 400, { error: 'bundle missing or too large' });
    const file = path.join(s.dir, 'import.bin');
    await writeFile(file, Buffer.from(b64, 'base64'));
    const out = await run(['--data-dir', s.dir, 'bundle', 'import', '--input', file]);
    return send(res, 200, { output: out.trim() });
  }
  if (action === 'sync') {
    const peerId = String(body.peer || '');
    const peer = sessions.get(peerId);
    if (!peer) return send(res, 404, { error: 'peer sandbox not found' });
    // Sandboxes run `datu serve`, which speaks the HTTP mirror transport
    // (the native DATUP2P1 listener belongs to `datu node`).
    const out = await run(['--data-dir', s.dir, 'sync', '--peer', `http://127.0.0.1:${peer.port}`]);
    return send(res, 200, { output: out.trim() });
  }
  return send(res, 404, { error: 'unknown action' });
}

// ---- static frontend + server --------------------------------------------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
};

async function serveStatic(req, res) {
  if (!existsSync(DIST)) return send(res, 404, { error: 'frontend not built: run npm run build' });
  const url = new URL(req.url, 'http://lab');
  let file = path.join(DIST, url.pathname === '/' ? 'index.html' : url.pathname);
  if (!file.startsWith(DIST)) file = path.join(DIST, 'index.html');
  try {
    const info = await stat(file);
    if (info.isDirectory()) file = path.join(file, 'index.html');
  } catch {
    file = path.join(DIST, 'index.html'); // SPA fallback
  }
  const data = await readFile(file);
  res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
  res.end(data);
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  try {
    if (!checkRate(ip)) return send(res, 429, { error: 'slow down a little' });
    if (req.url?.startsWith('/api/')) return await handleApi(req, res, ip);
    return await serveStatic(req, res);
  } catch (e) {
    return send(res, 400, { error: e instanceof Error ? e.message : String(e) });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  const actual = server.address().port;
  log(`DATU laboratory on http://127.0.0.1:${actual} (binary: ${DATU})`);
  if (process.send) process.send({ port: actual });
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    log('shutting down, clearing sandboxes');
    for (const id of [...sessions.keys()]) await killSession(id);
    process.exit(0);
  });
}
