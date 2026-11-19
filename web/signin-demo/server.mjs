// Reference relying party ("dApp") for DATU QR sign-in.
//
// One page issues a SignetAuth challenge and shows it as a QR; the phone
// scans it, signs with its own vault, and comes back to /auth/callback with
// the assertion in the URL fragment. This server verifies the assertion
// authoritatively with `datu signet auth-verify` (the relying-party check),
// enforces single-use nonces and expiry, and then asks a running node
// whether the signing key carries attestations (the trust-graph view).
//
// Deliberately small: node:http + one dependency (qrcode) to render the QR.
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import QRCode from 'qrcode';

const PORT = Number(process.env.PORT || 5176);
const HOST = process.env.HOST || '0.0.0.0';
const DATU = process.env.DATU_BIN || new URL('../../target/release/datu', import.meta.url).pathname;
const NODE_URL = process.env.NODE_URL || 'http://127.0.0.1:7474';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_OPEN = 256;

const challenges = new Map(); // nonce -> { challenge, createdAt, usedAt }

setInterval(() => {
  const now = Date.now();
  for (const [nonce, c] of challenges) {
    if (now - c.createdAt > CHALLENGE_TTL_MS * 2) challenges.delete(nonce);
  }
}, 60_000).unref();

function issue(origin) {
  if (challenges.size > MAX_OPEN) {
    const oldest = [...challenges.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt)[0];
    if (oldest) challenges.delete(oldest[0]);
  }
  const nonce = randomBytes(16).toString('hex');
  const challenge = {
    rp_id: new URL(origin).hostname,
    origin,
    nonce,
    expires_at_ms: Date.now() + CHALLENGE_TTL_MS,
    redirect: `${origin}/auth/callback`,
  };
  challenges.set(nonce, { challenge, createdAt: Date.now(), usedAt: null });
  return challenge;
}

function link(challenge) {
  const q = new URLSearchParams({
    rp_id: challenge.rp_id,
    origin: challenge.origin,
    nonce: challenge.nonce,
    expires_at_ms: String(challenge.expires_at_ms),
    redirect: challenge.redirect,
  });
  return `datu-auth://sign?${q.toString()}`;
}

function run(args, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const child = spawn(DATU, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const t = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('verifier timed out'));
    }, timeoutMs);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(new Error(`cannot run verifier: ${e.message}`));
    });
    child.on('close', (code) => {
      clearTimeout(t);
      resolve({ code, out: out.trim(), err: err.trim() });
    });
  });
}

// Ask the running node for attestations naming this key. Demo-scale: scan
// recent identity.attest entries and confirm the payload mentions the key.
async function attestationsFor(pubkey) {
  try {
    const res = await fetch(`${NODE_URL}/v1/entries?limit=500`);
    if (!res.ok) return { reachable: false, claims: [] };
    const { entries } = await res.json();
    const candidates = entries.filter((e) => e.namespace === 'identity.attest' || e.namespace === 'identity.revoke');
    const found = [];
    for (const entry of candidates.slice(-50)) {
      const full = await fetch(`${NODE_URL}/v1/entry/${entry.id}`).then((r) => r.json());
      // The node API ships payloads as base64; the CLI's `get` shows text.
      const text = typeof full.payload === 'string'
        ? full.payload
        : Buffer.from(full.payload_base64 || '', 'base64').toString('utf8');
      if (!text.includes(pubkey)) continue;
      let claims = null;
      try {
        claims = JSON.parse(text);
      } catch {}
      found.push({ namespace: full.namespace, by: full.author, entry: full.id, claims });
    }
    return { reachable: true, claims: found };
  } catch {
    return { reachable: false, claims: [] };
  }
}

function html(title, body, origin) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title}</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:#070b12; color:#e8eef7;
         display:flex; min-height:100vh; align-items:center; justify-content:center; }
  main { width:min(680px, 92vw); padding:32px; }
  h1 { font-size:1.5rem; margin:0 0 6px; }
  p.lede { color:#93a3b8; margin:0 0 22px; font-size:.95rem; }
  .card { background:rgba(16,23,34,.75); border:1px solid rgba(120,150,190,.18); border-radius:16px; padding:22px; }
  .qr { background:#fff; border-radius:12px; padding:12px; width:240px; margin:0 auto 16px; }
  .qr svg, .qr img { width:100%; height:auto; display:block; }
  code, .mono { font-family: ui-monospace, Menlo, monospace; font-size:.8rem; word-break:break-all; }
  .link { background:#04070c; border:1px solid rgba(120,150,190,.18); border-radius:10px; padding:10px 12px; margin:12px 0; }
  .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .pill { font-family:ui-monospace,Menlo,monospace; font-size:.7rem; letter-spacing:.12em; text-transform:uppercase;
          padding:3px 9px; border-radius:999px; border:1px solid rgba(120,150,190,.3); color:#93a3b8; }
  .ok { color:#5ee0a0; border-color:rgba(94,224,160,.4); background:rgba(94,224,160,.08); }
  .warn { color:#ffb454; border-color:rgba(255,180,84,.4); background:rgba(255,180,84,.08); }
  .err { color:#ff6b81; border-color:rgba(255,107,129,.4); background:rgba(255,107,129,.08); }
  table { width:100%; border-collapse:collapse; font-size:.82rem; margin-top:10px; }
  th { text-align:left; font-size:.68rem; letter-spacing:.12em; text-transform:uppercase; color:#5f6f85; padding:6px 8px; }
  td { padding:7px 8px; border-top:1px solid rgba(120,150,190,.1); vertical-align:top; }
  a { color:#4cd6c8; }
  .meta { color:#5f6f85; font-size:.75rem; margin-top:18px; }
  .btn { display:inline-block; background:#ffb454; color:#1a1205; font-weight:600; border-radius:10px;
         padding:10px 16px; text-decoration:none; font-size:.9rem; }
</style>
</head>
<body><main>${body}<div class="meta">DATU sign-in demo · ${origin}</div></main>
<script>
document.querySelectorAll('[data-copy]').forEach((el) => {
  el.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(el.dataset.copy); el.textContent = 'copied'; }
    catch (_) { el.textContent = 'copy failed'; }
    setTimeout(() => (el.textContent = 'Copy the link'), 1200);
  });
});
</script>
</body></html>`;
}

function pageHome(req) {
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  const origin = `http://${host}`;
  const challenge = issue(origin);
  const signLink = link(challenge);
  return QRCode.toString(signLink, { type: 'svg', margin: 1 }).then(
    (svg) => html(
      'Sign in with DATU',
      `<h1>Sign in with DATU</h1>
       <p class="lede">Scan this with the DATU Signet app on your phone. It signs the challenge with its own key; no password, no extension, no desktop bridge.</p>
       <div class="card" id="card">
         <div class="qr">${svg}</div>
         <div class="row" style="justify-content:center">
           <span class="pill">rp_id ${challenge.rp_id}</span>
           <span class="pill">expires ${Math.round(CHALLENGE_TTL_MS / 60000)} min</span>
         </div>
         <div class="link mono" id="link">${signLink.replaceAll('&', '&amp;')}</div>
         <div class="row">
           <button class="btn" data-copy="${signLink.replaceAll('&', '&amp;').replaceAll('"', '&quot;')}">Copy the link</button>
           <a href="${signLink.replaceAll('&', '&amp;')}">Open on this device</a>
         </div>
       </div>
       <div class="card" id="result" style="margin-top:16px;display:none"></div>
       <script>
         (function () {
           const nonce = ${JSON.stringify(challenge.nonce)};
           const box = document.getElementById('result');
           const qrCard = document.getElementById('card');
           const timer = setInterval(async () => {
             try {
               const res = await fetch('/api/challenge?nonce=' + encodeURIComponent(nonce));
               const data = await res.json();
               if (data.state === 'verified') {
                 clearInterval(timer);
                 if (qrCard) qrCard.style.display = 'none';
                 const claims = (data.attestations || []).map((a) =>
                   '<tr><td class="mono">' + a.namespace + '</td><td class="mono">' + a.by.slice(0, 12) + '…</td><td class="mono">' +
                   JSON.stringify(a.claims || {}) + '</td></tr>').join('');
                 const attested = data.node_reachable
                   ? (claims
                       ? '<table><thead><tr><th>namespace</th><th>attestor</th><th>claims</th></tr></thead><tbody>' + claims + '</tbody></table>'
                       : '<p class="lede">No attestation for this key on the node yet. Signed in, unattested.</p>')
                   : '<p class="lede">Ledger node unreachable; signature verified, no attestation lookup.</p>';
                 box.style.display = '';
                 box.innerHTML = '<div class="row"><span class="pill ok">signed in</span></div>' +
                   '<h2 style="font-size:1.05rem;margin:14px 0 6px" class="mono">' + data.pubkey.slice(0, 16) + '…' + data.pubkey.slice(-8) + '</h2>' +
                   '<p class="lede">Verified datu-auth-v1 assertion by the relying-party verifier.</p>' + attested;
               } else if (data.state === 'refused') {
                 clearInterval(timer);
                 box.style.display = '';
                 box.innerHTML = '<div class="row"><span class="pill err">refused</span></div><p class="lede">That challenge was presented with an assertion that failed verification.</p>';
               } else if (data.state === 'expired') {
                 clearInterval(timer);
                 box.style.display = '';
                 box.innerHTML = '<div class="row"><span class="pill warn">expired</span></div><p class="lede">Reload this page for a fresh QR.</p>';
               }
             } catch (_) {}
           }, 1500);
         })();
       </script>`,
      origin,
    ),
  );
}

function pageCallback(req) {
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  const origin = `http://${host}`;
  return html(
    'Verifying…',
    `<h1>Verifying your sign-in</h1>
     <p class="lede">The assertion is in the URL fragment, so it never reached a server in transit. Posting it back for the relying-party check.</p>
     <div class="card" id="out">checking…</div>
     <script>
       (async () => {
         const out = document.getElementById('out');
         const fragment = location.hash.replace(/^#/, '');
         const prefix = 'datu-assertion=';
         const show = (cls, title, details = '') => {
           out.innerHTML = '<div class="row"><span class="pill ' + cls + '">' + title + '</span></div>' + details;
         };
         if (!fragment.startsWith(prefix)) return show('err', 'no assertion', '<p class="lede">This callback expects #datu-assertion=…</p>');
         let assertion;
         try {
           const payload = fragment.slice(prefix.length);
           const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
           assertion = JSON.parse(atob(padded.replaceAll('-', '+').replaceAll('_', '/')));
         } catch (e) {
           return show('err', 'unreadable assertion', '<p class="lede">' + String(e) + '</p>');
         }
         try {
           const res = await fetch('/api/verify', {
             method: 'POST',
             headers: { 'content-type': 'application/json' },
             body: JSON.stringify({ assertion }),
           });
           const data = await res.json();
           if (!data.ok) return show('err', 'refused', '<p class="lede">' + (data.error || 'verification failed') + '</p>');
           const claims = (data.attestations || []).map((a) =>
             '<tr><td class="mono">' + a.namespace + '</td><td class="mono">' + a.by.slice(0, 12) + '…</td><td class="mono">' +
             JSON.stringify(a.claims || {}) + '</td></tr>').join('');
           const attestationBlock = data.node_reachable
             ? (claims
                 ? '<h3 style="margin:16px 0 0;font-size:.9rem">Attested claims</h3><table><thead><tr><th>namespace</th><th>attestor</th><th>claims</th></tr></thead><tbody>' + claims + '</tbody></table>'
                 : '<p class="lede" style="margin-top:14px">No attestation on the node for this key yet. Signed in, unattested.</p>')
             : '<p class="lede" style="margin-top:14px">Ledger node unreachable, so no attestation lookup. Signature itself is verified.</p>';
           show('ok', 'signed in',
             '<h2 style="font-size:1.05rem;margin:14px 0 6px" class="mono">' + data.pubkey.slice(0, 16) + '…' + data.pubkey.slice(-8) + '</h2>' +
             '<p class="lede">Verified ' + data.domain + ' assertion for ' + data.rp_id + ' by the relying-party verifier.</p>' +
             attestationBlock +
             '<p class="meta">This browser session would now hold a cookie or JWT issued to this key; the demo stops at the verified identity.</p>');
         } catch (e) {
           show('err', 'verification failed', '<p class="lede">' + String(e) + '</p>');
         }
       })();
     </script>`,
    origin,
  );
}

async function verifyAssertion(assertion) {
  if (!assertion || typeof assertion !== 'object') return { ok: false, error: 'missing assertion' };
  const { rp_id, origin, nonce, expires_at_ms, pubkey, signature, domain } = assertion;
  if (domain !== 'datu-auth-v1') return { ok: false, error: `unexpected domain ${domain}` };
  const entry = challenges.get(String(nonce));
  if (!entry) return { ok: false, error: 'unknown nonce' };
  if (entry.usedAt) return { ok: false, error: 'nonce already used' };
  const c = entry.challenge;
  if (rp_id !== c.rp_id || origin !== c.origin || Number(expires_at_ms) !== c.expires_at_ms) {
    return { ok: false, error: 'assertion does not match the challenge this dApp issued' };
  }
  if (Date.now() > c.expires_at_ms) return { ok: false, error: 'challenge expired' };
  if (!/^[0-9a-f]{64}$/.test(String(pubkey)) || !/^[0-9a-f]{128}$/.test(String(signature))) {
    return { ok: false, error: 'malformed pubkey or signature' };
  }
  const out = await run([
    'signet', 'auth-verify',
    '--rp-id', c.rp_id,
    '--origin', c.origin,
    '--nonce', c.nonce,
    '--expires-at-ms', String(c.expires_at_ms),
    '--pubkey', pubkey,
    '--signature', signature,
  ]);
  if (out.code !== 0) return { ok: false, error: out.err || out.out || 'signature did not verify' };
  entry.usedAt = Date.now();
  const attest = await attestationsFor(pubkey);
  const verdict = {
    ok: true,
    domain: 'datu-auth-v1',
    rp_id: c.rp_id,
    pubkey,
    node_reachable: attest.reachable,
    attestations: attest.claims,
  };
  // Recorded so the QR page can show the result live, without the phone
  // having to come back to that tab.
  entry.verified = verdict;
  return verdict;
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://demo');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return send(res, 200, await pageHome(req), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/auth/callback') {
      return send(res, 200, pageCallback(req), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/api/challenge') {
      const nonce = url.searchParams.get('nonce') || '';
      const entry = challenges.get(nonce);
      if (!entry) return send(res, 404, { state: 'unknown' });
      if (entry.verified) return send(res, 200, { state: 'verified', ...entry.verified });
      if (entry.usedAt) return send(res, 200, { state: 'refused' });
      if (Date.now() > entry.challenge.expires_at_ms) return send(res, 200, { state: 'expired' });
      return send(res, 200, { state: 'open', expires_at_ms: entry.challenge.expires_at_ms });
    }
    if (req.method === 'GET' && url.pathname === '/api/status') {
      return send(res, 200, { ok: true, open: challenges.size, node: NODE_URL });
    }
    if (req.method === 'POST' && url.pathname === '/api/verify') {
      let body = '';
      req.on('data', (d) => {
        body += d;
        if (body.length > 64 * 1024) req.destroy();
      });
      req.on('end', async () => {
        let parsed = {};
        try {
          parsed = JSON.parse(body || '{}');
        } catch {
          return send(res, 400, { ok: false, error: 'body must be JSON' });
        }
        const verdict = await verifyAssertion(parsed.assertion);
        return send(res, verdict.ok ? 200 : 400, verdict);
      });
      return;
    }
    return send(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    return send(res, 500, { ok: false, error: String(e?.message || e) });
  }
});

server.listen(PORT, HOST, () => {
  const bound = server.address().port;
  console.log(`DATU sign-in demo on http://${HOST}:${bound} (verifier: ${DATU}, node: ${NODE_URL})`);
  if (process.send) process.send({ port: server.address().port });
});
