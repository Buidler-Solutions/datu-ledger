const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let identities = [];
let myRecords = [];
let pendingSign = null; // { document, role, kind }
let idleTimer = null;

// Wallets = one datu wallet bridge each (own directory, passphrases, token).
let wallets = []; // [{ label, url }]
let activeUrl = '';
let tokens = {}; // bridge url -> pairing token (session only)

const DEFAULT_WALLET = { label: 'default', url: 'http://127.0.0.1:7488' };

// ---------- status ----------
const status = (msg, kind = 'muted') => {
  const el = $('status');
  el.textContent = msg;
  el.className = kind === 'err' ? 'err' : kind === 'ok' ? 'ok' : 'muted';
  $('bridgeDot').className = `dot ${kind === 'err' ? 'red' : 'green'}`;
};

// ---------- storage ----------
const localGet = (keys) => chrome.storage.local.get(keys);
const localSet = (obj) => chrome.storage.local.set(obj);
const sessionGet = (keys) =>
  chrome.storage.session ? chrome.storage.session.get(keys) : chrome.storage.local.get(keys);
const sessionSet = (obj) =>
  chrome.storage.session ? chrome.storage.session.set(obj) : chrome.storage.local.set(obj);

// ---------- http ----------
const bridgeUrl = () => activeUrl.replace(/\/+$/, '');
const nodeUrl = () => $('node').value.trim().replace(/\/+$/, '');

function timeoutSignal(ms = 20000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, done: () => clearTimeout(timer) };
}

async function call(url, { method = 'GET', body, auth = false, token } = {}) {
  const { signal, done } = timeoutSignal();
  try {
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (auth) {
      const bearer = token ?? tokens[bridgeUrl()];
      if (!bearer) throw new Error('not paired with this Signet - paste its token in Settings');
      headers['Authorization'] = `Bearer ${bearer}`;
    }
    const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, signal });
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = { error: text }; }
    if (res.status === 401) {
      delete tokens[bridgeUrl()];
      await sessionSet({ tokens });
      document.querySelector('nav button[data-tab="settings"]').click();
      throw new Error(json.error || 'pairing token rejected - re-pair in Settings');
    }
    if (!res.ok) {
      // Version skew: a bridge older than this panel has no SignetAuth route.
      const message = json.error || `HTTP ${res.status}`;
      throw new Error(
        /no route for/i.test(message)
          ? `${message} - this Signet service predates SignetAuth; restart it with the current datu binary (datu signet serve)`
          : message,
      );
    }
    return json;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('request timed out');
    throw e;
  } finally {
    done();
  }
}

const bridge = (path, body) => call(`${bridgeUrl()}${path}`, { method: body ? 'POST' : 'GET', body, auth: true });
const nodeGet = (path) => call(`${nodeUrl()}${path}`);

// ---------- wallets ----------
function renderWallets() {
  const select = $('walletSelect');
  select.innerHTML = '';
  for (const wallet of wallets) {
    const option = document.createElement('option');
    option.value = wallet.url;
    option.textContent = `${wallet.label} - ${wallet.url}`;
    select.appendChild(option);
  }
  const active = wallets.find((w) => w.url === activeUrl);
  if (active) {
    select.value = active.url;
    $('brandSub').textContent = `${active.label} · ${active.url.replace(/^https?:\/\//, '')}`;
    $('walletLabel').value = active.label;
    $('walletUrl').value = active.url;
  } else {
    $('brandSub').textContent = 'no Signet paired';
  }
}

async function persistWallets() {
  await localSet({ wallets });
  await sessionSet({ activeWallet: activeUrl, tokens });
  renderWallets();
}

async function pairWallet(url, token, label) {
  activeUrl = url.replace(/\/+$/, '');
  tokens[activeUrl] = token;
  if (label) {
    const existing = wallets.find((w) => w.url === activeUrl);
    if (existing) existing.label = label;
    else wallets.push({ label, url: activeUrl });
  }
  if (!wallets.some((w) => w.url === activeUrl)) {
    wallets.push({ label: activeUrl.replace(/^https?:\/\//, ''), url: activeUrl });
  }
  await persistWallets();
  const data = await bridge('/v1/wallet/identities');
  identities = data.identities || [];
  const select = $('identity');
  const keep = select.value;
  select.innerHTML = '';
  for (const id of identities) {
    const option = document.createElement('option');
    option.value = id.name;
    option.textContent = `${id.name} · ${id.ed_public.slice(0, 8)}…`;
    select.appendChild(option);
  }
  if (identities.some((i) => i.name === keep)) select.value = keep;
  showSeal();
  notifyState();
  $('pairHint').textContent = `paired · ${identities.length} identities · token kept for this browser session`;
  setConnState('connected');
  status(`Signet ready - ${identities.length} identities`, 'ok');
  checkNode(true);
}

// 7488 first: the canonical desktop bridge (LaunchAgent / DATU Wallet.app).
const PROBE_PORTS = ['7488', '7588', '7482', '7483', '7480', '7481', '7484', '7485', '7489', '7490'];
// Which features a service offers. The probe exists so the panel can prefer a
// current service over an older one running on another port: a stale app
// without SignetAuth should never be the one the panel pairs with when a
// current one is also up.
const bridgeFeatures = {}; // url -> Set(features)
// Browser calls to the bridge are POSTs: Chromium attaches the extension's
// true chrome-extension:// Origin to every POST (and forbids forging it),
// while GETs from extensions carry no Origin at all. The pairing token is
// bound to that Origin, so reads must go over POST too.
async function bridgePost(url, path, token, timeoutMs = 1500) {
  return fetch(`${url}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: '{}',
    signal: AbortSignal.timeout(timeoutMs),
  });
}
async function probeFeatures(url, token) {
  if (bridgeFeatures[url]) return bridgeFeatures[url];
  try {
    const res = await bridgePost(url, '/v1/wallet/capabilities', token);
    if (!res.ok) return new Set();
    const json = await res.json();
    const set = new Set(Array.isArray(json.features) ? json.features : []);
    bridgeFeatures[url] = set;
    return set;
  } catch {
    return new Set();
  }
}

async function autoPair() {
  const candidates = [];
  for (const port of PROBE_PORTS) {
    const url = `http://127.0.0.1:${port}`;
    let token = tokens[url];
    if (token) {
      const features = await probeFeatures(url, token);
      const reachable = await bridgePost(url, '/v1/wallet/identities', token)
        .then((r) => r.ok)
        .catch(() => false);
      if (reachable) {
        candidates.push({ url, token, port, features });
        continue;
      }
      delete tokens[url]; // stale token (bridge restarted) - mint a fresh one
      await sessionSet({ tokens });
    }
    try {
      const res = await bridgePost(url, '/v1/pair');
      if (!res.ok) continue;
      const data = await res.json();
      if (!data || !data.token) continue;
      const features = await probeFeatures(url, data.token);
      candidates.push({ url, token: data.token, port, features });
    } catch {}
  }
  if (!candidates.length) return false;
  // Prefer a service that speaks SignetAuth; fall back to a legacy one only
  // when nothing better is running.
  const modern = candidates.filter((c) => c.features.has('auth-assert'));
  const chosen = modern[0] || candidates[0];
  await pairWallet(chosen.url, chosen.token, `datu · ${chosen.port}`);
  if (!chosen.features.has('auth-assert')) {
    setConnState(
      'legacy',
      `connected to ${chosen.url}, which predates SignetAuth (login needs a current Signet). Update the DATU Wallet app, or start the current binary: datu signet serve --addr 127.0.0.1:7588`,
    );
    status('paired with an older Signet - SignetAuth login is unavailable until it is updated', 'err');
  } else {
    status(`auto-paired with the Signet service at ${chosen.url}`, 'ok');
  }
  return true;
}

// ---- connection state: auto-detect the local Signet, explain how to get one ----
const REPO_URL = 'https://github.com/greenarmor/datu-ledger';
const RELEASES_URL = 'https://github.com/greenarmor/datu-ledger/releases';

function setConnState(kind, detail = '') {
  const text = $('connText');
  const hint = $('installHint');
  if (!text) return;
  if (kind === 'connected') {
    const active = wallets.find((w) => w.url === activeUrl);
    text.className = 'ok small';
    text.textContent = `connected: ${active ? active.url : activeUrl} - ${identities.length} identities, paired automatically`;
    if (hint) hint.style.display = 'none';
    $('bridgeDot').className = 'dot green';
    return;
  }
  if (kind === 'searching') {
    text.className = 'muted small';
    text.textContent = detail || 'looking for a local Signet service…';
    if (hint) hint.style.display = 'none';
    return;
  }
  if (kind === 'legacy') {
    text.className = 'err small';
    text.textContent = detail || 'connected to an older Signet service that predates SignetAuth';
    if (hint) hint.style.display = 'block';
    $('bridgeDot').className = 'dot red';
    return;
  }
  // not-found: the extension needs a local Signet; show install guidance
  text.className = 'err small';
  text.textContent =
    detail ||
    'no Signet service found. Install or launch the DATU Wallet desktop app (or run datu signet serve), then press Connect now.';
  if (hint) hint.style.display = 'block';
  $('bridgeDot').className = 'dot red';
}

async function connectSignet({ quiet = false } = {}) {
  if (!quiet) setConnState('searching');
  status('looking for a local Signet service…', 'muted');
  const found = await autoPair();
  if (found) {
    setConnState('connected');
    return true;
  }
  setConnState('not-found');
  if (!quiet) {
    status('no Signet service answered - see the installation steps in Settings', 'err');
  }
  return false;
}

// Watchdog: the desktop app may start after the browser, or restart mid-session.
// While unpaired, poll quietly so pairing happens without the human doing anything.
let connTimer = null;
function armConnectionWatchdog() {
  clearInterval(connTimer);
  connTimer = setInterval(async () => {
    if (identities.length) return;
    if (document.visibilityState === 'hidden') return;
    await connectSignet({ quiet: true });
  }, 20_000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && !identities.length) {
      connectSignet({ quiet: true });
    }
  });
  window.addEventListener('focus', () => {
    if (!identities.length) connectSignet({ quiet: true });
  });
}

async function addWallet() {
  try {
    const label = $('walletLabel').value.trim() || 'wallet';
    let url = $('walletUrl').value.trim().replace(/\/+$/, '');
    const token = $('token').value.trim();
    if (!url) throw new Error('enter the bridge URL');
    if (!token) throw new Error('paste the pairing token (legacy Signets only; current ones auto-pair per extension)');
    if (!/^https?:\/\//.test(url)) url = `http://${url}`;
    try {
      await pairWallet(url, token, label);
    } catch (e) {
      const unreachable = /failed to fetch|networkerror|timed out|load failed/i.test(e.message);
      if (!unreachable) throw e;
      const fallback = 'http://127.0.0.1:7488';
      if (url === fallback) throw new Error(`cannot reach ${url} - is DATU Signet running?`);
      const res = await bridgePost(fallback, '/v1/pair', null, 3000).catch(() => null);
      if (!res || !res.ok) throw new Error(`cannot reach ${url} - is DATU Signet running?`);
      wallets = wallets.filter((w) => w.url !== url);
      delete tokens[url];
      await pairWallet(fallback, (await res.json()).token, label);
      $('walletUrl').value = fallback;
      status(`could not reach ${url} - paired with the desktop Signet service at ${fallback} instead`, 'ok');
      $('token').value = '';
      return;
    }
    $('token').value = '';
  } catch (e) {
    status(e.message, 'err');
  }
}

async function switchWallet() {
  try {
    const url = $('walletSelect').value;
    if (!url) throw new Error('no Signet to switch to');
    activeUrl = url;
    const wallet = wallets.find((w) => w.url === url);
    $('walletLabel').value = wallet ? wallet.label : '';
    $('walletUrl').value = url;
    if (!tokens[url]) {
      await persistWallets();
      $('pairHint').textContent = 'this Signet is not paired yet - press Connect now, or use the advanced token field';
      setConnState('not-found', `switched to ${url}, which is not paired yet - press Connect now`);
      status(`switched to ${url} - not paired`, 'muted');
      return;
    }
    await pairWallet(url, tokens[url], wallet?.label);
  } catch (e) {
    status(e.message, 'err');
  }
}

async function removeWallet() {
  const url = $('walletSelect').value;
  wallets = wallets.filter((w) => w.url !== url);
  delete tokens[url];
  if (activeUrl === url) {
    activeUrl = wallets[0]?.url ?? '';
    identities = [];
  }
  await persistWallets();
  if (activeUrl && tokens[activeUrl]) {
    await pairWallet(activeUrl, tokens[activeUrl]);
  } else {
    status('Signet removed', 'muted');
  }
}

async function forgetToken() {
  delete tokens[bridgeUrl()];
  identities = [];
  $('identity').innerHTML = '';
  $('token').value = '';
  await sessionSet({ tokens });
  $('pairHint').textContent = 'token forgotten for this Signet - pair again to use it';
  status('pairing token forgotten', 'muted');
}

// ---------- identity ----------
function selected() {
  const name = $('identity').value;
  const identity = identities.find((i) => i.name === name);
  if (identity) return identity;
  if (!identities.length) {
    throw new Error('no identity on this Signet yet - create one in Settings, then pair');
  }
  if (!name) throw new Error('pick an identity in the header first');
  throw new Error(`identity '${name}' is not on this Signet - pick another in the header`);
}

// Re-read the identity list from the bridge and rebuild the header picker.
// The passkey and backup flows call this first: after a browser restart the
// panel can be paired with an empty picker, which looked like "select an
// identity first" with nothing to select.
async function refreshIdentities() {
  const data = await bridge('/v1/wallet/identities');
  const list = data.identities || [];
  if (!list.length) throw new Error('this Signet has no identities yet - create one in Settings');
  identities = list;
  const select = $('identity');
  const keep = select.value;
  select.innerHTML = '';
  for (const id of list) {
    const option = document.createElement('option');
    option.value = id.name;
    option.textContent = `${id.name} · ${id.ed_public.slice(0, 8)}…`;
    select.appendChild(option);
  }
  if (list.some((i) => i.name === keep)) select.value = keep;
  showSeal();
  return list;
}

function showSeal() {
  try {
    const identity = selected();
    $('seal').textContent = `seal ${identity.seal_public.slice(0, 20)}…`;
    $('sealFull').textContent = identity.seal_public;
  } catch {
    $('seal').textContent = '';
    $('sealFull').textContent = '';
  }
}

// ---------- tabs ----------
document.querySelectorAll('nav button[data-tab]').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('section[data-panel]').forEach((s) => s.classList.remove('active'));
    button.classList.add('active');
    document.querySelector(`section[data-panel="${button.dataset.tab}"]`).classList.add('active');
  });
});

// ---------- node ----------
// The typed node URL wins; when nothing answers there, probe the usual
// local ports and adopt the first live ledger node, so a stale default
// (7475, 7474, ...) never reads as "node down" while an explorer is up.
const NODE_CANDIDATES = ['7574', '7474', '7480', '7490', '7575'];
async function adoptLiveNode() {
  const configured = nodeUrl();
  const ports = NODE_CANDIDATES.filter((port) => !configured.includes(`:${port}`));
  for (const port of ports) {
    const url = `http://127.0.0.1:${port}`;
    try {
      const res = await fetch(`${url}/v1/status`, { signal: AbortSignal.timeout(1500) });
      if (!res.ok) continue;
      const st = await res.json();
      if (typeof st.entries !== 'number') continue; // not a datu node
      $('node').value = url;
      await localSet({ node: url });
      return st;
    } catch {}
  }
  return null;
}

async function checkNode(quiet = false) {
  try {
    const st = await nodeGet('/v1/status');
    const mode = st.policy?.mode ?? '?';
    $('modeText').textContent = `${mode} · ${st.entries}`;
    $('modeDot').className = `dot ${mode === 'open-observer' ? 'green' : 'blue'}`;
    if (!quiet) status(`node ok - ${mode}, ${st.entries} entries, ${st.checkpoints} witnesses`, 'ok');
  } catch (e) {
    const found = await adoptLiveNode();
    if (found) {
      const mode = found.policy?.mode ?? '?';
      $('modeText').textContent = `${mode} · ${found.entries}`;
      $('modeDot').className = `dot ${mode === 'open-observer' ? 'green' : 'blue'}`;
      if (!quiet) {
        status(
          `node moved to ${nodeUrl()} - ${mode}, ${found.entries} entries (the previous URL was down: ${e.message})`,
          'ok',
        );
      }
      return;
    }
    $('modeText').textContent = 'node down';
    $('modeDot').className = 'dot red';
    if (!quiet) status(`cannot reach node: ${e.message}`, 'err');
  }
}

// ---------- records (any namespace, any kind) ----------
function nsMatches(pattern, ns) {
  if (!pattern) return true;
  return pattern.endsWith('*') ? ns.startsWith(pattern.slice(0, -1)) : ns === pattern;
}

function concernsMe(payload, me) {
  if (!payload) return false;
  if ((payload.parties || []).some((p) => p.key === me.ed_public)) return true;
  const doc = payload.doc ?? payload;
  return Object.values(doc).some((v) => v === me.ed_public);
}

// Deferred-delivery fields (wallet seal-deferred): ciphertext on the ledger
// from day one, but the content key's other half is published only by the
// release entry. The holder cannot open them until that release lands.
const DEFERRED_MARK = 'datu-sealed-deferred-v2';

function payloadDoc(payload) {
  return payload?.doc ?? payload ?? {};
}

function deferredFields(payload) {
  const doc = payloadDoc(payload);
  if (!doc || typeof doc !== 'object') return [];
  return Object.entries(doc)
    .filter(([, value]) => value && typeof value === 'object' && value.sealed === DEFERRED_MARK)
    .map(([name]) => name);
}

function recordLabel(payload, id) {
  const doc = payload?.doc ?? payload ?? {};
  const candidates = ['parcel', 'title_no', 'license_id', 'license_no', 'licence_no',
    'lot', 'bid_id', 'permit_no', 'reference', 'ref', 'object', 'subject', 'id', 'name'];
  for (const key of candidates) {
    if (typeof doc[key] === 'string' && doc[key]) return `${key.replace(/_/g, ' ')} · ${doc[key]}`;
  }
  const first = Object.entries(doc).find(([, v]) => typeof v === 'string' && v);
  return first ? `${first[0].replace(/_/g, ' ')} · ${first[1]}` : `${id.slice(0, 12)}…`;
}

async function findMyRecords() {
  $('records').innerHTML = '';
  $('verdict').style.display = 'none';
  try {
    const identity = selected();
    const pattern = $('nsFilter').value.trim();
    const list = await nodeGet('/v1/entries?limit=200');
    // Attestation revocations (identity.revoke): a trusted statement names
    // the attestation id it kills. Best-effort - older nodes may not serve
    // the namespace, and the badge is informational, never a verdict.
    const revoked = {}; // attestation id -> revoker entry author
    try {
      const revokes = await nodeGet('/v1/entries?ns=identity.revoke&limit=200');
      for (const item of revokes.entries || []) {
        try {
          const full = await nodeGet(`/v1/entry/${item.id}`);
          const body = JSON.parse(new TextDecoder().decode(
            Uint8Array.from(atob(full.payload_base64), (c) => c.charCodeAt(0)),
          ));
          if (typeof body.attestation === 'string') {
            revoked[body.attestation] = full.author ?? item.author ?? '(unknown signer)';
          }
        } catch { /* skip malformed revoke */ }
      }
    } catch { /* best-effort */ }
    myRecords = [];
    for (const item of list.entries || []) {
      if (!nsMatches(pattern, item.namespace)) continue;
      const full = await nodeGet(`/v1/entry/${item.id}`);
      let payload;
      try {
        payload = JSON.parse(new TextDecoder().decode(
          Uint8Array.from(atob(full.payload_base64), (c) => c.charCodeAt(0)),
        ));
      } catch { continue; }
      if (!concernsMe(payload, identity)) continue;
      const doc = payload?.doc ?? payload ?? {};
      // An agreement anchor declares a contract for a future document
      // (escrow, reward offer): the pending view is what a Signet holder
      // watches go OUTSTANDING -> READY without reading a single field.
      const contract = doc.contract && typeof doc.contract.id === 'string' ? doc.contract : null;
      let outlook = null;
      if (contract) {
        try { outlook = await nodeGet(`/v1/contract/status/${item.id}`); } catch { /* best-effort */ }
      }
      myRecords.push({
        id: item.id,
        seq: item.seq,
        namespace: item.namespace,
        kind: payload?.kind ?? '(unsigned document)',
        label: recordLabel(payload, item.id),
        entry: full,
        payload,
        contract,
        outlook,
        revokedBy: revoked[item.id] || null,
        deferred: deferredFields(payload),
      });
    }
    if (!myRecords.length) {
      status(pattern ? `no records match '${pattern}' for you` : 'no records on this node concern you', 'muted');
      return;
    }
    myRecords.forEach((rec, i) => {
      const card = document.createElement('div');
      card.className = 'record';
      const head = document.createElement('div');
      head.className = 'head';
      const label = document.createElement('span');
      label.className = 'parcel';
      label.textContent = rec.label;
      const meta = document.createElement('span');
      meta.className = 'meta';
      meta.textContent = `${rec.kind} · seq ${rec.seq}`;
      head.append(label, meta);
      const ns = document.createElement('div');
      ns.className = 'meta';
      ns.textContent = `${rec.namespace} · ${rec.id.slice(0, 12)}…`;
      const actions = document.createElement('div');
      actions.className = 'actions';
      const verify = document.createElement('button');
      verify.className = 'ghost';
      verify.textContent = 'Verify';
      verify.addEventListener('click', () => verifyRecord(i));
      const open = document.createElement('button');
      open.className = 'ghost';
      open.textContent = 'Decrypt';
      open.addEventListener('click', () => decryptRecord(i));
      const witnessed = document.createElement('button');
      witnessed.className = 'ghost';
      witnessed.textContent = 'Witnessed';
      witnessed.addEventListener('click', () => showWitnesses(i));
      actions.append(verify, open, witnessed);
      if (rec.revokedBy) {
        const revoked = document.createElement('div');
        revoked.className = 'meta err';
        revoked.textContent = `REVOKED by ${String(rec.revokedBy).slice(0, 16)}… - this attestation no longer admits where that signer is a trusted root`;
        card.insertBefore(revoked, actions);
      }
      if (rec.deferred.length) {
        const deferredLine = document.createElement('div');
        deferredLine.className = 'meta';
        deferredLine.textContent = `${rec.deferred.length} field(s) sealed for deferred delivery (${rec.deferred.join(', ')}) - the release entry carries the key half`;
        card.insertBefore(deferredLine, actions);
        const deferredButton = document.createElement('button');
        deferredButton.className = 'ghost';
        deferredButton.textContent = 'Open deferred';
        deferredButton.addEventListener('click', () => openDeferred(i, rec.deferred[0]));
        actions.append(deferredButton);
      }
      if (rec.contract) {
        const conditions = document.createElement('button');
        conditions.className = 'ghost';
        conditions.textContent = 'Conditions';
        conditions.addEventListener('click', () => showConditions(i));
        actions.append(conditions);
        if (rec.outlook) {
          const pending = document.createElement('div');
          pending.className = 'meta';
          pending.textContent = rec.outlook.ready
            ? `conditions met - a '${rec.outlook.admits}' may land (${rec.outlook.citing?.length ?? 0} evidence entries)`
            : `conditions pending - ${rec.outlook.conditions?.filter((c) => !c.met).length ?? '?'} outstanding`;
          card.insertBefore(pending, actions);
        }
      }
      card.append(head, ns, actions);
      $('records').append(card);
    });
    status(`${myRecords.length} record(s) concern you${pattern ? ` in ${pattern}` : ' (any namespace)'} - verified locally`, 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

// Full pending view of an agreement that declares a contract: the same
// pure predicate admission uses, judged over the entries citing the
// anchor. Read-only; nothing to sign, nothing to decrypt.
async function showConditions(index) {
  try {
    const rec = myRecords[index];
    const o = rec.outlook ?? await nodeGet(`/v1/contract/status/${rec.id}`);
    const lines = [
      `${o.ready ? 'READY' : 'OUTSTANDING'}  ${o.kind}`,
      `awaits     a '${o.admits}' document citing this anchor`,
      `contract   ${(o.contract_id || '').slice(0, 16)}… v${o.version}`,
    ];
    for (const reason of o.reasons || []) lines.push(`reason     ${reason}`);
    if ((o.conditions || []).length) {
      lines.push('conditions:');
      for (const condition of o.conditions) {
        lines.push(`  [${condition.met ? 'met    ' : 'NOT MET'}] ${condition.requirement} (required: ${condition.required}, found: ${condition.found})`);
      }
    }
    if ((o.citing || []).length) {
      lines.push(`evidence (${o.citing.length} citing entries):`);
      for (const cited of o.citing) {
        lines.push(`  ${cited.id.slice(0, 12)}…  ${cited.kind ?? '-'}  ${cited.namespace}  ts ${cited.timestamp_ms}`);
      }
    }
    $('verdict').style.display = 'block';
    $('verdict').textContent = lines.join('\n');
    status(o.ready ? 'citation-side conditions are met - the satisfying document may land' : 'conditions outstanding', o.ready ? 'ok' : 'muted');
  } catch (e) {
    status(`cannot evaluate contract: ${e.message}`, 'err');
  }
}

async function verifyRecord(index) {
  try {
    const rec = myRecords[index];
    const data = await bridge('/v1/wallet/verify-entry', { entry: rec.entry });
    const parties = (data.parties || [])
      .map((p) => `[${p.role}] ${p.key.slice(0, 16)}… verified`)
      .join('\n');
    $('verdict').style.display = 'block';
    $('verdict').textContent =
      `VERIFIED  ${data.id}\nauthor     ${data.author}\nnamespace  ${data.namespace} seq ${data.seq}\n` +
      `parties:\n${parties}\n\n${data.note}`;
    status('signatures verified locally (Ed25519 + ML-DSA-65)', 'ok');
  } catch (e) {
    status(`verification failed: ${e.message}`, 'err');
  }
}

// Witness time-attestation: which fresh checkpoints cover this entry, as of
// when. Each line is backed by the served Merkle proof, which verifies
// offline (datu witness verify-proof) - the panel only displays it.
async function showWitnesses(index) {
  try {
    const rec = myRecords[index];
    const data = await nodeGet(`/v1/coverage/${rec.id}`);
    const witnesses = data.witnesses || [];
    const lines = [];
    if (!witnesses.length) {
      lines.push('No fresh witness covers this entry on this node right now.');
      lines.push('Coverage follows the next checkpoint a witness signs over it.');
    } else {
      lines.push(`witnessed by ${witnesses.length} node(s):`);
      for (const w of witnesses) {
        let verdict = 'NOT CHECKED';
        try {
          const check = await window.datuCoverage.verifyWitness(rec.id, w);
          verdict = check.ok
            ? check.signature === 'ok'
              ? 'verified locally (merkle path + Ed25519)'
              : 'path verified locally; signature checked by your node (no WebCrypto Ed25519 here)'
            : `NOT VERIFIED: ${check.reason}`;
        } catch (e) {
          verdict = `NOT VERIFIED: ${e.message}`;
        }
        lines.push(
          `  ${String(w.signer).slice(0, 16)}…  as of ${new Date(w.timestamp_ms).toISOString()}  (checkpoint height ${w.height})
    ${verdict}`,
        );
      }
      lines.push('');
      lines.push('The Merkle path and the checkpoint signature are re-checked in this panel; the node only relays witnesses.');
    }
    for (const behind of data.stale || []) {
      lines.push(`  behind: ${String(behind.signer).slice(0, 16)}… (${behind.reason})`);
    }
    $('verdict').style.display = 'block';
    $('verdict').textContent = lines.join('\n');
    status(
      witnesses.length ? `${witnesses.length} witness checkpoint(s) cover this entry` : 'no fresh witness yet',
      witnesses.length ? 'ok' : 'muted',
    );
  } catch (e) {
    status(`coverage lookup failed: ${e.message}`, 'err');
  }
}

async function decryptRecord(index) {
  try {
    const identity = selected();
    const rec = myRecords[index];
    if (!$('pass').value) throw new Error('enter your vault passphrase (Sign tab)');
    const data = await bridge('/v1/wallet/open', {
      name: identity.name,
      passphrase: $('pass').value,
      document: rec.payload,
    });
    const doc = data.document.doc ?? data.document;
    $('decrypted').style.display = 'block';
    $('decrypted').textContent =
      `${data.opened} field(s) decrypted for you, ${data.skipped} sealed for others\n\n` +
      JSON.stringify(doc, null, 2);
    document.querySelector('nav button[data-tab="data"]').click();
    status(data.opened > 0 ? 'your data, decrypted locally' : 'nothing is sealed to you', data.opened > 0 ? 'ok' : 'muted');
  } catch (e) {
    status(e.message, 'err');
  }
}

// Open a deferred-delivery field: the release entry publishes the key half
// as a 'datu-share-v2' object; paste it here and the bridge recomposes the
// key locally. Wrong holder, wrong field, or a tampered share fail closed.
function openDeferred(index, field) {
  const rec = myRecords[index];
  const verdict = $('verdict');
  verdict.style.display = 'block';
  verdict.textContent = '';
  const form = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'muted';
  title.textContent = `Paste the release object the release entry published (datu-share-v2) for '${field}':`;
  const input = document.createElement('textarea');
  input.rows = 5;
  input.placeholder = '{"sealed":"datu-share-v2","recipient":{...}}';
  const submit = document.createElement('button');
  submit.className = 'ghost';
  submit.textContent = 'Open field';
  const hint = document.createElement('div');
  hint.className = 'muted';
  hint.textContent =
    'The release half is sealed to you only; the field opens with zero trust in the node.';
  submit.addEventListener('click', async () => {
    try {
      const identity = selected();
      if (!$('pass').value) throw new Error('enter your vault passphrase (Sign tab)');
      const raw = input.value.trim();
      if (!raw) throw new Error('paste the release object first');
      let release;
      try {
        release = JSON.parse(raw);
      } catch {
        throw new Error('release object must be JSON');
      }
      const data = await bridge('/v1/wallet/deferred-open', {
        name: identity.name,
        passphrase: $('pass').value,
        document: payloadDoc(rec.payload),
        field,
        release,
      });
      $('decrypted').style.display = 'block';
      $('decrypted').textContent = `${field} (opened with the release half):\n\n${JSON.stringify(
        data.value,
        null,
        2,
      )}`;
      document.querySelector('nav button[data-tab="data"]').click();
      status(`'${field}' opened - the release half was sealed to you`, 'ok');
    } catch (e) {
      status(`cannot open deferred field: ${e.message}`, 'err');
    }
  });
  form.append(title, input, submit, hint);
  verdict.append(form);
}

// ---------- consent (review, then confirm) ----------
function reviewConsent() {
  try {
    const identity = selected();
    const document = JSON.parse($('doc').value);
    if (!$('pass').value) throw new Error('enter your vault passphrase');
    const role = $('role').value.trim() || 'holder';
    const kind = document.kind || $('kind').value.trim();
    if (!kind) throw new Error('enter the document kind (e.g. land.title.application, procurement.bid)');
    const keyField = `${role}_key`;
    const namedKey = document?.doc?.[keyField];
    if (namedKey && namedKey !== identity.ed_public) {
      throw new Error(
        `this document names ${keyField} ${namedKey.slice(0, 16)}… but you are ${identity.ed_public.slice(0, 16)}… - not a party to this record`,
      );
    }
    pendingSign = { document, role, kind };

    const parties = (document.parties || []).map((p) => p.role).join(', ') || 'none yet';
    $('confirmSummary').innerHTML = [
      `<div><span class="k">action</span> <b>sign as ${role}</b></div>`,
      `<div><span class="k">kind</span> <b>${kind}</b></div>`,
      `<div><span class="k">document subject</span> <b>${recordLabel(document, identity.ed_public).slice(0, 60)}</b></div>`,
      `<div><span class="k">your role key (${role}_key)</span> <b>${(document?.doc?.[`${role}_key`] ?? 'not named').slice(0, 16)}…</b></div>`,
      `<div><span class="k">parties already signed</span> <b>${parties}</b></div>`,
      `<div><span class="k">document size</span> <b>${JSON.stringify(document).length} bytes</b></div>`,
    ].join('');
    $('confirmBox').style.display = 'block';
    status('review the summary, then confirm', 'muted');
  } catch (e) {
    pendingSign = null;
    $('confirmBox').style.display = 'none';
    status(e.message, 'err');
  }
}

async function confirmSign() {
  try {
    if (!pendingSign) throw new Error('nothing to sign');
    const identity = selected();
    status('unlocking your Signet and signing…');
    const data = await bridge('/v1/wallet/party-sign', {
      name: identity.name,
      passphrase: $('pass').value,
      role: pendingSign.role,
      kind: pendingSign.kind,
      document: pendingSign.document,
    });
    $('result').value = JSON.stringify(data.document, null, 2);
    $('copy').disabled = false;
    $('confirmBox').style.display = 'none';
    pendingSign = null;
    status(`signed as ${data.role} - Ed25519 + ML-DSA-65`, 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

function cancelSign() {
  pendingSign = null;
  $('confirmBox').style.display = 'none';
  status('signing cancelled', 'muted');
}

async function openPasted() {
  try {
    const identity = selected();
    const passphrase = $('pass').value;
    if (!passphrase) throw new Error('enter your vault passphrase');
    const raw = $('openDoc').value.trim();
    if (!raw) throw new Error('paste a record first');
    const parsed = JSON.parse(raw);
    const document = parsed.payload_base64
      ? JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(parsed.payload_base64), (c) => c.charCodeAt(0))))
      : parsed;
    const data = await bridge('/v1/wallet/open', { name: identity.name, passphrase, document });
    $('opened').style.display = 'block';
    $('opened').textContent =
      `${data.opened} field(s) decrypted for you, ${data.skipped} sealed for others\n\n` +
      JSON.stringify(data.document.doc ?? data.document, null, 2);
    status(data.opened > 0 ? 'your fields are readable' : 'nothing is sealed to you', data.opened > 0 ? 'ok' : 'muted');
  } catch (e) {
    status(e.message, 'err');
  }
}

// ---------- SignetAuth login (review, then confirm) ----------
// Level 1: the site's challenge is signed with the selected identity; the
// assertion goes back to the site and is worthless on any other site, origin
// or nonce. Review shows exactly what is being signed.
let pendingLogin = null; // { rp_id, origin, nonce, expires_at_ms }

function reviewLogin() {
  try {
    const identity = selected();
    if (!$('pass').value) throw new Error('enter your vault passphrase (Sign tab)');
    const rp_id = $('loginRp').value.trim();
    const origin = $('loginOrigin').value.trim();
    const nonce = $('loginNonce').value.trim().toLowerCase();
    const expiresRaw = $('loginExpires').value.trim();
    if (!rp_id) throw new Error('enter the site id (rp_id, e.g. app.example.com)');
    if (!origin) throw new Error('enter the origin the login request came from');
    if (!/^[0-9a-f]{32}$/.test(nonce)) throw new Error('nonce must be 32 hex chars (issued by the site)');
    const expires_at_ms = expiresRaw
      ? (/^\d+$/.test(expiresRaw) ? Number(expiresRaw) : NaN)
      : Date.now() + 60000;
    if (!Number.isFinite(expires_at_ms)) throw new Error('expiry must be milliseconds since epoch');
    if (expires_at_ms <= Date.now()) throw new Error('this challenge has already expired - ask the site for a fresh one');
    pendingLogin = { rp_id, origin, nonce, expires_at_ms };
    $('loginSummary').innerHTML = [
      `<div><span class="k">sign in to</span> <b>${esc(rp_id)}</b></div>`,
      `<div><span class="k">origin</span> <b>${esc(origin)}</b></div>`,
      `<div><span class="k">as identity</span> <b>${esc(identity.name)} · ${identity.ed_public.slice(0, 16)}…</b></div>`,
      `<div><span class="k">nonce (single use)</span> <b>${esc(nonce)}</b></div>`,
      `<div><span class="k">expires</span> <b>${new Date(expires_at_ms).toISOString()}</b></div>`,
      '<div><span class="k">domain</span> <b>datu-auth-v1 (never a ledger entry)</b></div>',
      '<div><span class="k">origin pin</span> <b>first sign-in registers this origin; any other origin is refused afterwards</b></div>',
    ].join('');
    $('loginConfirm').style.display = 'block';
    status('review the sign-in, then approve', 'muted');
  } catch (e) {
    pendingLogin = null;
    $('loginConfirm').style.display = 'none';
    status(e.message, 'err');
  }
}

async function confirmLogin() {
  try {
    if (!pendingLogin) throw new Error('nothing to sign');
    const identity = selected();
    if (!$('pass').value) throw new Error('enter your vault passphrase (Sign tab)');
    await stepUpIfProtected(identity.name);
    status('unlocking your Signet and signing the challenge…');
    const data = await bridge('/v1/wallet/auth-assert', {
      name: identity.name,
      passphrase: $('pass').value,
      rp_id: pendingLogin.rp_id,
      origin: pendingLogin.origin,
      nonce: pendingLogin.nonce,
      expires_at_ms: pendingLogin.expires_at_ms,
      // The Approve click is the user-presence gesture: first use of a site
      // registers its origin for this identity (the bridge pins it after).
      approve: true,
    });
    if (data.domain !== 'datu-auth-v1') throw new Error('unexpected assertion domain from the bridge');
    if (data.grant) {
      grantCache[bridgeUrl()] = grantCache[bridgeUrl()] || {};
      grantCache[bridgeUrl()][identity.name] = data.grant;
      await persistGrants();
    }
    $('loginResult').value = JSON.stringify(data, null, 2);
    $('loginCopy').disabled = false;
    $('loginConfirm').style.display = 'none';
    pendingLogin = null;
    status(`signed in to ${data.rp_id} - paste the assertion into the site's login form`, 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

function cancelLogin() {
  pendingLogin = null;
  $('loginConfirm').style.display = 'none';
  status('sign-in cancelled', 'muted');
}

// ---------- create identity ----------
async function createIdentity() {
  try {
    const name = $('newName').value.trim();
    const pass = $('newPass').value;
    const confirm = $('newPass2').value;
    if (!name) throw new Error('choose a name for this identity');
    if (pass.length < 8) throw new Error('passphrase must be at least 8 characters');
    if (pass !== confirm) throw new Error('passphrases do not match');
    status('creating identity (Argon2id key stretching)…');
    const data = await bridge('/v1/wallet/create', { name, passphrase: pass });
    await pairWallet(activeUrl, tokens[activeUrl]);
    $('identity').value = data.identity.name;
    showSeal();
    $('newName').value = '';
    $('newPass').value = '';
    $('newPass2').value = '';
    $('createHint').style.display = 'block';
    $('createHint').textContent =
      `identity '${data.identity.name}' created - seal key ${data.identity.seal_public.slice(0, 20)}…\n` +
      `Remember the passphrase: it cannot be recovered. Share only your seal key.`;
    status(`identity '${data.identity.name}' created`, 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

// ---------- backup / restore ----------
async function exportIdentity() {
  try {
    const identity = selected();
    const backupPass = $('backupPass').value;
    if (backupPass.length < 8) throw new Error('backup passphrase must be at least 8 characters');
    const passphrase = $('pass').value;
    if (!passphrase) throw new Error('enter the identity passphrase (Sign tab)');
    status('exporting encrypted backup…');
    const data = await bridge('/v1/wallet/export', {
      name: identity.name,
      passphrase,
      backup_passphrase: backupPass,
    });
    const blob = new Blob([JSON.stringify(data.backup, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${identity.name}.datu-identity.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    status('backup downloaded - keep it with the backup passphrase (they are useless apart)', 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

async function importIdentity() {
  try {
    const file = $('importFile').files[0];
    if (!file) throw new Error('choose a backup file');
    const passphrase = $('importPass').value;
    if (!passphrase) throw new Error('enter the backup passphrase');
    const text = await file.text();
    let backup;
    try { backup = JSON.parse(text); } catch { throw new Error('backup file is not valid JSON'); }
    const rename = $('importRename').value.trim() || null;
    const data = await bridge('/v1/wallet/import', { backup, passphrase, rename });
    await pairWallet(activeUrl, tokens[activeUrl]);
    $('identity').value = data.identity.name;
    showSeal();
    $('importFile').value = '';
    $('importPass').value = '';
    $('importRename').value = '';
    status(`identity '${data.identity.name}' imported - it unlocks with the backup passphrase`, 'ok');
  } catch (e) {
    status(e.message, 'err');
  }
}

// ---------- device passkey unlock (Level 3b) ----------
// The passkey wraps the passphrase: enable stores an AES-GCM blob (key
// derived from the authenticator's PRF output) per identity; unlock runs the
// biometric gesture, unwraps the passphrase into panel memory (passCache)
// and the session grant / signing flows work as if it was typed.
const PASSKEY_PREFIX = 'datu.passkey.';
const SESSION_PASS = 'datu.passkeySessionPass';

// Step-up: when an identity is passkey-protected, every interactive sign-in
// asks for the biometric gesture, so the passkey gates the action itself and
// not merely the session. Silent re-logins (auto) are exempt by design: they
// exist so a page reload does not prompt on every navigation.
const STEPUP_KEY = 'datu.passkeyStepUp';
async function stepUpIfProtected(name) {
  try {
    const stored = await localGet([PASSKEY_PREFIX + name, STEPUP_KEY]);
    const record = stored[PASSKEY_PREFIX + name];
    if (!record) return;
    if (stored[STEPUP_KEY] === false) return;
    if (!window.datuPasskey) return;
    status(`confirm '${name}' with the device passkey…`);
    await window.datuPasskey.presenceAssertion(record.credentialId);
  } catch (e) {
    throw new Error(`passkey confirmation failed: ${e.message}`);
  }
}

// The picker can be empty right after a browser restart even though the
// Signet is paired, so passkey actions refresh the list before selecting.
async function pickIdentityForPasskey() {
  if (!identities.length) await refreshIdentities();
  return selected();
}

// Two modes, chosen by what the device's authenticator supports:
//   prf      - the passkey derives a key (HKDF over the PRF output) that wraps
//              the passphrase; the wrapped blob is all that is stored
//   presence - no PRF (common for Touch ID / iCloud passkeys): the passkey is
//              a user-presence gate and the passphrase lives in session
//              storage only, expiring with the browser session
async function passkeyEnable() {
  try {
    const identity = await pickIdentityForPasskey();
    // A passkey wraps the passphrase, so it is needed once: the field right
    // here, the Sign tab field, or a session that already cached it.
    const passphrase = $('passkeyPass').value || $('pass').value || passCache[identity.name];
    if (!passphrase) throw new Error("type this identity's vault passphrase in the field above");
    if (!window.datuPasskey) throw new Error('passkey module not loaded');
    status('creating the device passkey (follow the system prompt)…');
    const { credentialId, prfEnabled } = await window.datuPasskey.createPasskey(identity.name);
    let record;
    if (prfEnabled) {
      const salt = window.datuPasskey.prfSalt();
      status('confirm the passkey once to activate it…');
      const secret = await window.datuPasskey.unlockSecret(credentialId, salt);
      if (!secret) throw new Error('the device reported PRF support but returned no secret');
      const blob = await window.datuPasskey.wrapPassphrase(secret, passphrase);
      record = { mode: 'prf', credentialId, salt: btoa(String.fromCharCode(...salt)), ...blob };
    } else {
      // Presence mode: prove the gesture works, then keep the passphrase in
      // session storage (memory-backed, dies with the browser session).
      status('this device has no PRF support - using passkey-gated session mode…');
      await window.datuPasskey.presenceAssertion(credentialId);
      const session = await sessionGet([SESSION_PASS]);
      const map = session[SESSION_PASS] || {};
      map[identity.name] = passphrase;
      await sessionSet({ [SESSION_PASS]: map });
      record = { mode: 'presence', credentialId };
    }
    await localSet({ [PASSKEY_PREFIX + identity.name]: record });
    passCache[identity.name] = passphrase;
    notifyState();
    $('passkeyPass').value = '';
    $('passkeyHint').textContent =
      record.mode === 'prf'
        ? `passkey active for '${identity.name}' (PRF-wrapped) - Unlock with passkey replaces typing`
        : `passkey active for '${identity.name}' (session mode: the passphrase rests in this browser session only)`;
    status(`passkey protection enabled for ${identity.name}`, 'ok');
  } catch (e) {
    status(`passkey setup failed: ${e.message}`, 'err');
  }
}

async function passkeyUnlock() {
  try {
    const identity = await pickIdentityForPasskey();
    const stored = await localGet([PASSKEY_PREFIX + identity.name]);
    const record = stored[PASSKEY_PREFIX + identity.name];
    if (!record) throw new Error(`no passkey registered for '${identity.name}' - protect it first`);
    if (!window.datuPasskey) throw new Error('passkey module not loaded');
    status('authenticate with the device passkey…');
    let passphrase;
    if (record.mode === 'presence') {
      await window.datuPasskey.presenceAssertion(record.credentialId);
      const session = await sessionGet([SESSION_PASS]);
      passphrase = (session[SESSION_PASS] || {})[identity.name];
      if (!passphrase) {
        throw new Error('the session cache expired - type the passphrase once and re-protect');
      }
    } else {
      const salt = Uint8Array.from(atob(record.salt), (c) => c.charCodeAt(0));
      const secret = await window.datuPasskey.unlockSecret(record.credentialId, salt);
      if (!secret) throw new Error('this passkey stopped offering PRF - re-protect it');
      passphrase = await window.datuPasskey.unwrapPassphrase(secret, record.iv, record.ct);
    }
    passCache[identity.name] = passphrase;
    notifyState();
    status(`unlocked ${identity.name} with the device passkey (session only)`, 'ok');
  } catch (e) {
    status(`passkey unlock failed: ${e.message} - type the passphrase instead`, 'err');
  }
}

async function passkeyForget() {
  try {
    const identity = await pickIdentityForPasskey();
    await chrome.storage.local.remove(PASSKEY_PREFIX + identity.name);
    const session = await sessionGet([SESSION_PASS]);
    const map = session[SESSION_PASS] || {};
    delete map[identity.name];
    await sessionSet({ [SESSION_PASS]: map });
    $('passkeyHint').textContent = 'passkey forgotten - the passphrase still works';
    status(`passkey protection removed for ${identity.name}`, 'muted');
  } catch (e) {
    status(e.message, 'err');
  }
}

// ---------- idle auto-lock ----------
function clearSensitive() {
  $('pass').value = '';
  $('result').value = '';
  $('copy').disabled = true;
  $('decrypted').style.display = 'none';
  $('decrypted').textContent = '';
  $('opened').style.display = 'none';
  $('opened').textContent = '';
  $('confirmBox').style.display = 'none';
  pendingSign = null;
  pendingLogin = null;
  $('loginConfirm').style.display = 'none';
  $('loginResult').value = '';
  $('loginCopy').disabled = true;
}
function armIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if ($('pass').value || $('result').value || $('decrypted').textContent || $('opened').textContent) {
      clearSensitive();
      status('locked: passphrase and decrypted data cleared after 2 minutes idle', 'muted');
    }
  }, 120000);
}
['pointerdown', 'keydown', 'input'].forEach((event) =>
  document.addEventListener(event, armIdleTimer, { passive: true }),
);

// ---------- dApp sign requests ----------
// The background relays {kind:'datu-rpc'} jobs queued in session storage.
// Requests marked `auto` (session re-login challenges) are answered silently
// when this panel already holds the passphrase for that identity; everything
// else waits for an explicit confirm here.
const REQUESTS_KEY = 'datuRpcQueue';
const passCache = {}; // identity name -> passphrase, panel memory only
const grantCache = {}; // bridge url -> { identity name -> SignetAuth session grant }
// Grants are also mirrored to session storage so the WebAuthn proxy in the
// background can spend one without another prompt (they expire in 15 min).
const persistGrants = () => sessionSet({ datuGrants: grantCache });
const grantFor = (name, url) => {
  const clean = String(url || '').replace(/\/+$/, '');
  if ((grantCache[clean] || {})[name]) return grantCache[clean][name];
  for (const byName of Object.values(grantCache)) {
    if ((byName || {})[name]) return byName[name];
  }
  return '';
};
let requestsFingerprint = '';

function notifyState() {
  try {
    chrome.runtime.sendMessage({ kind: 'datu-state-changed', unlocked: Object.keys(passCache) });
  } catch {}
}

function bridgeCall(url, path, body, token) {
  return call(`${url}${path}`, {
    method: 'POST',
    body,
    auth: true,
    token,
  });
}

async function processRequest(req, passphrase) {
  const payload = req.payload || {};
  const body = { ...(payload.body || {}) };
  const url = (payload.bridgeUrl || '').replace(/\/+$/, '');
  const token = tokens[url];
  const isLogin = payload.path === '/v1/wallet/auth-assert';
  try {
    if (!token) throw new Error('this Signet is not paired - open Settings and connect, or re-pair from the panel');
    if (passphrase) {
      body.passphrase = passphrase;
      passCache[body.name] = passphrase;
      notifyState();
    }
    // A confirmed login request carries the approval gesture; silent auto
    // re-logins do not (the bridge only needs it to register a new site).
    if (isLogin && body.auto !== true) {
      body.approve = true;
      await stepUpIfProtected(body.name);
    }
    // Silent re-logins prefer a session grant: no passphrase round-trip.
    // If the grant expired, retry once with the cached passphrase.
    if (isLogin && !passphrase && grantFor(body.name, url)) {
      body.grant = grantFor(body.name, url);
    }
    try {
      const res = await bridgeCall(url, payload.path || '', body, token);
      if (isLogin && res.grant) {
        grantCache[url] = grantCache[url] || {};
        grantCache[url][body.name] = res.grant;
        await persistGrants();
      }
      chrome.runtime.sendMessage({ kind: 'datu-result', id: req.id, ok: true, result: { status: 200, body: res } });
      return true;
    } catch (e) {
      if (isLogin && body.grant && /grant/.test(e.message) && passCache[body.name]) {
        delete (grantCache[url] || {})[body.name];
        const retry = { ...body };
        delete retry.grant;
        retry.passphrase = passCache[body.name];
        const res = await bridgeCall(url, payload.path || '', retry, token);
        if (res.grant) {
          grantCache[url] = grantCache[url] || {};
          grantCache[url][body.name] = res.grant;
          await persistGrants();
        }
        chrome.runtime.sendMessage({ kind: 'datu-result', id: req.id, ok: true, result: { status: 200, body: res } });
        return true;
      }
      throw e;
    }
  } catch (e) {
    chrome.runtime.sendMessage({ kind: 'datu-result', id: req.id, ok: false, error: e.message });
    throw e;
  }
}

async function pollRequests() {
  try {
    const o = await chrome.storage.session.get(REQUESTS_KEY);
    const queue = o[REQUESTS_KEY] || [];

    // Silent path: auto re-login challenges when the passphrase is cached OR
    // a live session grant exists (passkey unlocks never cache a passphrase).
    const remaining = [];
    for (const req of queue) {
      const body = (req.payload || {}).body || {};
      if (body.auto === true && (passCache[body.name] || grantFor(body.name, (req.payload || {}).bridgeUrl))) {
        try {
          await processRequest(req, passCache[body.name]);
          continue;
        } catch (e) {
          status(`auto sign failed for ${body.name}: ${e.message}`, 'err');
          continue;
        }
      }
      remaining.push(req);
    }

    const card = $('requestsCard');
    if (!remaining.length) {
      card.style.display = 'none';
      requestsFingerprint = '';
      return;
    }
    card.style.display = 'block';
    const fingerprint = remaining.map((r) => r.id).join(',');
    if (fingerprint === requestsFingerprint) return;
    const holder = $('requests');
    holder.innerHTML = '';
    for (const req of remaining) holder.appendChild(renderRequest(req));
    requestsFingerprint = fingerprint; // only mark rendered once every box is on screen
  } catch {}
}

function renderRequest(req) {
  const payload = req.payload || {};
  const path = payload.path || '';
  const body = payload.body || {};
  const url = (payload.bridgeUrl || '').replace(/\/+$/, '');

  const box = document.createElement('div');
  box.style.borderTop = '1px solid #30363d';
  box.style.padding = '.45rem 0';

  const head = document.createElement('div');
  const isLogin = path === '/v1/wallet/auth-assert';
  head.innerHTML = `<b>${esc(payload.summary || (isLogin ? `sign in to ${body.rp_id || 'a site'}` : path || req.action))}</b>
    <div class="muted small">${esc(url)}${esc(path)} · identity ${esc(body.name || '?')} · ${new Date(req.at).toLocaleTimeString()}</div>`;
  box.appendChild(head);

  if (isLogin) {
    const detail = document.createElement('div');
    detail.className = 'muted small';
    detail.style.margin = '.3rem 0';
    detail.innerHTML = [
      `site <b>${esc(body.rp_id || '?')}</b> · origin <b>${esc(body.origin || '?')}</b>`,
      `<br/>challenge expires ${body.expires_at_ms ? esc(new Date(body.expires_at_ms).toISOString()) : '?'} · datu-auth-v1, never a ledger entry`,
    ].join('');
    box.insertBefore(detail, head.nextSibling);
  }

  const pass = document.createElement('input');
  pass.type = 'password';
  pass.placeholder = passCache[body.name] ? 'passphrase remembered for this session' : 'vault passphrase';
  pass.value = passCache[body.name] || '';
  pass.style.marginTop = '.3rem';
  box.appendChild(pass);

  const row = document.createElement('div');
  row.className = 'row';
  const confirm = document.createElement('button');
  confirm.className = 'primary';
  confirm.textContent = isLogin ? 'Approve sign-in' : 'Confirm & sign';
  const reject = document.createElement('button');
  reject.className = 'ghost';
  reject.textContent = 'Reject';
  row.append(confirm, reject);
  box.appendChild(row);

  confirm.addEventListener('click', async () => {
    confirm.disabled = true;
    try {
      await processRequest(req, pass.value || passCache[body.name]);
      status('sign request completed', 'ok');
    } catch (e) {
      status(e.message, 'err');
      confirm.disabled = false;
    }
  });
  reject.addEventListener('click', () => {
    chrome.runtime.sendMessage({ kind: 'datu-result', id: req.id, ok: false, error: 'rejected in the Signet' });
  });

  return box;
}

setInterval(pollRequests, 1200);
pollRequests();

// ---------- wiring ----------
$('addWallet').addEventListener('click', addWallet);
$('findWallet').addEventListener('click', () => connectSignet());
$('connRetry').addEventListener('click', () => connectSignet());
$('switchWallet').addEventListener('click', switchWallet);
$('removeWallet').addEventListener('click', removeWallet);
$('forget').addEventListener('click', forgetToken);
$('identity').addEventListener('change', showSeal);
$('find').addEventListener('click', findMyRecords);
$('check').addEventListener('click', () => checkNode());
$('sign').addEventListener('click', reviewConsent);
$('loginReview').addEventListener('click', reviewLogin);
$('loginSign').addEventListener('click', confirmLogin);
$('loginCancel').addEventListener('click', cancelLogin);
$('loginCopy').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('loginResult').value);
  status('login assertion copied - paste it into the site login form', 'ok');
});
$('confirmSign').addEventListener('click', confirmSign);
$('cancelSign').addEventListener('click', cancelSign);
$('open').addEventListener('click', openPasted);
$('create').addEventListener('click', createIdentity);
$('exportIdentity').addEventListener('click', exportIdentity);
$('importIdentity').addEventListener('click', importIdentity);
$('copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('result').value);
  status('signed consent copied - paste it back into the registry dApp', 'ok');
});
$('passkeyStepUp').addEventListener('change', async () => {
  await localSet({ [STEPUP_KEY]: $('passkeyStepUp').checked });
  status(
    $('passkeyStepUp').checked
      ? 'every sign-in will ask for the device passkey'
      : 'sign-ins use the session unlock until it expires',
    'muted',
  );
});
$('passkeyEnable').addEventListener('click', passkeyEnable);
$('passkeyUnlock').addEventListener('click', passkeyUnlock);
$('passkeyForget').addEventListener('click', passkeyForget);
$('node').addEventListener('change', () => {
  localSet({ node: nodeUrl() });
  checkNode();
});

// ---------- boot ----------
const stepUpEl = $('passkeyStepUp');
if (stepUpEl) {
  localGet([STEPUP_KEY]).then((v) => {
    stepUpEl.checked = v[STEPUP_KEY] !== false;
  });
}
const versionEl = $('extVersion');
if (versionEl && chrome.runtime?.getManifest) {
  versionEl.textContent = `v${chrome.runtime.getManifest().version}`;
}

(async () => {
  const local = await localGet(['wallets', 'node']);
  if (local.node) $('node').value = local.node;
  wallets = Array.isArray(local.wallets) && local.wallets.length ? local.wallets : [DEFAULT_WALLET];
  const session = await sessionGet(['activeWallet', 'tokens', 'datuGrants']);
  tokens = session.tokens || {};
  Object.assign(grantCache, session.datuGrants || {});
  activeUrl = session.activeWallet || wallets[0].url;
  renderWallets();

  if (tokens[activeUrl]) {
    try {
      await pairWallet(activeUrl, tokens[activeUrl]);
    } catch {
      // token went stale or the bridge was down - drop it and try a fresh auto-pair
      delete tokens[activeUrl];
      await sessionSet({ tokens });
    }
  }
  if (identities.length) {
    setConnState('connected');
  } else if (await connectSignet({ quiet: true })) {
    // paired itself - nothing for the user to do
  } else {
    setConnState('not-found');
    document.querySelector('nav button[data-tab="settings"]').click();
  }
  armConnectionWatchdog();
  armIdleTimer();
})();
