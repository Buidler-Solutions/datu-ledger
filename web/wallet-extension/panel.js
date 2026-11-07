const $ = (id) => document.getElementById(id);
let identities = [];
let myRecords = [];
let pendingSign = null; // { document, role, kind }
let idleTimer = null;

// Wallets = one datu wallet bridge each (own directory, passphrases, token).
let wallets = []; // [{ label, url }]
let activeUrl = '';
let tokens = {}; // bridge url -> pairing token (session only)

const DEFAULT_WALLET = { label: 'default', url: 'http://127.0.0.1:7482' };

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
      if (!bearer) throw new Error('not paired with this wallet - paste its token in Settings');
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
    if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
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
    $('brandSub').textContent = 'no wallet paired';
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
  $('pairHint').textContent = `paired · ${identities.length} identities · token kept for this browser session`;
  status(`wallet ready - ${identities.length} identities`, 'ok');
  checkNode(true);
}

async function addWallet() {
  try {
    const label = $('walletLabel').value.trim() || 'wallet';
    const url = $('walletUrl').value.trim().replace(/\/+$/, '');
    const token = $('token').value.trim();
    if (!url) throw new Error('enter the bridge URL');
    if (!token) throw new Error('paste the pairing token from wallet/bridge.token');
    await pairWallet(url, token, label);
    $('token').value = '';
  } catch (e) {
    status(e.message, 'err');
  }
}

async function switchWallet() {
  try {
    const url = $('walletSelect').value;
    if (!url) throw new Error('no wallet to switch to');
    activeUrl = url;
    const wallet = wallets.find((w) => w.url === url);
    $('walletLabel').value = wallet ? wallet.label : '';
    $('walletUrl').value = url;
    if (!tokens[url]) {
      await persistWallets();
      $('pairHint').textContent = 'this wallet needs its token - paste it and press “Save wallet & pair”';
      status(`switched to ${url} - paste its pairing token`, 'muted');
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
    status('wallet removed', 'muted');
  }
}

async function forgetToken() {
  delete tokens[bridgeUrl()];
  identities = [];
  $('identity').innerHTML = '';
  $('token').value = '';
  await sessionSet({ tokens });
  $('pairHint').textContent = 'token forgotten for this wallet - pair again to use it';
  status('pairing token forgotten', 'muted');
}

// ---------- identity ----------
function selected() {
  const identity = identities.find((i) => i.name === $('identity').value);
  if (!identity) throw new Error('select an identity first');
  return identity;
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
async function checkNode(quiet = false) {
  try {
    const st = await nodeGet('/v1/status');
    const mode = st.policy?.mode ?? '?';
    $('modeText').textContent = `${mode} · ${st.entries}`;
    $('modeDot').className = `dot ${mode === 'open-observer' ? 'green' : 'blue'}`;
    if (!quiet) status(`node ok - ${mode}, ${st.entries} entries, ${st.checkpoints} witnesses`, 'ok');
  } catch (e) {
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
      myRecords.push({
        id: item.id,
        seq: item.seq,
        namespace: item.namespace,
        kind: payload?.kind ?? '(unsigned document)',
        label: recordLabel(payload, item.id),
        entry: full,
        payload,
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
      actions.append(verify, open);
      card.append(head, ns, actions);
      $('records').append(card);
    });
    status(`${myRecords.length} record(s) concern you${pattern ? ` in ${pattern}` : ' (any namespace)'} - verified locally`, 'ok');
  } catch (e) {
    status(e.message, 'err');
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

async function decryptRecord(index) {
  try {
    const identity = selected();
    const rec = myRecords[index];
    if (!$('pass').value) throw new Error('enter your wallet passphrase (Sign tab)');
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

// ---------- consent (review, then confirm) ----------
function reviewConsent() {
  try {
    const identity = selected();
    const document = JSON.parse($('doc').value);
    if (!$('pass').value) throw new Error('enter your wallet passphrase');
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
    status('unlocking wallet and signing…');
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
    if (!passphrase) throw new Error('enter your wallet passphrase');
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

// ---------- wiring ----------
$('addWallet').addEventListener('click', addWallet);
$('switchWallet').addEventListener('click', switchWallet);
$('removeWallet').addEventListener('click', removeWallet);
$('forget').addEventListener('click', forgetToken);
$('identity').addEventListener('change', showSeal);
$('find').addEventListener('click', findMyRecords);
$('check').addEventListener('click', () => checkNode());
$('sign').addEventListener('click', reviewConsent);
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
$('node').addEventListener('change', () => {
  localSet({ node: nodeUrl() });
  checkNode();
});

// ---------- boot ----------
(async () => {
  const local = await localGet(['wallets', 'node']);
  if (local.node) $('node').value = local.node;
  wallets = Array.isArray(local.wallets) && local.wallets.length ? local.wallets : [DEFAULT_WALLET];
  const session = await sessionGet(['activeWallet', 'tokens']);
  tokens = session.tokens || {};
  activeUrl = session.activeWallet || wallets[0].url;
  renderWallets();

  if (tokens[activeUrl]) {
    try {
      await pairWallet(activeUrl, tokens[activeUrl]);
    } catch (e) {
      status(e.message, 'err');
    }
  } else {
    status('pair a wallet - paste its bridge token in Settings', 'muted');
    document.querySelector('nav button[data-tab="settings"]').click();
  }
  armIdleTimer();
})();
