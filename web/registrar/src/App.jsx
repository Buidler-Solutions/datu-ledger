import React, { useCallback, useEffect, useState } from 'react';
import { listIdentities, nodeGet, nodePost, getToken, setToken } from './api.js';
import { walletPing, walletSign } from './wallet.js';

const NS = 'gov.titles.application';
const KIND = 'land.title.application';
const CLAIM_KIND = 'land.ownership.registration';

const defaultName = (page) =>
  page === 'register'
    ? 'amina'
    : page === 'registrar'
      ? 'registrar'
      : page === 'landowner'
        ? 'amina'
        : 'registry-signer';

function useHashPage() {
  const read = () => window.location.hash.replace(/^#\/?/, '') || 'register';
  const [page, setPage] = useState(read);
  useEffect(() => {
    const on = () => setPage(read());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const go = (p) => {
    window.location.hash = `#/${p}`;
  };
  return [page, go];
}

function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

function downloadJson(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function FileLoader({ label, onText }) {
  return (
    <label>
      {label}
      <input
        type="file"
        accept="application/json,.json"
        onChange={(e) => {
          const file = e.target.files && e.target.files[0];
          if (!file) return;
          const reader = new FileReader();
          reader.onload = () => onText(String(reader.result || ''));
          reader.readAsText(file);
        }}
      />
    </label>
  );
}

function parseEnvelope(text) {
  const doc = JSON.parse(text);
  if (!doc || !Array.isArray(doc.parties) || !doc.doc) {
    throw new Error('not a signed envelope (expected { doc, parties[] })');
  }
  return doc;
}

const partyOf = (doc, role) => (doc.parties || []).find((p) => p.role === role);

function WalletLogin({ page, bridgeUrl, nodeUrl, session, onLogin, onLogout, say }) {
  const [name, setName] = useState(defaultName(page));
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setName(defaultName(page));
  }, [page]);

  if (session) {
    return (
      <div className="card login">
        <p className="ok small">
          Signed in through the wallet as <b>{session.name}</b> · {session.ed.slice(0, 16)}…
        </p>
        <p className="muted small">
          challenge {session.challenge.nonce.slice(0, 12)}… signed {session.at} at the wallet ·
          signature {session.sig.slice(0, 24)}…
        </p>
        <button className="ghost" onClick={onLogout}>
          Log out
        </button>
      </div>
    );
  }

  async function login() {
    setBusy(true);
    try {
      if (!(await walletPing())) {
        throw new Error(
          'wallet extension not detected - load it from chrome://extensions and reload this page'
        );
      }
      const challenge = { page, node: nodeUrl, nonce: randomHex(16), ts: Date.now() };
      const res = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/party-sign',
        summary: `Login - page "${page}" signs a one-time challenge as ${name.trim()}`,
        body: {
          name: name.trim(),
          role: 'login',
          kind: 'datu.login',
          document: challenge,
        },
      });
      const party = ((res.body || {}).parties || []).find((p) => p.role === 'login');
      if (!party) throw new Error('wallet returned no login signature');
      onLogin({
        name: name.trim(),
        ed: party.key,
        sig: party.signature || '',
        at: new Date().toLocaleTimeString(),
        challenge,
      });
      say(`${page} logged in via the wallet as ${name.trim()} (${party.key.slice(0, 16)}…)`, 'ok');
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card login">
      <h2>Login through the wallet</h2>
      <p className="muted small">
        No passphrase here - the wallet signs a one-time challenge and asks you to confirm it in the
        side panel. The dApp only receives the signed challenge.
      </p>
      <div className="row">
        <label>
          Identity on the bridge
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <button onClick={login} disabled={busy} style={{ marginTop: '1.4rem' }}>
          {busy ? 'signing challenge…' : 'Login with wallet'}
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [page, go] = useHashPage();

  const [nodeUrl, setNodeUrl] = useState('http://127.0.0.1:7474');
  const [bridgeUrl, setBridgeUrl] = useState('http://127.0.0.1:7482');
  const [identities, setIdentities] = useState([]);
  const [nodeStatus, setNodeStatus] = useState(null);
  const [log, setLog] = useState([]);
  const [busy, setBusy] = useState(false);

  const [sessions, setSessions] = useState({});

  const [claimForm, setClaimForm] = useState({ parcel: 'TIT-0101-25', district: 'Westfield' });
  const [claim, setClaim] = useState(null);

  const [claimIn, setClaimIn] = useState('');
  const [form, setForm] = useState({
    parcel: '',
    district: '',
    holder_name: '',
    birth_date: '',
    holder_key: '',
    holder_seal: '',
  });
  const [registrarEnvelope, setRegistrarEnvelope] = useState(null);

  const [holderIn, setHolderIn] = useState('');
  const [holderEnvelope, setHolderEnvelope] = useState(null);

  const [registryIn, setRegistryIn] = useState('');
  const [readyDoc, setReadyDoc] = useState(null);
  const [result, setResult] = useState(null);

  const say = (msg, kind = 'info') =>
    setLog((l) => [...l, { msg, kind, at: new Date().toLocaleTimeString() }]);

  const refresh = useCallback(async () => {
    try {
      const ids = await listIdentities(bridgeUrl);
      setIdentities(ids);
      const { body } = await nodeGet(nodeUrl, '/v1/status');
      setNodeStatus(body);
      say(`bridge: ${ids.length} identities · node mode: ${body?.policy?.mode ?? '?'}`);
    } catch (e) {
      say(`cannot reach services: ${e.message}`, 'err');
    }
  }, [bridgeUrl, nodeUrl]);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function onLogin(p, session) {
    setSessions((s) => ({ ...s, [p]: session }));
  }
  function onLogout(p) {
    setSessions((s) => {
      const next = { ...s };
      delete next[p];
      return next;
    });
    say(`${p} logged out`);
  }

  // ---- 0 · landowner registers the ownership claim ----
  async function registerOwnership() {
    const session = sessions.register;
    if (!session) return say('login through the wallet first', 'err');
    setBusy(true);
    try {
      const me = identities.find((i) => i.name === session.name);
      if (!me) throw new Error(`identity '${session.name}' vanished from the bridge`);
      const document = {
        parcel: claimForm.parcel,
        district: claimForm.district,
        claimant_key: session.ed,
        claimant_seal: me.seal_public,
        registered_at: new Date().toISOString(),
      };
      const res = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/party-sign',
        summary: `Register land ownership - ${claimForm.parcel} (${claimForm.district}) signed by ${session.name}`,
        body: { name: session.name, role: 'claimant', kind: CLAIM_KIND, document },
      });
      setClaim(res.body);
      say('ownership claim signed by the landowner - hand it to the registrar');
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- 1 · registrar receives the claim, prepares and signs ----
  function loadClaim() {
    try {
      const doc = parseEnvelope(claimIn);
      const claimant = partyOf(doc, 'claimant');
      if (!claimant) throw new Error('this file has no claimant signature');
      if (doc.doc?.claimant_key && claimant.key !== doc.doc.claimant_key) {
        throw new Error('claimant signature does not match claimant_key');
      }
      setForm((f) => ({
        ...f,
        parcel: doc.doc.parcel || '',
        district: doc.doc.district || '',
        holder_key: doc.doc.claimant_key || '',
        holder_seal: doc.doc.claimant_seal || '',
      }));
      setClaim(doc);
      say(`claim verified: ${doc.doc.parcel} · claimant ${claimant.key.slice(0, 16)}…`);
    } catch (e) {
      say(`claim not accepted: ${e.message}`, 'err');
    }
  }

  async function signAsRegistrar() {
    const session = sessions.registrar;
    if (!session) return say('login through the wallet first', 'err');
    setBusy(true);
    setResult(null);
    try {
      if (!form.holder_key || !form.holder_seal) {
        throw new Error('holder key and holder seal key are required (load the claim first)');
      }
      const me = identities.find((i) => i.name === session.name);
      if (!me) throw new Error(`identity '${session.name}' vanished from the bridge`);
      const document = {
        parcel: form.parcel,
        district: form.district,
        holder_key: form.holder_key.trim(),
        holder_seal: form.holder_seal.trim(),
        holder_name: form.holder_name,
        birth_date: form.birth_date,
        claim: claim
          ? {
              kind: claim.kind,
              claimant: claim.parties.find((p) => p.role === 'claimant')?.key,
              signature: claim.parties.find((p) => p.role === 'claimant')?.signature,
              registered_at: claim.doc.registered_at,
            }
          : undefined,
      };
      say('sealing personal fields to registry + holder…');
      const sealed = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/seal',
        summary: `Seal holder_name + birth_date for ${form.parcel} (readers: registrar + holder)`,
        body: {
          name: session.name,
          document,
          fields: ['holder_name', 'birth_date'],
          to: [me.seal_public],
          to_fields: ['holder_seal'],
        },
      });
      say(`${sealed.body.sealed} field(s) sealed to ${sealed.body.readers} readers`);

      const signed = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/party-sign',
        summary: `Registrar certification - ${form.parcel} signed as registrar by ${session.name}`,
        body: {
          name: session.name,
          role: 'registrar',
          kind: KIND,
          document: sealed.body.document,
        },
      });
      say('registrar signature added - envelope ready for the landowner');
      setRegistrarEnvelope(signed.body);
      setHolderEnvelope(null);
      setReadyDoc(null);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- 2 · landowner consents ----
  async function signAsHolder() {
    const session = sessions.landowner;
    if (!session) return say('login through the wallet first', 'err');
    setBusy(true);
    try {
      const doc = parseEnvelope(holderIn);
      if (!partyOf(doc, 'registrar')) throw new Error('this envelope has no registrar signature');
      if (doc.doc?.holder_key && session.ed !== doc.doc.holder_key) {
        throw new Error(
          `this envelope names holder ${doc.doc.holder_key.slice(0, 16)}… but you are ${session.ed.slice(0, 16)}…`
        );
      }
      const res = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/party-sign',
        summary: `Holder consent - ${doc.doc.parcel} signed as holder by ${session.name}`,
        body: { name: session.name, role: 'holder', kind: KIND, document: doc },
      });
      say('holder consent added - envelope ready for the registry-signer');
      setHolderEnvelope(res.body);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- 3 · registry-signer records ----
  function checkForRecording() {
    try {
      const doc = parseEnvelope(registryIn);
      const holder = partyOf(doc, 'holder');
      if (!holder) throw new Error('the envelope has no holder consent yet');
      if (doc.doc?.holder_key && holder.key !== doc.doc.holder_key) {
        throw new Error('holder signature is not from the key named in holder_key');
      }
      if (!partyOf(doc, 'registrar')) throw new Error('the envelope has no registrar signature');
      setReadyDoc(doc);
      say(`envelope verified locally: registrar + holder (${holder.key.slice(0, 16)}…)`);
    } catch (e) {
      say(`envelope not accepted: ${e.message}`, 'err');
    }
  }

  async function recordToLedger() {
    const session = sessions.registry;
    if (!session) return say('login through the wallet first', 'err');
    setBusy(true);
    setResult(null);
    try {
      if (!readyDoc) throw new Error('no verified envelope - check it first');
      const feed = await nodeGet(nodeUrl, `/v1/feed/${session.ed}`);
      if (feed.status !== 200) throw new Error(feed.body.error || 'cannot read feed');
      const next = feed.body.next || { seq: 0, prev: null };
      say(`authoring entry seq ${next.seq} as ${session.ed.slice(0, 16)}…`);

      const signed = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/sign-entry',
        summary: `Record title ${readyDoc.doc?.parcel} into ${NS} as ${session.name} (seq ${next.seq})`,
        body: {
          name: session.name,
          request: {
            namespace: NS,
            seq: next.seq,
            prev: next.prev,
            payload_json: readyDoc,
          },
        },
      });
      if (!signed.body || !signed.body.entry) throw new Error('wallet returned no signed entry');
      say(`entry ${signed.body.id.slice(0, 16)}… signed`);

      const submit = await nodePost(nodeUrl, '/v1/entries', signed.body.entry);
      if (submit.status !== 201 && submit.status !== 200) {
        throw new Error(
          `node ${submit.status}: ${submit.body.denied || submit.body.rejected || submit.body.error}`
        );
      }
      say(submit.status === 201 ? 'accepted into the ledger' : 'already present (idempotent)');
      const entry = await nodeGet(nodeUrl, `/v1/entry/${signed.body.id}`);
      setResult({ id: signed.body.id, status: submit.status, entry: entry.body });
      const st = await nodeGet(nodeUrl, '/v1/status');
      setNodeStatus(st.body);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  const pages = [
    ['register', '0 · Landowner registers'],
    ['registrar', '1 · Registrar'],
    ['landowner', '2 · Landowner signs'],
    ['registry', '3 · Registry records'],
  ];

  return (
    <div className="page">
      <header>
        <h1>DATU · Land Registry</h1>
        <p className="muted">
          Ownership registration → registrar certification → landowner consent → ledger record. The
          envelope travels by file; every signature is confirmed in the browser wallet extension.
        </p>
      </header>

      <nav className="navtabs">
        {pages.map(([key, label]) => (
          <button key={key} className={page === key ? 'tab active' : 'tab'} onClick={() => go(key)}>
            {label}
          </button>
        ))}
      </nav>

      <section className="card">
        <h2>Services (node + wallet bridge)</h2>
        <div className="row">
          <label>
            Registry node
            <input value={nodeUrl} onChange={(e) => setNodeUrl(e.target.value)} />
          </label>
          <label>
            Wallet bridge
            <input value={bridgeUrl} onChange={(e) => setBridgeUrl(e.target.value)} />
          </label>
        </div>
        <div className="row">
          <label>
            Bridge pairing token (read-only bridge calls: identities, feed)
            <input
              type="password"
              defaultValue={getToken()}
              onChange={(e) => setToken(e.target.value)}
              placeholder="64 hex characters"
            />
          </label>
          <button className="ghost" onClick={refresh} disabled={busy}>
            Refresh
          </button>
        </div>
        {nodeStatus && (
          <p className="muted small">
            mode <b>{nodeStatus.policy?.mode}</b> · entries {nodeStatus.entries} · witnesses{' '}
            {nodeStatus.checkpoints} · identities on this bridge: {identities.length}
          </p>
        )}
      </section>

      <WalletLogin
        key={page}
        page={page}
        bridgeUrl={bridgeUrl}
        nodeUrl={nodeUrl}
        session={sessions[page]}
        onLogin={(s) => onLogin(page, s)}
        onLogout={() => onLogout(page)}
        say={say}
      />

      {page === 'register' && sessions.register && (
        <section className="grid">
          <div className="card">
            <h2>Register your land ownership</h2>
            <label>
              Parcel
              <input
                value={claimForm.parcel}
                onChange={(e) => setClaimForm({ ...claimForm, parcel: e.target.value })}
              />
            </label>
            <label>
              District
              <input
                value={claimForm.district}
                onChange={(e) => setClaimForm({ ...claimForm, district: e.target.value })}
              />
            </label>
            <button onClick={registerOwnership} disabled={busy}>
              Sign ownership claim with the wallet
            </button>
          </div>

          <div className="card">
            <h2>Claim → registrar</h2>
            {!claim && <p className="muted small">- sign to produce the ownership claim -</p>}
            {claim && (
              <>
                <p className="ok small">claimant signed · {claim.doc.parcel}</p>
                <button onClick={() => downloadJson(`${claim.doc.parcel}-0-claim.json`, claim)}>
                  Download claim for the registrar
                </button>
                <details>
                  <summary>claim preview</summary>
                  <pre>{JSON.stringify(claim, null, 2)}</pre>
                </details>
              </>
            )}
          </div>
        </section>
      )}

      {page === 'registrar' && sessions.registrar && (
        <section className="grid">
          <div className="card">
            <h2>Process the ownership claim</h2>
            <FileLoader label="Load the claim file from the landowner" onText={setClaimIn} />
            <label>
              …or paste it
              <textarea
                rows={5}
                value={claimIn}
                onChange={(e) => setClaimIn(e.target.value)}
                placeholder="claim JSON"
              />
            </label>
            <button className="ghost" onClick={loadClaim} disabled={!claimIn}>
              Verify claim &amp; prefill
            </button>
            {claim && <p className="ok small">claim verified - form prefilled</p>}
          </div>

          <div className="card">
            <h2>Certify the title</h2>
            <label>
              Parcel
              <input value={form.parcel} onChange={(e) => setForm({ ...form, parcel: e.target.value })} />
            </label>
            <label>
              District
              <input value={form.district} onChange={(e) => setForm({ ...form, district: e.target.value })} />
            </label>
            <label>
              Holder name <em className="tag">encrypted</em>
              <input
                value={form.holder_name}
                onChange={(e) => setForm({ ...form, holder_name: e.target.value })}
                placeholder="Amina Yusuf"
              />
            </label>
            <label>
              Birth date <em className="tag">encrypted</em>
              <input
                value={form.birth_date}
                onChange={(e) => setForm({ ...form, birth_date: e.target.value })}
                placeholder="1990-04-12"
              />
            </label>
            <label>
              Holder Ed25519 key <em className="tag pub">from the claim</em>
              <input value={form.holder_key} onChange={(e) => setForm({ ...form, holder_key: e.target.value })} />
            </label>
            <label>
              Holder seal key (X25519) <em className="tag pub">from the claim</em>
              <input value={form.holder_seal} onChange={(e) => setForm({ ...form, holder_seal: e.target.value })} />
            </label>
            <button onClick={signAsRegistrar} disabled={busy}>
              Seal fields &amp; sign as registrar
            </button>
            {registrarEnvelope && (
              <>
                <p className="ok small">
                  registrar signed · parties:{' '}
                  {registrarEnvelope.parties.map((p) => p.role).join(', ')}
                </p>
                <button
                  onClick={() => downloadJson(`${form.parcel || 'title'}-1-registrar.json`, registrarEnvelope)}
                >
                  Download envelope for the landowner
                </button>
              </>
            )}
          </div>
        </section>
      )}

      {page === 'landowner' && (
        <section className="grid">
          <div className="card">
            <h2>Receive the envelope</h2>
            <FileLoader label="Load the envelope file from the registrar" onText={setHolderIn} />
            <label>
              …or paste it
              <textarea
                rows={6}
                value={holderIn}
                onChange={(e) => setHolderIn(e.target.value)}
                placeholder="envelope JSON"
              />
            </label>
            {holderIn && (
              <p className="muted small">
                {(() => {
                  try {
                    const doc = parseEnvelope(holderIn);
                    return `parcel ${doc.doc?.parcel ?? '?'} · signatures: ${(doc.parties || [])
                      .map((p) => p.role)
                      .join(', ')}`;
                  } catch (e) {
                    return `unreadable: ${e.message}`;
                  }
                })()}
              </p>
            )}
          </div>

          <div className="card">
            <h2>Consent as holder</h2>
            <button onClick={signAsHolder} disabled={busy || !holderIn || !sessions.landowner}>
              Sign consent with the wallet
            </button>
            {holderEnvelope && (
              <>
                <p className="ok small">
                  holder consented · parties: {holderEnvelope.parties.map((p) => p.role).join(', ')}
                </p>
                <button
                  onClick={() =>
                    downloadJson(`${holderEnvelope.doc?.parcel || 'title'}-2-consented.json`, holderEnvelope)
                  }
                >
                  Download consented envelope for the registry
                </button>
              </>
            )}
          </div>
        </section>
      )}

      {page === 'registry' && (
        <section className="grid">
          <div className="card">
            <h2>Receive the consented envelope</h2>
            <FileLoader label="Load the envelope file from the landowner" onText={setRegistryIn} />
            <label>
              …or paste it
              <textarea
                rows={6}
                value={registryIn}
                onChange={(e) => setRegistryIn(e.target.value)}
                placeholder="envelope JSON"
              />
            </label>
            <button className="ghost" onClick={checkForRecording} disabled={!registryIn}>
              Verify registrar + holder
            </button>
            {readyDoc && <p className="ok small">verified - ready to record</p>}
          </div>

          <div className="card">
            <h2>Record to the ledger</h2>
            <button onClick={recordToLedger} disabled={busy || !readyDoc || !sessions.registry}>
              Sign entry with the wallet &amp; POST to node
            </button>
            {result && (
              <div className={`result ${result.status === 201 ? 'okbox' : 'dupbox'}`}>
                <p>
                  {result.status === 201 ? 'Accepted' : 'Already present'} · entry{' '}
                  <code>{result.id}</code>
                </p>
                <details>
                  <summary>stored entry (ciphertext fields visible)</summary>
                  <pre>{JSON.stringify(result.entry, null, 2)}</pre>
                </details>
              </div>
            )}
          </div>
        </section>
      )}

      <section className="card logs">
        <h2>Activity</h2>
        <ul>
          {log.map((l, i) => (
            <li key={i} className={l.kind === 'err' ? 'err' : ''}>
              <span className="muted">{l.at}</span> {l.msg}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
