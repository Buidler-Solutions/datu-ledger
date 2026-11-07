import React, { useCallback, useEffect, useState } from 'react';
import { listIdentities, nodeGet, nodePost, bridgePost, getToken, setToken } from './api.js';

const NS = 'gov.titles.application';
const KIND = 'land.title.application';

const emptyForm = {
  parcel: 'TIT-0101-23',
  district: 'Westfield',
  holder_name: '',
  birth_date: '',
  holder_key: '',
  holder_seal: '',
};

const defaultName = (page) =>
  page === 'registrar' ? 'registrar' : page === 'landowner' ? 'amina' : 'registry-signer';

function useHashPage() {
  const read = () => window.location.hash.replace(/^#\/?/, '') || 'registrar';
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

function WalletLogin({ page, bridgeUrl, nodeUrl, session, onLogin, onLogout }) {
  const [name, setName] = useState(defaultName(page));
  const [pass, setPass] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setName(defaultName(page));
    setPass('');
    setErr('');
  }, [page]);

  if (session) {
    return (
      <div className="card login">
        <p className="ok small">
          Signed in through the wallet as <b>{session.name}</b> · {session.ed.slice(0, 16)}…
        </p>
        <p className="muted small">
          challenge {session.challenge.nonce.slice(0, 12)}… signed {session.at} · signature{' '}
          {session.sig.slice(0, 24)}…
        </p>
        <button className="ghost" onClick={onLogout}>
          Log out
        </button>
      </div>
    );
  }

  async function login() {
    setBusy(true);
    setErr('');
    try {
      if (!name.trim()) throw new Error('identity name is required');
      if (!pass) throw new Error('the wallet passphrase is required');
      const challenge = {
        page,
        node: nodeUrl,
        nonce: randomHex(16),
        ts: Date.now(),
      };
      const res = await bridgePost(bridgeUrl, '/v1/wallet/party-sign', {
        name: name.trim(),
        passphrase: pass,
        role: 'login',
        kind: 'datu.login',
        document: challenge,
      });
      if (res.status !== 200) throw new Error(res.body.error || 'wallet refused the challenge');
      const party = ((res.body.document || {}).parties || []).find((p) => p.role === 'login');
      if (!party) throw new Error('wallet returned no login signature');
      onLogin({
        name: name.trim(),
        pass,
        ed: party.key,
        sig: party.signature || '',
        at: new Date().toLocaleTimeString(),
        challenge,
      });
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card login">
      <h2>Login through the wallet</h2>
      <p className="muted small">
        The wallet signs a one-time challenge - only the right passphrase produces it. The dApp never
        sees your keys.
      </p>
      <div className="row">
        <label>
          Identity on the bridge
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Passphrase
          <input
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && login()}
          />
        </label>
      </div>
      <button onClick={login} disabled={busy}>
        {busy ? 'signing challenge…' : 'Login with wallet'}
      </button>
      {err && <p className="err small">{err}</p>}
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

  const [form, setForm] = useState(emptyForm);
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

  const setField = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  function onLogin(p, session) {
    setSessions((s) => ({ ...s, [p]: session }));
    say(`${p} logged in via wallet as ${session.name} (${session.ed.slice(0, 16)}…)`, 'ok');
  }
  function onLogout(p) {
    setSessions((s) => {
      const next = { ...s };
      delete next[p];
      return next;
    });
    say(`${p} logged out`);
  }

  // ---- registrar: prepare, seal, sign, hand over ----
  async function signAsRegistrar() {
    const session = sessions.registrar;
    if (!session) return say('login through the wallet first', 'err');
    setBusy(true);
    setResult(null);
    try {
      if (!form.holder_key || !form.holder_seal) {
        throw new Error('holder key and holder seal key are required');
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
      };
      say('sealing personal fields to registry + holder…');
      const sealed = await bridgePost(bridgeUrl, '/v1/wallet/seal', {
        name: session.name,
        passphrase: session.pass,
        document,
        fields: ['holder_name', 'birth_date'],
        to: [me.seal_public],
        to_fields: ['holder_seal'],
      });
      if (sealed.status !== 200) throw new Error(sealed.body.error || 'seal failed');
      say(`${sealed.body.sealed} field(s) sealed to ${sealed.body.readers} readers`);

      const signed = await bridgePost(bridgeUrl, '/v1/wallet/party-sign', {
        name: session.name,
        passphrase: session.pass,
        role: 'registrar',
        kind: KIND,
        document: sealed.body.document,
      });
      if (signed.status !== 200) throw new Error(signed.body.error || 'party sign failed');
      say('registrar signature added (Ed25519 + ML-DSA-65) - envelope ready for the landowner');
      setRegistrarEnvelope(signed.body.document);
      setHolderEnvelope(null);
      setReadyDoc(null);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- landowner: review, consent-sign, hand over ----
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
      say('signing consent as holder…');
      const signed = await bridgePost(bridgeUrl, '/v1/wallet/party-sign', {
        name: session.name,
        passphrase: session.pass,
        role: 'holder',
        kind: KIND,
        document: doc,
      });
      if (signed.status !== 200) throw new Error(signed.body.error || 'consent signing failed');
      say('holder consent added - envelope ready for the registry-signer');
      setHolderEnvelope(signed.body.document);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- registry: verify, author, record ----
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

      const signed = await bridgePost(bridgeUrl, '/v1/wallet/sign-entry', {
        name: session.name,
        passphrase: session.pass,
        request: {
          namespace: NS,
          seq: next.seq,
          prev: next.prev,
          payload_json: readyDoc,
        },
      });
      if (signed.status !== 200) throw new Error(signed.body.error || 'entry signing failed');
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
    ['registrar', '1 · Registrar'],
    ['landowner', '2 · Landowner'],
    ['registry', '3 · Registry'],
  ];

  return (
    <div className="page">
      <header>
        <h1>DATU · Land Registry</h1>
        <p className="muted">
          Title application - one page per party. The envelope travels by file: registrar → landowner
          → registry. Each party logs in through their wallet and signs with it.
        </p>
      </header>

      <nav className="navtabs">
        {pages.map(([key, label]) => (
          <button
            key={key}
            className={page === key ? 'tab active' : 'tab'}
            onClick={() => go(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      <section className="card">
        <h2>Services (this party's node + wallet bridge)</h2>
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
            Bridge pairing token (printed by <code>datu wallet serve</code>)
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
      />

      {page === 'registrar' && sessions.registrar && (
        <section className="grid">
          <div className="card">
            <h2>Prepare the title application</h2>
            <label>
              Parcel
              <input value={form.parcel} onChange={setField('parcel')} />
            </label>
            <label>
              District
              <input value={form.district} onChange={setField('district')} />
            </label>
            <label>
              Holder name <em className="tag">encrypted</em>
              <input value={form.holder_name} onChange={setField('holder_name')} placeholder="Amina Yusuf" />
            </label>
            <label>
              Birth date <em className="tag">encrypted</em>
              <input value={form.birth_date} onChange={setField('birth_date')} placeholder="1990-04-12" />
            </label>
            <label>
              Holder Ed25519 key <em className="tag pub">public</em>
              <input value={form.holder_key} onChange={setField('holder_key')} placeholder="64 hex" />
            </label>
            <label>
              Holder seal key (X25519) <em className="tag pub">public</em>
              <input value={form.holder_seal} onChange={setField('holder_seal')} placeholder="64 hex" />
            </label>
            <button onClick={signAsRegistrar} disabled={busy}>
              Seal fields &amp; sign as registrar
            </button>
          </div>

          <div className="card">
            <h2>Envelope → landowner</h2>
            {!registrarEnvelope && <p className="muted small">- seal &amp; sign to produce the envelope -</p>}
            {registrarEnvelope && (
              <>
                <p className="ok small">
                  registrar signed · parties: {registrarEnvelope.parties.map((p) => p.role).join(', ')}
                </p>
                <button
                  onClick={() =>
                    downloadJson(`${form.parcel || 'title'}-1-registrar.json`, registrarEnvelope)
                  }
                >
                  Download envelope for the landowner
                </button>
                <button
                  className="ghost"
                  onClick={() => navigator.clipboard.writeText(JSON.stringify(registrarEnvelope))}
                >
                  Copy envelope JSON
                </button>
                <details>
                  <summary>envelope preview</summary>
                  <pre>{JSON.stringify(registrarEnvelope, null, 2)}</pre>
                </details>
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
                    const parcels = doc.doc?.parcel ?? '?';
                    const roles = (doc.parties || []).map((p) => p.role).join(', ') || '-';
                    return `parcel ${parcels} · signatures: ${roles}`;
                  } catch (e) {
                    return `unreadable: ${e.message}`;
                  }
                })()}
              </p>
            )}
          </div>

          <div className="card">
            <h2>Consent as holder</h2>
            <p className="muted small">
              Your identity must be the one named in <code>holder_key</code>; the registry checks it
              again on the ledger.
            </p>
            <button onClick={signAsHolder} disabled={busy || !holderIn || !sessions.landowner}>
              Sign consent as holder
            </button>
            {holderEnvelope && (
              <>
                <p className="ok small">
                  holder consented · parties: {holderEnvelope.parties.map((p) => p.role).join(', ')}
                </p>
                <button
                  onClick={() =>
                    downloadJson(
                      `${holderEnvelope.doc?.parcel || 'title'}-2-consented.json`,
                      holderEnvelope
                    )
                  }
                >
                  Download consented envelope for the registry
                </button>
                <button
                  className="ghost"
                  onClick={() => navigator.clipboard.writeText(JSON.stringify(holderEnvelope))}
                >
                  Copy envelope JSON
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
              Sign entry &amp; POST to node
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
