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

export default function App() {
  const [nodeUrl, setNodeUrl] = useState('http://127.0.0.1:7474');
  const [bridgeUrl, setBridgeUrl] = useState('http://127.0.0.1:7482');
  const [identities, setIdentities] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [registrarName, setRegistrarName] = useState('registrar');
  const [registrarPass, setRegistrarPass] = useState('');
  const [authorName, setAuthorName] = useState('registry-signer');
  const [authorPass, setAuthorPass] = useState('');
  const [signedDoc, setSignedDoc] = useState(null);
  const [consentInput, setConsentInput] = useState('');
  const [readyDoc, setReadyDoc] = useState(null);
  const [log, setLog] = useState([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [nodeStatus, setNodeStatus] = useState(null);

  const say = (msg, kind = 'info') =>
    setLog((l) => [...l, { msg, kind, at: new Date().toLocaleTimeString() }]);

  const refresh = useCallback(async () => {
    try {
      const ids = await listIdentities(bridgeUrl);
      setIdentities(ids);
      const registrar = ids.find((i) => i.name === registrarName);
      if (registrar && !form.holder_seal && registrar.seal_public) {
        setForm((f) => (f.holder_seal ? f : f));
      }
      const { body } = await nodeGet(nodeUrl, '/v1/status');
      setNodeStatus(body);
      say(`bridge: ${ids.length} identities · node mode: ${body?.policy?.mode ?? '?'}`);
    } catch (e) {
      say(`cannot reach services: ${e.message}`, 'err');
    }
  }, [bridgeUrl, nodeUrl, registrarName, form.holder_seal]);

  useEffect(() => {
    refresh();
        // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const registrar = identities.find((i) => i.name === registrarName);
  const author = identities.find((i) => i.name === authorName);

  const setField = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function sealAndSignAsRegistrar() {
    setBusy(true);
    setResult(null);
    try {
      if (!registrar) throw new Error(`identity '${registrarName}' not found on the bridge`);
      if (!form.holder_key || !form.holder_seal) {
        throw new Error('holder key and holder seal key are required');
      }
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
        name: registrarName,
        passphrase: registrarPass,
        document,
        fields: ['holder_name', 'birth_date'],
        to: [registrar.seal_public],
        to_fields: ['holder_seal'],
      });
      if (sealed.status !== 200) throw new Error(sealed.body.error || 'seal failed');
      say(`${sealed.body.sealed} field(s) sealed to ${sealed.body.readers} readers`);

      const signed = await bridgePost(bridgeUrl, '/v1/wallet/party-sign', {
        name: registrarName,
        passphrase: registrarPass,
        role: 'registrar',
        kind: KIND,
        document: sealed.body.document,
      });
      if (signed.status !== 200) throw new Error(signed.body.error || 'party sign failed');
      say('registrar consent signature added (Ed25519 + ML-DSA-65)');
      setSignedDoc(signed.body.document);
      setReadyDoc(null);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  function acceptHolderConsent() {
    try {
      const doc = JSON.parse(consentInput);
      const holder = (doc.parties || []).find((p) => p.role === 'holder');
      if (!holder) throw new Error('the pasted document has no holder party signature');
      if (doc.doc?.holder_key && holder.key !== doc.doc.holder_key) {
        throw new Error('holder signature is not from the key named in holder_key');
      }
      setReadyDoc(doc);
      say(`holder consent verified locally: ${holder.key.slice(0, 16)}…`);
    } catch (e) {
      say(`consent not accepted: ${e.message}`, 'err');
    }
  }

  async function submitToLedger() {
    setBusy(true);
    setResult(null);
    try {
      if (!readyDoc) throw new Error('the holder has not consented yet');
      if (!author) throw new Error(`identity '${authorName}' not found on the bridge`);
      const feed = await nodeGet(nodeUrl, `/v1/feed/${author.ed_public}`);
      if (feed.status !== 200) throw new Error(feed.body.error || 'cannot read feed');
      const next = feed.body.next || { seq: 0, prev: null };
      say(`authoring entry seq ${next.seq} as ${author.ed_public.slice(0, 16)}…`);

      const signed = await bridgePost(bridgeUrl, '/v1/wallet/sign-entry', {
        name: authorName,
        passphrase: authorPass,
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
        throw new Error(`node ${submit.status}: ${submit.body.denied || submit.body.rejected || submit.body.error}`);
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

  return (
    <div className="page">
      <header>
        <h1>DATU · Land Registry</h1>
        <p className="muted">
          Title application - sealed personal data, holder consent required, two validators.
        </p>
      </header>

      <section className="grid">
        <div className="card">
          <h2>Services</h2>
          <label>
            Registry node
            <input value={nodeUrl} onChange={(e) => setNodeUrl(e.target.value)} />
          </label>
          <label>
            Wallet bridge
            <input value={bridgeUrl} onChange={(e) => setBridgeUrl(e.target.value)} />
          </label>
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
          {nodeStatus && (
            <p className="muted small">
              mode <b>{nodeStatus.policy?.mode}</b> · entries {nodeStatus.entries} ·
              witnesses {nodeStatus.checkpoints}
            </p>
          )}
          <h3>Identities on this bridge</h3>
          <ul className="ids">
            {identities.map((i) => (
              <li key={i.name}>
                <b>{i.name}</b>
                <span className="muted">{i.ed_public.slice(0, 16)}…</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <h2>1 · Title application</h2>
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
          <div className="row">
            <label>
              Registrar identity
              <input value={registrarName} onChange={(e) => setRegistrarName(e.target.value)} />
            </label>
            <label>
              Passphrase
              <input type="password" value={registrarPass} onChange={(e) => setRegistrarPass(e.target.value)} />
            </label>
          </div>
          <button onClick={sealAndSignAsRegistrar} disabled={busy}>
            Seal fields &amp; sign as registrar
          </button>
        </div>

        <div className="card">
          <h2>2 · Holder consent</h2>
          <p className="muted small">
            Send this document to the landowner. They sign the <b>holder</b> role in the wallet
            extension (on their own machine), then paste the result here.
          </p>
          <textarea
            readOnly
            rows={8}
            value={signedDoc ? JSON.stringify(signedDoc, null, 2) : '- run step 1 -'}
          />
          <button
            className="ghost"
            disabled={!signedDoc}
            onClick={() => navigator.clipboard.writeText(JSON.stringify(signedDoc))}
          >
            Copy consent request
          </button>
          <textarea
            rows={8}
            placeholder="paste the holder-signed document here"
            value={consentInput}
            onChange={(e) => setConsentInput(e.target.value)}
          />
          <button className="ghost" onClick={acceptHolderConsent} disabled={!consentInput}>
            Check consent
          </button>
          {readyDoc && <p className="ok small">holder consent verified - ready to submit</p>}
        </div>

        <div className="card">
          <h2>3 · Submit to the ledger</h2>
          <div className="row">
            <label>
              Author identity
              <input value={authorName} onChange={(e) => setAuthorName(e.target.value)} />
            </label>
            <label>
              Passphrase
              <input type="password" value={authorPass} onChange={(e) => setAuthorPass(e.target.value)} />
            </label>
          </div>
          <button onClick={submitToLedger} disabled={busy || !readyDoc}>
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
