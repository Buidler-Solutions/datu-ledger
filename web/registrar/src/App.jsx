import React, { useCallback, useEffect, useState } from 'react';
import { listIdentities, nodeGet, nodePost, getToken, setToken } from './api.js';
import { onWalletState, walletCreateIdentity, walletIdentities, walletPing, walletSign } from './wallet.js';
import { newChallenge, verifyAssertion } from './signetauth.js';

const NS = 'gov.titles.application';
const KIND = 'land.title.application';
const CLAIM_KIND = 'land.ownership.registration';

// ---- roles: one wallet, one workspace ----
// The first login registers the wallet's key under the chosen role; every
// later visit restores the session and lands straight in that workspace.
const ROLES = {
  landowner: {
    label: 'Landowner',
    page: 'landowner',
    defaultName: 'amina',
    hint: 'Register an ownership claim, then consent as the holder when the registrar certifies the title.',
  },
  registrar: {
    label: 'Registrar',
    page: 'registrar',
    defaultName: 'registrar',
    hint: 'Verify landowner claims, seal the personal fields, and certify the title application.',
  },
  registry: {
    label: 'Registry signer',
    page: 'registry',
    defaultName: 'registry-signer',
    hint: 'Verify the fully signed envelope and record the title into the DATU ledger.',
  },
};
const ROLE_PAGES = Object.values(ROLES).map((r) => r.page);
const roleForPage = (p) => Object.entries(ROLES).find(([, r]) => r.page === p)?.[0] || null;

const SESSION_KEY = 'datu.landreg.session';
const ROLES_KEY = 'datu.landreg.roles';
const loadStored = (key, fallback) => {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
};
const saveSession = (s) => localStorage.setItem(SESSION_KEY, JSON.stringify(s));
const clearSession = () => localStorage.removeItem(SESSION_KEY);
const walletRoles = () => loadStored(ROLES_KEY, {});
const roleOfKey = (ed) => walletRoles()[ed] || null;
const rememberRole = (ed, role) => {
  const map = walletRoles();
  map[ed] = role;
  localStorage.setItem(ROLES_KEY, JSON.stringify(map));
};

function useHashPage() {
  const read = () => window.location.hash.replace(/^#\/?/, '') || 'welcome';
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


// ---- landing page: not logged in (or wallet not yet registered here) ----
function Welcome({ wallet, identities, bridgeUrl, nodeUrl, nodeStatus, busy, onLogin, onRefresh, say }) {
  const [role, setRole] = useState('landowner');
  const [name, setName] = useState(ROLES.landowner.defaultName);
  const [creating, setCreating] = useState(false);
  const registered = Object.entries(walletRoles());

  useEffect(() => {
    setName(ROLES[role].defaultName);
  }, [role]);

  const wanted = ROLES[role].defaultName;
  const have = identities.find((i) => i.name === wanted);

  async function login() {
    onLogin(role, name.trim());
  }

  // Set the Signet for this role: mint the role's identity inside the vault
  // through the extension. The panel asks the human for a passphrase, the
  // bridge creates the key, and this page only ever sees the public record.
  async function addRoleIdentity() {
    setCreating(true);
    try {
      await walletCreateIdentity({
        bridgeUrl,
        name: wanted,
        summary: `Add the ${ROLES[role].label} Signet '${wanted}' - choose its passphrase in this prompt`,
      });
      say(`Signet '${wanted}' created and added to your extension`, 'ok');
      await onRefresh();
      onLogin(role, wanted);
    } catch (e) {
      say(`could not add '${wanted}': ${e.message}`, 'err');
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <section className="grid hero">
        <div className="card">
          <h2>What this registry does</h2>
          <p className="muted small">
            Ownership registration → registrar certification → landowner consent → ledger record. The
            envelope travels by file; every signature is confirmed in the browser Signet extension.
            Nothing is trusted - each party signs with its own keys.
          </p>
          <p className={wallet.detected ? 'ok small' : 'err small'}>
            Signet extension:{' '}
            {wallet.detected
              ? `active · ${wallet.wallets.length} wallet(s) paired`
              : 'not detected - load/reload it in chrome://extensions, then reload this page'}
          </p>
          {nodeStatus && (
            <p className="muted small">
              registry node: mode <b>{nodeStatus.policy?.mode}</b> · {nodeStatus.entries} entries ·{' '}
              {identities.length} identities on this bridge
            </p>
          )}
        </div>

        <div className="card login">
          <h2>Log in with your Signet</h2>
          <p className="muted small">
            Pick the role this Signet acts as. Your vault signs a one-time challenge - the passphrase
            never leaves it. First login registers the vault's key under this role; next visits go
            straight to its workspace.
          </p>
          <div className="roles">
            {Object.entries(ROLES).map(([key, r]) => (
              <button
                key={key}
                className={role === key ? 'role active' : 'role'}
                onClick={() => setRole(key)}
              >
                <b>{r.label}</b>
                <span className="muted small">{r.hint}</span>
              </button>
            ))}
          </div>
          <div className="row">
            <label>
              Identity in your Signet
              <input value={name} onChange={(e) => setName(e.target.value)} list="signet-names" />
              <datalist id="signet-names">
                {identities.map((i) => (
                  <option key={i.name} value={i.name} />
                ))}
              </datalist>
            </label>
            <button onClick={login} disabled={busy || !wallet.detected} style={{ marginTop: '1.4rem' }}>
              {busy ? 'signing challenge…' : `Login as ${ROLES[role].label}`}
            </button>
          </div>
          <p className={have ? 'ok small' : 'muted small'}>
            {have
              ? `role identity '${wanted}' is in this Signet (${String(have.ed_public || '').slice(0, 16)}…)`
              : `role identity '${wanted}' is not in this Signet yet`}
          </p>
          {!have && (
            <button
              className="ghost"
              onClick={addRoleIdentity}
              disabled={creating || busy || !wallet.detected}
            >
              {creating ? 'waiting for the extension…' : `Add '${wanted}' to the Signet`}
            </button>
          )}
          {!have && (
            <p className="muted small">
              Adding creates this role's identity inside your Signet vault: the extension asks you
              for a passphrase (8+ characters) and keeps the key there. This page never sees it.
              You are signed in as {ROLES[role].label} right after.
            </p>
          )}
          {!wallet.detected && (
            <p className="err small">the Signet extension is not answering - see the Services card below</p>
          )}
        </div>
      </section>

      {registered.length > 0 && (
        <section className="card">
          <h2>Signets registered on this browser</h2>
          <ul className="ids">
            {registered.map(([ed, r]) => (
              <li key={ed}>
                <span>
                  <b>{ROLES[r]?.label || r}</b> · {ed.slice(0, 24)}…
                </span>
                <button
                  className="ghost"
                  onClick={() => {
                    setRole(r);
                    say(`role set to ${ROLES[r]?.label || r} - now log in with that Signet`);
                  }}
                >
                  use this role
                </button>
              </li>
            ))}
          </ul>
          <p className="muted small">
            A Signet already has a role when its key is listed above - after login the registry routes
            it to its own workspace automatically.
          </p>
        </section>
      )}
    </>
  );
}

// ---- signed-in strip shown on every workspace ----
function RoleBar({ session, onLogout, onSwitchRole }) {
  const r = ROLES[session.role] || { label: session.role };
  return (
    <div className="rolebar">
      <span>
        <b>{r.label} workspace</b> · signed in as <b>{session.name}</b> · key{' '}
        <code>{session.ed.slice(0, 16)}…</code> · since {session.at}
      </span>
      <span className="rolebar-actions">
        <button className="ghost" onClick={onSwitchRole}>
          Switch role
        </button>
        <button className="ghost" onClick={onLogout}>
          Log out
        </button>
      </span>
    </div>
  );
}

export default function App() {
  const [page, go] = useHashPage();

  const [nodeUrl, setNodeUrl] = useState('http://127.0.0.1:7474');
  const [bridgeUrl, setBridgeUrl] = useState('http://127.0.0.1:7488');
  const [identities, setIdentities] = useState([]);
  const [nodeStatus, setNodeStatus] = useState(null);
  const [log, setLog] = useState([]);
  const [busy, setBusy] = useState(false);

  const [session, setSession] = useState(() => loadStored(SESSION_KEY, null));
  const [wallet, setWallet] = useState({ detected: false, wallets: [], unlocked: [] });
  const autoTried = React.useRef(false);

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
  const [deferRelease, setDeferRelease] = useState(false);
  const [releaseSecrets, setReleaseSecrets] = useState(null);
  const [contractAdmits, setContractAdmits] = useState('');
  const [contractWasmB64, setContractWasmB64] = useState(null);
  const [releaseDoc, setReleaseDoc] = useState('');
  const [releaseSecretsText, setReleaseSecretsText] = useState('');
  const [releaseField, setReleaseField] = useState('');
  const [releaseShare, setReleaseShare] = useState(null);

  const [holderIn, setHolderIn] = useState('');
  const [holderEnvelope, setHolderEnvelope] = useState(null);

  const [registryIn, setRegistryIn] = useState('');
  const [readyDoc, setReadyDoc] = useState(null);
  const [result, setResult] = useState(null);

  const [contractNs, setContractNs] = useState('records.escrow');
  const [contractList, setContractList] = useState(null);
  const [contractView, setContractView] = useState(null); // { id, outlook }

  const say = (msg, kind = 'info') =>
    setLog((l) => [...l, { msg, kind, at: new Date().toLocaleTimeString() }]);

  const refresh = useCallback(async () => {
    try {
      const { body } = await nodeGet(nodeUrl, '/v1/status');
      setNodeStatus(body);
      say(`node: ${body?.entries ?? '?'} entries · mode ${body?.policy?.mode ?? '?'}`);
    } catch (e) {
      say(`cannot reach the node at ${nodeUrl}: ${e.message}`, 'err');
    }
    // Identity listing goes through the extension, which already holds the
    // bridge token - the dApp never needs one pasted into it. A manually
    // pasted token (Settings) remains as a fallback for debugging.
    try {
      const listed = await walletIdentities(bridgeUrl);
      const ids = listed.identities || [];
      setIdentities(ids);
      say(`bridge: ${ids.length} identities via the Signet extension`, 'ok');
    } catch (viaExtension) {
      if (!getToken()) {
        say(
          `identities need the extension (${viaExtension.message}) or a pasted token in Settings`,
          'muted'
        );
        return;
      }
      try {
        const ids = await listIdentities(bridgeUrl);
        setIdentities(ids);
        say(`bridge: ${ids.length} identities on ${bridgeUrl} (manual token)`, 'ok');
      } catch (e) {
        say(`cannot reach the bridge at ${bridgeUrl}: ${e.message}`, 'err');
      }
    }
  }, [bridgeUrl, nodeUrl]);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let alive = true;
    let attempts = 0;
    const probe = async () => {
      const ok = await walletPing();
      if (!alive) return;
      if (ok) {
        setWallet((w) => ({ ...w, detected: true }));
        return;
      }
      if (++attempts < 20) setTimeout(probe, 2000);
    };
    probe();
    const off = onWalletState((state) => {
      if (!alive) return;
      setWallet({
        detected: true,
        wallets: state.wallets || [],
        unlocked: state.unlocked || [],
      });
    });
    return () => {
      alive = false;
      off();
    };
  }, []);

  // ---- routing: a workspace is only reachable by its own role ----
  useEffect(() => {
    if (page !== 'welcome' && (!session || session.role !== roleForPage(page))) {
      const needed = roleForPage(page);
      say(
        needed
          ? `that workspace needs a signed-in ${needed} Signet - log in first`
          : 'unknown workspace - back to the landing page'
      );
      go('welcome');
    }
    if (page === 'welcome' && session) {
      go(ROLES[session.role]?.page || 'welcome');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, session]);

  // ---- login / logout ----
  // SignetAuth (datu-auth-v1): challenge-response login. The Signet signs the
  // one-time challenge; the app verifies the Ed25519 signature locally
  // against the identity's public key, so the node and the bridge are never
  // trusted for authentication.
  async function login(roleKey, name) {
    setBusy(true);
    try {
      if (!(await walletPing())) {
        throw new Error(
          'Signet extension not detected - load it from chrome://extensions and reload this page'
        );
      }
      const role = ROLES[roleKey] ? roleKey : 'landowner';
      const challenge = newChallenge({
        rpId: window.location.hostname,
        origin: window.location.origin,
      });
      // Version skew: a Signet service older than SignetAuth answers 404 for
      // the assertion route. Fall back to the party-signed login challenge so
      // older wallets keep working, and say which path was taken.
      let assertion;
      let legacy = false;
      try {
        const res = await walletSign({
          bridgeUrl,
          path: '/v1/wallet/auth-assert',
          summary: `Login - your Signet signs a one-time challenge as ${ROLES[role].label}${name ? ` (${name})` : ''}`,
          body: {
            name,
            rp_id: challenge.rp_id,
            origin: challenge.origin,
            nonce: challenge.nonce,
            expires_at_ms: challenge.expires_at_ms,
          },
        });
        assertion = res.body || {};
      } catch (e) {
        if (!/no route|404/i.test(e.message)) throw e;
        legacy = true;
        const res = await walletSign({
          bridgeUrl,
          path: '/v1/wallet/party-sign',
          summary: `Login (legacy) - your Signet signs a one-time challenge as ${ROLES[role].label}${name ? ` (${name})` : ''}`,
          body: {
            name,
            role: 'login',
            kind: 'datu.login',
            document: { role, node: nodeUrl, nonce: challenge.nonce, ts: Date.now() },
          },
        });
        const party = ((res.body || {}).document?.parties || []).find((p) => p.role === 'login');
        if (!party) throw new Error('Signet returned no login signature');
        assertion = { pubkey: party.key, signature: party.ed_signature || '' };
      }
      if (!assertion.pubkey) throw new Error('Signet returned no login assertion');
      let verdict = { ok: null };
      if (legacy) {
        say(
          'this Signet predates SignetAuth (no /v1/wallet/auth-assert) - used the legacy party-sign challenge',
          'muted'
        );
      } else {
        verdict = await verifyAssertion(nodeUrl, assertion, challenge);
        if (verdict.ok === false) throw new Error(`login assertion rejected: ${verdict.reason}`);
      }
      const known = roleOfKey(assertion.pubkey);
      const finalRole = known && ROLES[known] ? known : role;
      if (known && known !== role) {
        say(`this Signet is already registered as ${ROLES[known].label} - routing it there`, 'muted');
      }
      rememberRole(assertion.pubkey, finalRole);
      const s = {
        name,
        ed: assertion.pubkey,
        sig: assertion.signature || '',
        at: new Date().toLocaleTimeString(),
        role: finalRole,
      };
      setSession(s);
      saveSession(s);
      say(
        `${name || 'Signet'} logged in as ${ROLES[finalRole].label} (${assertion.pubkey.slice(0, 16)}…)${
          verdict.ok === true ? ' - signature verified locally' : ' - local verification unavailable'
        }`,
        'ok'
      );
      go(ROLES[finalRole].page);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  function logout() {
    if (session) say(`${session.name} logged out`);
    setSession(null);
    clearSession();
    go('welcome');
  }

  function switchRole() {
    say(`logged out of the ${ROLES[session.role]?.label || session.role} workspace - pick another role`);
    setSession(null);
    clearSession();
    go('welcome');
  }

  // Silent session restore: when the extension is active and a stored session
  // exists, ask the wallet to re-sign a fresh challenge. If the panel does not
  // hold the passphrase yet, the request waits there for one confirm.
  useEffect(() => {
    if (!wallet.detected || !session?.name || autoTried.current) return;
    autoTried.current = true;
    (async () => {
      try {
        const challenge = newChallenge({
          rpId: window.location.hostname,
          origin: window.location.origin,
        });
        let assertion;
        let legacy = false;
        try {
          const res = await walletSign({
            bridgeUrl,
            path: '/v1/wallet/auth-assert',
            summary: `Re-login - ${session.name} re-signs a challenge as ${ROLES[session.role]?.label || session.role}`,
            body: {
              name: session.name,
              rp_id: challenge.rp_id,
              origin: challenge.origin,
              nonce: challenge.nonce,
              expires_at_ms: challenge.expires_at_ms,
              auto: true,
            },
          });
          assertion = res.body || {};
        } catch (e) {
          if (!/no route|404/i.test(e.message)) throw e;
          legacy = true;
          const res = await walletSign({
            bridgeUrl,
            path: '/v1/wallet/party-sign',
            summary: `Re-login (legacy) - ${session.name} re-signs a challenge`,
            body: {
              name: session.name,
              role: 'login',
              kind: 'datu.login',
              document: { nonce: challenge.nonce, ts: Date.now() },
              auto: true,
            },
          });
          const party = ((res.body || {}).document?.parties || []).find((p) => p.role === 'login');
          if (!party) throw new Error('no login signature');
          assertion = { pubkey: party.key, signature: party.ed_signature || '' };
        }
        if (!assertion.pubkey || assertion.pubkey !== session.ed) {
          say('stored session belongs to a different key - log in again', 'err');
          setSession(null);
          clearSession();
          go('welcome');
          return;
        }
        if (!legacy) {
          const verdict = await verifyAssertion(nodeUrl, assertion, challenge);
          if (verdict.ok === false) {
            say(`re-login assertion rejected: ${verdict.reason}`, 'err');
            setSession(null);
            clearSession();
            go('welcome');
            return;
          }
        }
        const s = {
          ...session,
          sig: assertion.signature || '',
          at: new Date().toLocaleTimeString(),
        };
        setSession(s);
        saveSession(s);
        say(`session restored - ${s.name} continues as ${ROLES[s.role]?.label || s.role}`, 'ok');
        go(ROLES[s.role]?.page || 'welcome');
      } catch {
        // leave the manual login on the landing page in place
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet.detected]);

  // ---- landowner: register the ownership claim ----
  async function registerOwnership() {
    if (!session || session.role !== 'landowner') return say('log in as a landowner first', 'err');
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

  // ---- registrar: receive the claim, prepare and sign ----
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
    if (!session || session.role !== 'registrar') return say('log in as a registrar first', 'err');
    setBusy(true);
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
              signature: claim.parties.find((p) => p.role === 'claimant')?.ed_signature,
              registered_at: claim.doc.registered_at,
            }
          : undefined,
      };
      say(deferRelease
        ? 'sealing personal fields for deferred delivery to the holder…'
        : 'sealing personal fields to registry + holder…');
      const sealed = await walletSign({
        bridgeUrl,
        path: deferRelease ? '/v1/wallet/seal-deferred' : '/v1/wallet/seal',
        summary: deferRelease
          ? `Defer holder_name + birth_date for ${form.parcel} (opens only when a release publishes the key half)`
          : `Seal holder_name + birth_date for ${form.parcel} (readers: registrar + holder)`,
        body: deferRelease
          ? {
              name: session.name,
              document,
              fields: ['holder_name', 'birth_date'],
              to_fields: ['holder_seal'],
            }
          : {
              name: session.name,
              document,
              fields: ['holder_name', 'birth_date'],
              to: [me.seal_public],
              to_fields: ['holder_seal'],
            },
      });
      if (deferRelease) {
        setReleaseSecrets({ version: 1, fields: sealed.body.releases || {} });
        say(`${sealed.body.sealed} field(s) deferred to the holder - download the release secrets and keep them until release`, 'ok');
      } else {
        setReleaseSecrets(null);
        say(`${sealed.body.sealed} field(s) sealed to ${sealed.body.readers} readers`);
      }

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

  // ---- landowner: consent as holder ----
  async function signAsHolder() {
    if (!session || session.role !== 'landowner') return say('log in as a landowner first', 'err');
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

  // ---- registry: verify and record ----
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
    if (!session || session.role !== 'registry') return say('log in as a registry signer first', 'err');
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
      if (!signed.body || !signed.body.entry) throw new Error('Signet returned no signed entry');
      say(`entry ${signed.body.id.slice(0, 16)}… signed`);

      const submit = await nodePost(nodeUrl, '/v1/entries', signed.body.entry);
      if (submit.status !== 201 && submit.status !== 200) {
        throw new Error(
          `node ${submit.status}: ${submit.body.denied || submit.body.rejected || submit.body.error}`
        );
      }
      say(submit.status === 201 ? 'accepted into the ledger' : 'already present (idempotent)');
      const entry = await nodeGet(nodeUrl, `/v1/entry/${signed.body.id}`);
      // Who has witnessed it so far: informational here (the node relays
      // witnesses; re-verify the served proofs with `datu witness
      // verify-proof` or the panel's Witnessed view).
      let coverage = null;
      try {
        const cov = await nodeGet(nodeUrl, `/v1/coverage/${signed.body.id}`);
        coverage = { witnesses: cov.body.witnesses || [], error: cov.body.error || null };
      } catch {
        /* coverage is a bonus; recording already succeeded */
      }
      setResult({ id: signed.body.id, status: submit.status, entry: entry.body, coverage });
      const st = await nodeGet(nodeUrl, '/v1/status');
      setNodeStatus(st.body);
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---- document contracts: pending agreements (conditions outstanding) ----
  // ---- registry: draft a contract spec ----
  async function onContractWasm(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) {
      setContractWasmB64(null);
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = '';
      for (const b of bytes) binary += String.fromCharCode(b);
      setContractWasmB64(btoa(binary));
      say(`wasm module loaded: ${bytes.length} bytes (base64-encoded into the spec)`);
    } catch (err) {
      say(`cannot read the module: ${err.message}`, 'err');
    }
  }

  function downloadContractSpec() {
    const admits = contractAdmits.trim();
    if (!admits) return say('enter the document kind the contract admits', 'err');
    const spec = { version: 1, admits };
    if (contractWasmB64) spec.wasm = contractWasmB64;
    downloadJson(`${admits.replace(/[^a-z0-9._-]/gi, '-')}-contract-spec.json`, spec);
    say('contract spec drafted; sign it into a gov.contract document before publishing', 'ok');
  }

  // ---- registry: release a deferred field ----
  async function makeRelease() {
    setBusy(true);
    try {
      if (!releaseDoc.trim()) throw new Error('paste or load the document that carries the deferred field');
      if (!releaseSecretsText.trim()) throw new Error('paste the release-secrets file from the seal step');
      const document = JSON.parse(releaseDoc);
      let secrets;
      try {
        secrets = JSON.parse(releaseSecretsText);
      } catch {
        throw new Error('release secrets must be JSON');
      }
      if (!secrets.fields || typeof secrets.fields !== 'object') {
        throw new Error('release secrets carry no "fields" map');
      }
      const field = releaseField.trim() || Object.keys(secrets.fields)[0] || '';
      if (!field) throw new Error('the secrets file names no fields');
      const res = await walletSign({
        bridgeUrl,
        path: '/v1/wallet/release-deferred',
        summary: `Release '${field}': publish the key half sealed to the nominated holder (no signature needed)`,
        body: { document, field, release: secrets },
      });
      setReleaseShare(res.body.share);
      say(`release key half for '${field}' generated - attach it to the release entry`, 'ok');
    } catch (e) {
      say(e.message, 'err');
    } finally {
      setBusy(false);
    }
  }

  async function listContractAnchors() {
    setContractView(null);
    try {
      const ns = contractNs.trim();
      const { status, body } = await nodeGet(
        nodeUrl,
        `/v1/entries?ns=${encodeURIComponent(ns)}&limit=50`,
      );
      if (status !== 200) throw new Error(body.error || `node ${status}`);
      setContractList(body.entries || []);
      say(`${(body.entries || []).length} entries in ${ns}`);
    } catch (e) {
      say(`cannot list ${contractNs}: ${e.message}`, 'err');
    }
  }

  async function checkContractStatus(id) {
    try {
      const { status, body } = await nodeGet(nodeUrl, `/v1/contract/status/${id}`);
      if (status === 404) {
        setContractView({ id, outlook: { ready: false, kind: body.error || 'no contract', conditions: [], reasons: [], citing: [] } });
        say(`entry ${id.slice(0, 12)}… declares no contract`);
        return;
      }
      if (status !== 200) throw new Error(body.error || `node ${status}`);
      setContractView({ id, outlook: body });
      say(
        body.ready
          ? `citation-side conditions met - a '${body.admits}' may land`
          : `conditions outstanding on ${id.slice(0, 12)}…`,
        body.ready ? 'ok' : 'muted',
      );
    } catch (e) {
      say(`cannot evaluate contract: ${e.message}`, 'err');
    }
  }

  const workspace = ROLE_PAGES.includes(page) ? page : null;

  return (
    <div className="page">
      <header>
        <h1>DATU · Land Registry</h1>
        <p className="muted">
          Ownership registration → registrar certification → landowner consent → ledger record. Log in
          with your Signet - the registry opens only the workspace that vault's role is allowed to see.
        </p>
      </header>

      {workspace && session && <RoleBar session={session} onLogout={logout} onSwitchRole={switchRole} />}

      {page === 'welcome' && (
        <Welcome
          wallet={wallet}
          identities={identities}
          bridgeUrl={bridgeUrl}
          nodeUrl={nodeUrl}
          nodeStatus={nodeStatus}
          busy={busy}
          onLogin={login}
          onRefresh={refresh}
          say={say}
        />
      )}

      {workspace && (
        <section className="card slim">
          <details>
            <summary className="muted small">Services (node + Signet service)</summary>
            <div className="row">
              <label>
                Registry node
                <input value={nodeUrl} onChange={(e) => setNodeUrl(e.target.value)} />
              </label>
              <label>
                Signet service (bridge URL)
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
                  onBlur={refresh}
                  onKeyDown={(e) => e.key === 'Enter' && refresh()}
                  placeholder="64 hex characters"
                />
              </label>
              <button className="ghost" onClick={refresh} disabled={busy}>
                Refresh
              </button>
            </div>
            <p className={wallet.detected ? 'ok small' : 'err small'}>
              Signet extension:{' '}
              {wallet.detected
                ? `active · ${wallet.wallets.length} wallet(s) paired`
                : 'not detected - load/reload it in chrome://extensions, then reload this page'}
              {wallet.detected &&
                ` · unlocked: ${wallet.unlocked.join(', ') || 'none (panel will ask once)'}`}
            </p>
          </details>
        </section>
      )}

      {page === 'welcome' && (
        <section className="card">
          <h2>Services (node + Signet service)</h2>
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
                onBlur={refresh}
                onKeyDown={(e) => e.key === 'Enter' && refresh()}
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
          <p className={wallet.detected ? 'ok small' : 'err small'}>
            Signet extension:{' '}
            {wallet.detected
              ? `active · ${wallet.wallets.length} wallet(s) paired`
              : 'not detected - load/reload it in chrome://extensions, then reload this page'}
            {wallet.detected &&
              ` · unlocked: ${wallet.unlocked.join(', ') || 'none (panel will ask once)'}`}
          </p>
        </section>
      )}

      {page === 'landowner' && session && (
        <>
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
                Sign ownership claim with your Signet
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

          <section className="grid">
            <div className="card">
              <h2>Receive the envelope from the registrar</h2>
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
              <button onClick={signAsHolder} disabled={busy || !holderIn}>
                Sign consent with your Signet
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
                </>
              )}
            </div>
          </section>
        </>
      )}

      {page === 'registrar' && session && (
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
              <input
                value={form.district}
                onChange={(e) => setForm({ ...form, district: e.target.value })}
              />
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
            <label>
              <input
                type="checkbox"
                checked={deferRelease}
                onChange={(e) => setDeferRelease(e.target.checked)}
              />{' '}
              Defer the encrypted fields until release: the title lands now, but the holder can
              open their personal data only when a release publishes the key half
            </label>
            <button onClick={signAsRegistrar} disabled={busy}>
              Seal fields &amp; sign as registrar
            </button>
            {releaseSecrets && (
              <>
                <p className="muted small">
                  deferred: {Object.keys(releaseSecrets.fields).length} release key half(s) - keep
                  this file offline; the release entry publishes it, and only then can the holder
                  open their data.
                </p>
                <button
                  className="ghost"
                  onClick={() =>
                    downloadJson(`${form.parcel || 'title'}-release-secrets.json`, releaseSecrets)
                  }
                >
                  Download release secrets
                </button>
              </>
            )}
            {registrarEnvelope && (
              <>
                <p className="ok small">
                  registrar signed · parties:{' '}
                  {registrarEnvelope.parties.map((p) => p.role).join(', ')}
                </p>
                <button
                  onClick={() =>
                    downloadJson(`${form.parcel || 'title'}-1-registrar.json`, registrarEnvelope)
                  }
                >
                  Download envelope for the landowner
                </button>
              </>
            )}
          </div>
        </section>
      )}

      {page === 'registry' && session && (
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
            <button onClick={recordToLedger} disabled={busy || !readyDoc}>
              Sign entry with your Signet &amp; POST to node
            </button>
            {result && (
              <div className={`result ${result.status === 201 ? 'okbox' : 'dupbox'}`}>
                <p>
                  {result.status === 201 ? 'Accepted' : 'Already present'} · entry{' '}
                  <code>{result.id}</code>
                </p>
                {result.coverage && (
                  <p className="muted small">
                    {result.coverage.witnesses.length
                      ? `covered by ${result.coverage.witnesses.length} fresh witness checkpoint(s) on this node (as reported; re-verify with datu witness verify-proof or the panel's Witnessed view)`
                      : 'no fresh witness covers it yet - coverage follows the next checkpoint a witness signs (as reported by this node)'}
                  </p>
                )}
                <details>
                  <summary>stored entry (ciphertext fields visible)</summary>
                  <pre>{JSON.stringify(result.entry, null, 2)}</pre>
                </details>
              </div>
            )}
          </div>
          <div className="card">
            <h2>Release a deferred field</h2>
            <p className="muted small">
              A title whose fields were sealed for deferred delivery opens only when a release
              publishes the key half. Load the document and the release-secrets file; the share
              object goes into the release entry, sealed to the nominated holder.
            </p>
            <label>
              Document carrying the deferred field
              <textarea
                rows={4}
                value={releaseDoc}
                onChange={(e) => setReleaseDoc(e.target.value)}
                placeholder='{"cert_id":"...","owner_name":{"sealed":"datu-sealed-deferred-v2", ...}}'
              />
            </label>
            <FileLoader label="...or load the document" onText={setReleaseDoc} />
            <label>
              Release secrets (written by the seal step)
              <textarea
                rows={4}
                value={releaseSecretsText}
                onChange={(e) => setReleaseSecretsText(e.target.value)}
                placeholder='{"version":1,"fields":{"owner_name":"<hex>"}}'
              />
            </label>
            <label>
              Field to release
              <input
                value={releaseField}
                onChange={(e) => setReleaseField(e.target.value)}
                placeholder="owner_name (defaults to the first field in the secrets)"
              />
            </label>
            <button onClick={makeRelease} disabled={busy}>
              Generate the release key half
            </button>
            {releaseShare && (
              <>
                <p className="ok small">release half sealed to the nominated holder</p>
                <button
                  onClick={() =>
                    downloadJson(`${releaseField || 'field'}-release-share.json`, releaseShare)
                  }
                >
                  Download the share object
                </button>
                <label>
                  Release entry skeleton (kind + doc carrying the share - edit to match your
                  contract, then sign it through the usual consent flow)
                  <textarea
                    rows={6}
                    value={JSON.stringify(
                      {
                        kind: 'datu.cert.release',
                        doc: { released_field: releaseField || 'field', released_share: releaseShare },
                      },
                      null,
                      2,
                    )}
                    readOnly
                  />
                </label>
              </>
            )}
          </div>

          <div className="card">
            <h2>Draft a contract</h2>
            <p className="muted small">
              Build the spec JSON for a document contract: a JSON-DSL skeleton, or a deterministic
              wasm predicate whose body is base64-encoded here. Sign it into a gov.contract
              document and publish it (datu wallet cosign-doc, then datu publish).
            </p>
            <label>
              Admits (document kind)
              <input
                value={contractAdmits}
                onChange={(e) => setContractAdmits(e.target.value)}
                placeholder="land.title.grant"
              />
            </label>
            <label>
              wasm module (.wasm), optional
              <input type="file" accept=".wasm" onChange={onContractWasm} />
            </label>
            <button onClick={downloadContractSpec} disabled={!contractAdmits.trim()}>
              Download contract spec
            </button>
          </div>

          <div className="card">
            <h2>Contract status · pending agreements</h2>
            <p className="muted small">
              Anchors that declare a document contract (escrow agreements, reward offers): the node
              judges the citation-side conditions over the evidence citing them. READY means the
              satisfying document may land; OUTSTANDING shows what is missing.
            </p>
            <label>
              namespace of agreement anchors
              <input
                value={contractNs}
                onChange={(e) => setContractNs(e.target.value)}
                placeholder="records.escrow"
              />
            </label>
            <button className="ghost" onClick={listContractAnchors}>
              List anchors
            </button>
            {contractList &&
              (contractList.length === 0 ? (
                <p className="muted small">no entries in that namespace on this node</p>
              ) : (
                <ul className="anchorlist">
                  {contractList.map((entry) => (
                    <li key={entry.id}>
                      <code>{entry.id.slice(0, 16)}…</code>{' '}
                      <span className="muted small">
                        seq {entry.seq} · refs {entry.refs?.length ?? 0}
                      </span>{' '}
                      <button className="ghost" onClick={() => checkContractStatus(entry.id)}>
                        Status
                      </button>
                    </li>
                  ))}
                </ul>
              ))}
            {contractView && (
              <div className={`result ${contractView.outlook.ready ? 'okbox' : 'dupbox'}`}>
                <p>
                  {contractView.outlook.ready ? 'READY' : 'OUTSTANDING'} · {contractView.outlook.kind}
                  {contractView.outlook.admits ? (
                    <>
                      {' '}
                      · awaits <code>{contractView.outlook.admits}</code>
                    </>
                  ) : null}
                </p>
                {(contractView.outlook.conditions || []).length > 0 && (
                  <ul className="conditions">
                    {contractView.outlook.conditions.map((c, i) => (
                      <li key={i} className={c.met ? '' : 'err'}>
                        [{c.met ? 'met' : 'NOT MET'}] {c.requirement} (required {c.required}, found{' '}
                        {c.found})
                      </li>
                    ))}
                  </ul>
                )}
                {(contractView.outlook.reasons || []).map((r) => (
                  <p key={r} className="err small">
                    {r}
                  </p>
                ))}
                {(contractView.outlook.citing || []).length > 0 && (
                  <details>
                    <summary>evidence: {contractView.outlook.citing.length} citing entries</summary>
                    <pre>
                      {contractView.outlook.citing
                        .map(
                          (c) =>
                            `${c.id.slice(0, 16)}…  ${c.kind ?? '-'}  ${c.namespace}  ts ${c.timestamp_ms}`,
                        )
                        .join('\n')}
                    </pre>
                  </details>
                )}
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
