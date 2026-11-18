import { useEffect, useState } from 'react';
import DagCanvas from '../components/DagCanvas';
import Hash from '../components/Hash';
import Reveal from '../components/Reveal';
import Terminal from '../components/Terminal';
import { peerSandbox, sandbox, short, timeAgo } from '../lib/api';
import { useSandbox } from '../lib/useSandbox';

const line = (kind, text) => ({ kind, text });

export default function Lab() {
  const { node, entries, error, busy, run, refresh } = useSandbox();
  const [log, setLog] = useState([]);
  const [ns, setNs] = useState('general');
  const [payload, setPayload] = useState('{"hello":"laboratory"}');
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [peer, setPeer] = useState(null);
  const [peerEntries, setPeerEntries] = useState([]);
  const [attestSubject, setAttestSubject] = useState('');
  const [attestClaims, setAttestClaims] = useState('{"role":"lab-peer"}');
  const [revokeKey, setRevokeKey] = useState('');

  useEffect(() => {
    if (node && !attestSubject) setAttestSubject('');
  }, [node, attestSubject]);

  const push = (cmd, out, err) => {
    setLog((prev) => {
      const next = [...prev, line('cmd', cmd)];
      if (out) next.push(line('out', out));
      if (err) next.push(line('err', err));
      return next.slice(-40);
    });
  };

  const act = async (name, cmd, fn) => {
    try {
      const r = await run(fn);
      push(cmd, r?.output || 'done');
    } catch (e) {
      push(cmd, null, e.message);
    }
  };

  const selectEntry = async (e) => {
    setSelected(e.id);
    setDetail(null);
    try {
      const full = await sandbox.entry(node.id, e.id);
      setDetail(full);
    } catch (err) {
      setDetail({ error: err.message });
    }
  };

  const createPeer = async () => {
    try {
      const p = await peerSandbox.ensure();
      setPeer(p);
      const data = await sandbox.entries(p.id);
      setPeerEntries(data.entries || []);
      push('sandbox B created', `${p.identity}\n(second node, independent history)`);
    } catch (e) {
      push('sandbox B', null, e.message);
    }
  };

  const refreshPeer = async () => {
    if (!peer) return;
    const data = await sandbox.entries(peer.id);
    setPeerEntries(data.entries || []);
  };

  const reset = async () => {
    await sandbox.destroy();
    await peerSandbox.destroy();
    setPeer(null);
    setPeerEntries([]);
    setDetail(null);
    setSelected(null);
    setLog([]);
    await refresh();
  };

  return (
    <div>
      <header className="hero">
        <div className="kicker rise">the laboratory</div>
        <h1 className="rise delay-1">Playground</h1>
        <p className="lede rise delay-2">
          A real node, all of its verbs. Publish, attest, checkpoint, verify, sync and move bundles.
          The commands below are exactly what ran.
        </p>
      </header>

      {error && <div className="warn-box small" style={{ marginBottom: 16 }}>backend: {error}</div>}

      <div className="split">
        <div>
          <Reveal>
            <div className="panel">
              <div className="row">
                <h3 style={{ margin: 0 }}>Your node</h3>
                <span className="spacer" />
                <span className={`badge ${node ? 'ok' : 'warn'}`}>
                  <span className={`dot ${node ? 'live' : ''}`} /> {node ? 'live' : 'starting'}
                </span>
              </div>
              <div className="stack" style={{ marginTop: 12 }}>
                <div className="row small">
                  <span className="dim" style={{ width: 96 }}>identity</span>
                  {node ? <Hash value={node.identity} /> : <span className="dim">…</span>}
                </div>
                <div className="row small">
                  <span className="dim" style={{ width: 96 }}>entries</span>
                  <span className="mono">{node?.status?.entries ?? '…'}</span>
                  <span className="dim" style={{ width: 96, marginLeft: 20 }}>checkpoints</span>
                  <span className="mono">{node?.status?.checkpoints ?? '…'}</span>
                </div>
                <div className="btn-row">
                  <button className="btn ghost small" type="button" disabled={!node || busy} onClick={() => act('checkpoint', 'datu checkpoint', () => sandbox.checkpoint(node.id))}>
                    Checkpoint
                  </button>
                  <button className="btn ghost small" type="button" disabled={!node || busy} onClick={() => act('verify', 'datu verify', () => sandbox.verify(node.id))}>
                    Verify
                  </button>
                  <span className="spacer" />
                  <button className="btn danger small" type="button" onClick={reset}>
                    Reset sandbox
                  </button>
                </div>
              </div>
            </div>
          </Reveal>

          <Reveal>
            <div className="panel">
              <h3>Publish a record</h3>
              <div className="grid cols-2">
                <label className="field">
                  <span>namespace</span>
                  <input value={ns} onChange={(e) => setNs(e.target.value)} placeholder="gov.records" />
                </label>
                <label className="field">
                  <span>payload (JSON)</span>
                  <textarea value={payload} onChange={(e) => setPayload(e.target.value)} />
                </label>
              </div>
              <button
                className="btn"
                type="button"
                disabled={!node || busy}
                onClick={() =>
                  act('publish', `datu publish --ns ${ns} --payload '${payload}'`, () => sandbox.publish(node.id, ns, payload))
                }
              >
                Sign and publish
              </button>
            </div>
          </Reveal>

          <Reveal>
            <div className="panel">
              <h3>Attestations</h3>
              <p className="small muted" style={{ marginTop: -6 }}>
                Trust is a ledger fact: a key binds claims to another key. Revocation is a new
                record, never an edit.
              </p>
              <div className="grid cols-2">
                <label className="field">
                  <span>subject key (64 hex)</span>
                  <input value={attestSubject} onChange={(e) => setAttestSubject(e.target.value)} placeholder={peer?.identity || 'create sandbox B to get a key'} />
                </label>
                <label className="field">
                  <span>claims (JSON)</span>
                  <input value={attestClaims} onChange={(e) => setAttestClaims(e.target.value)} />
                </label>
              </div>
              <div className="btn-row">
                <button
                  className="btn ghost"
                  type="button"
                  disabled={!node || busy || attestSubject.length !== 64}
                  onClick={() => {
                    let claims;
                    try {
                      claims = JSON.parse(attestClaims);
                    } catch {
                      push('datu attest create', null, 'claims must be valid JSON');
                      return;
                    }
                    act('attest', `datu attest create --subject ${short(attestSubject)} --claims '${attestClaims}'`, () =>
                      sandbox.attest(node.id, attestSubject, claims),
                    );
                  }}
                >
                  Attest subject
                </button>
                <label className="field" style={{ margin: 0, flex: 1, minWidth: 220 }}>
                  <span>revoke key (64 hex)</span>
                  <input value={revokeKey} onChange={(e) => setRevokeKey(e.target.value)} placeholder={peer?.identity || ''} />
                </label>
                <button
                  className="btn danger"
                  type="button"
                  disabled={!node || busy || revokeKey.length !== 64}
                  onClick={() => act('revoke', `datu attest revoke --key ${short(revokeKey)}`, () => sandbox.revoke(node.id, revokeKey, 'laboratory playground'))}
                >
                  Revoke
                </button>
              </div>
            </div>
          </Reveal>

          <Reveal>
            <div className="panel">
              <div className="row">
                <h3 style={{ margin: 0 }}>Second node (peer)</h3>
                <span className="spacer" />
                {peer ? (
                  <span className="badge ok"><span className="dot live" /> B live</span>
                ) : (
                  <button className="btn ghost small" type="button" onClick={createPeer}>Create sandbox B</button>
                )}
              </div>
              {peer && (
                <div className="stack" style={{ marginTop: 12 }}>
                  <div className="row small">
                    <span className="dim" style={{ width: 96 }}>B identity</span>
                    <Hash value={peer.identity} />
                  </div>
                  <div className="btn-row">
                    <button
                      className="btn ghost small"
                      type="button"
                      disabled={busy}
                      onClick={async () => {
                        try {
                          const r = await sandbox.sync(peer.id, node.id);
                          push(`datu sync  (B pulls from A)`, r.output);
                          await refreshPeer();
                          await refresh();
                        } catch (e) {
                          push('datu sync', null, e.message);
                        }
                      }}
                    >
                      B syncs from A
                    </button>
                    <button
                      className="btn ghost small"
                      type="button"
                      disabled={busy}
                      onClick={async () => {
                        try {
                          const r = await sandbox.sync(node.id, peer.id);
                          push(`datu sync  (A pulls from B)`, r.output);
                          await refresh();
                        } catch (e) {
                          push('datu sync', null, e.message);
                        }
                      }}
                    >
                      A syncs from B
                    </button>
                  </div>
                  <div className="small dim">B holds {peerEntries.length} entries</div>
                </div>
              )}
            </div>
          </Reveal>

          <Reveal>
            <div className="panel">
              <h3>Offline channel (bundle)</h3>
              <div className="btn-row">
                <button
                  className="btn ghost small"
                  type="button"
                  disabled={!node || busy}
                  onClick={async () => {
                    try {
                      const r = await sandbox.exportBundle(node.id);
                      push('datu bundle export', `${r.output}\n${r.size} bytes, base64 in memory`);
                      if (peer) {
                        const imp = await sandbox.importBundle(peer.id, r.bundle);
                        push('datu bundle import  (into B)', imp.output);
                        await refreshPeer();
                      }
                    } catch (e) {
                      push('datu bundle export', null, e.message);
                    }
                  }}
                >
                  Export A, import into B
                </button>
              </div>
              <p className="small dim" style={{ margin: '10px 0 0' }}>
                A bundle is the whole history in one file: USB, email, anything that moves bytes.
              </p>
            </div>
          </Reveal>
        </div>

        <div>
          <Reveal>
            <Terminal lines={log} title="datu cli output" height={360} />
          </Reveal>

          <Reveal>
            <div className="panel">
              <h3>Your ledger</h3>
              <DagCanvas entries={entries} selected={selected} onSelect={selectEntry} />
              <div style={{ marginTop: 14, maxHeight: 260, overflow: 'auto' }}>
                <table className="data">
                  <thead>
                    <tr><th>entry</th><th>namespace</th><th>seq</th><th>age</th></tr>
                  </thead>
                  <tbody>
                    {[...entries].reverse().map((e) => (
                      <tr key={e.id} onClick={() => selectEntry(e)} style={{ cursor: 'pointer' }}>
                        <td className="mono"><Hash value={e.id} /></td>
                        <td className="mono">{e.namespace}</td>
                        <td className="mono">{e.seq}</td>
                        <td className="dim small">{timeAgo(e.timestamp_ms)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </Reveal>

          {detail && (
            <Reveal>
              <div className="panel">
                <h3>Entry detail</h3>
                <Terminal
                  title={`datu get --id ${detail.id ? short(detail.id) : '…'}`}
                  lines={[line('cmd', `datu get --id ${detail.id || '…'}`), line('out', JSON.stringify(detail, null, 2))]}
                  height={300}
                />
              </div>
            </Reveal>
          )}
        </div>
      </div>
    </div>
  );
}
