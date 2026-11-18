// Typed-ish client for the sandbox backend. Sessions are persisted in
// localStorage so a learner keeps one node across lessons; the server
// expires it after 30 idle minutes and the client recreates on 404.

const KEY = 'datu-lab-sandbox';

async function request(method, route, body) {
  const res = await fetch(route, {
    method,
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let payload = {};
  try {
    payload = await res.json();
  } catch {
    /* non-JSON error */
  }
  if (!res.ok) {
    const err = new Error(payload.error || `request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return payload;
}

let inflightEnsure = null;

export const sandbox = {
  id() {
    return localStorage.getItem(KEY);
  },
  setId(id) {
    if (id) localStorage.setItem(KEY, id);
    else localStorage.removeItem(KEY);
  },

  // Concurrent callers share one creation attempt: two lessons mounting at
  // once must not spawn two nodes.
  async ensure() {
    if (!inflightEnsure) {
      inflightEnsure = this._ensure().finally(() => {
        inflightEnsure = null;
      });
    }
    return inflightEnsure;
  },

  async _ensure() {
    const id = this.id();
    if (id) {
      try {
        return await request('GET', `/api/sandbox/${id}`);
      } catch (e) {
        if (e.status !== 404) throw e;
        this.setId(null);
      }
    }
    const created = await request('POST', '/api/sandbox');
    this.setId(created.id);
    return { id: created.id, identity: created.identity, status: { entries: 1 } };
  },

  async destroy() {
    const id = this.id();
    if (id) await request('DELETE', `/api/sandbox/${id}`).catch(() => {});
    this.setId(null);
  },

  entries(id, limit = 200) {
    return request('GET', `/api/sandbox/${id}/entries?limit=${limit}`);
  },
  entry(id, entryId) {
    return request('GET', `/api/sandbox/${id}/entry/${entryId}`);
  },
  checkpoints(id) {
    return request('GET', `/api/sandbox/${id}/checkpoints`);
  },
  publish(id, namespace, payload) {
    return request('POST', `/api/sandbox/${id}/publish`, { namespace, payload });
  },
  attest(id, subject, claims) {
    return request('POST', `/api/sandbox/${id}/attest`, { subject, claims });
  },
  revoke(id, key, reason) {
    return request('POST', `/api/sandbox/${id}/revoke`, { key, reason });
  },
  checkpoint(id) {
    return request('POST', `/api/sandbox/${id}/checkpoint`);
  },
  verify(id) {
    return request('POST', `/api/sandbox/${id}/verify`);
  },
  exportBundle(id) {
    return request('POST', `/api/sandbox/${id}/bundle/export`);
  },
  importBundle(id, bundle) {
    return request('POST', `/api/sandbox/${id}/bundle/import`, { bundle });
  },
  sync(id, peer) {
    return request('POST', `/api/sandbox/${id}/sync`, { peer });
  },
};

// A second, independent node for the sync and trust lessons. Recreated on
// demand; deleted with the primary sandbox by the lab page.
export const peerSandbox = {
  KEY: 'datu-lab-peer',
  id() {
    return localStorage.getItem(this.KEY);
  },
  async ensure() {
    const id = this.id();
    if (id) {
      try {
        return await request('GET', `/api/sandbox/${id}`);
      } catch (e) {
        if (e.status !== 404) throw e;
        localStorage.removeItem(this.KEY);
      }
    }
    const created = await request('POST', '/api/sandbox');
    localStorage.setItem(this.KEY, created.id);
    return { id: created.id, identity: created.identity, status: { entries: 1 } };
  },
  async destroy() {
    const id = this.id();
    if (id) await request('DELETE', `/api/sandbox/${id}`).catch(() => {});
    localStorage.removeItem(this.KEY);
  },
};

export const short = (h) => (h ? `${h.slice(0, 8)}…${h.slice(-4)}` : '');

export const timeAgo = (ms) => {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
};
