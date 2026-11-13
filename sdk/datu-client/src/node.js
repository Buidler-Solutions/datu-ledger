/**
 * Ledger node transport: the mirror HTTP API (datu serve / node --http).
 * Reads are public; submission accepts only pre-signed entries.
 */
import { DatuError, ErrorCode, mapError } from './errors.js';

const trim = (url) => String(url || '').replace(/\/+$/, '');

export function createNodeClient({ nodeUrl, fetchImpl } = {}) {
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  if (!doFetch) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'no fetch available; pass fetchImpl');

  async function call(path, { method = 'GET', body, timeoutMs = 20_000 } = {}) {
    if (!nodeUrl) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'nodeUrl is required');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await doFetch(`${trim(nodeUrl)}${path}`, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      const text = await res.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        json = { error: text };
      }
      if (!res.ok) {
        throw new DatuError(
          ErrorCode.NODE_ERROR,
          (json && json.error) || `node ${res.status}`,
          { status: res.status },
        );
      }
      return json;
    } catch (e) {
      if (e instanceof DatuError) throw e;
      if (e && e.name === 'AbortError') {
        throw new DatuError(ErrorCode.TIMEOUT, `node did not answer within ${timeoutMs}ms`);
      }
      throw mapError(e, ErrorCode.NODE_ERROR);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    url: trim(nodeUrl),
    status: () => call('/v1/status'),
    entries: ({ ns, author, limit = 50 } = {}) => {
      const query = new URLSearchParams();
      if (ns) query.set('ns', ns);
      if (author) query.set('author', author);
      if (limit) query.set('limit', String(limit));
      const suffix = query.toString() ? `?${query}` : '';
      return call(`/v1/entries${suffix}`);
    },
    entry: (id) => {
      if (!id) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'entry id is required');
      return call(`/v1/entry/${encodeURIComponent(id)}`);
    },
    coverage: (entryId, checkpointId) => {
      if (!entryId) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'entry id is required');
      const suffix = checkpointId ? `/${encodeURIComponent(checkpointId)}` : '';
      return call(`/v1/coverage/${encodeURIComponent(entryId)}${suffix}`);
    },
    contractStatus: (entryId) => {
      if (!entryId) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'entry id is required');
      return call(`/v1/contract/status/${encodeURIComponent(entryId)}`);
    },
    feedHead: (author) => {
      if (!author) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'author key is required');
      return call(`/v1/feed/${encodeURIComponent(author)}`);
    },
    submit: (entry) => {
      if (!entry) throw new DatuError(ErrorCode.BAD_ARGUMENT, 'signed entry is required');
      return call('/v1/entries', { method: 'POST', body: entry });
    },
    raw: call,
  };
}
