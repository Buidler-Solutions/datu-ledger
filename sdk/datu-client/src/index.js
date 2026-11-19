/**
 * @greenarmor/datu-client - integrate a dApp with the DATU accountability DAG.
 *
 * One entry point: connect({ bridgeUrl, nodeUrl }) returns a client that
 * speaks to the Signet extension (keys live in the Signet service, never here)
 * and to a ledger node (reads, submission, coverage proofs).
 *
 * SignetAuth is a one-liner:
 *   const { assertion, verified } = await datu.signIn({ name, rpId, origin });
 * See specs/signetauth.md in the repo for the wire standard.
 */
import { createExtensionTransport } from './extension.js';
import { createNodeClient } from './node.js';
import {
  AUTH_DOMAIN,
  authSignedBytes,
  buildSignInLink,
  challengeIsLive,
  newChallenge,
  readAssertionFragment,
  randomNonceHex,
  verifyAssertion,
  verifyEd25519,
} from './auth.js';
import {
  PROVIDER_DOMAIN,
  pinBridgeKey,
  providerProofBytes,
  verifyProviderProof,
} from './provider.js';
import { DatuError, ErrorCode, mapError } from './errors.js';
import { beginPhoneSignIn, finishPhoneSignIn, resumePhoneSignIn } from './phone.js';

export {
  AUTH_DOMAIN,
  authSignedBytes,
  buildSignInLink,
  challengeIsLive,
  newChallenge,
  readAssertionFragment,
  randomNonceHex,
  verifyAssertion,
  verifyEd25519,
  PROVIDER_DOMAIN,
  pinBridgeKey,
  providerProofBytes,
  verifyProviderProof,
  DatuError,
  ErrorCode,
  createExtensionTransport,
  createNodeClient,
  beginPhoneSignIn,
  finishPhoneSignIn,
  resumePhoneSignIn,
};

const require = (value, message) => {
  if (!value) throw new DatuError(ErrorCode.BAD_ARGUMENT, message);
  return value;
};

// Accept "a,b", "a" or ["a","b"] everywhere a list of names/keys is expected:
// integrations read from forms and env vars far more often than from arrays.
const asList = (value) => {
  if (value == null || value === '') return undefined;
  if (Array.isArray(value)) return value;
  return String(value)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
};

/**
 * Connect to a Signet extension (and optionally a node).
 * Options:
 *   bridgeUrl   - the Signet service URL the extension is paired with
 *   nodeUrl     - a ledger node / explorer (default http://127.0.0.1:7474)
 *   transport   - inject an extension transport (tests, custom hosts)
 *   fetchImpl   - inject fetch (tests, non-browser runtimes)
 *   rpId/origin - defaults for signIn (origin defaults to window.location.origin)
 */
export async function connect({
  bridgeUrl,
  nodeUrl = 'http://127.0.0.1:7474',
  transport,
  fetchImpl,
  rpId,
  origin,
  detect = true,
} = {}) {
  const rpc = transport || createExtensionTransport();
  if (detect) {
    const pong = await rpc.ping();
    if (!pong) {
      throw new DatuError(
        ErrorCode.NOT_CONNECTED,
        'Signet extension not detected - load it from chrome://extensions and reload this page',
      );
    }
  }

  const defaultRpId = rpId || (typeof window !== 'undefined' ? window.location.hostname : undefined);
  const defaultOrigin = origin || (typeof window !== 'undefined' ? window.location.origin : undefined);

  async function identities() {
    const listed = await rpc.identities(bridgeUrl);
    return listed.identities || [];
  }

  async function sign({ name, path, body, summary }) {
    require(path, 'path is required');
    try {
      const res = await rpc.sign({ bridgeUrl, path, body: { name, ...body }, summary });
      return res.body || res;
    } catch (e) {
      // Whatever transport produced it, callers get a stable code.
      throw mapError(e);
    }
  }

  /** Bridge passthrough for screens that already build full bodies. */
  const bridge = (path, body, summary) => sign({ name: body && body.name, path, body, summary });

  /**
   * Genuineness handshake (datu-provider-v1): challenge whoever claims to be
   * the Signet extension with a fresh nonce. Only the extension holding a
   * pairing token can obtain this bridge-keyed proof, so:
   *   genuine:true  - a paired provider answered (verified:false only means
   *                   this browser has no local Ed25519 verifier)
   *   genuine:false + reachable:true - it answered with an invalid proof:
   *                   an impostor; never ask for a passphrase here
   *   genuine:false + reachable:false - no answer at all (bridge down):
   *                   say "cannot reach the Signet service", not "malicious"
   */
  async function proveGenuine({ bridgeUrl: wantedBridge, nonce, expectedBridgePubkey, nowMs } = {}) {
    const challenge = nonce || randomNonceHex();
    let proof;
    try {
      proof = await rpc.prove({ bridgeUrl: wantedBridge || bridgeUrl, nonce: challenge });
    } catch (e) {
      return { genuine: false, reachable: false, reason: mapError(e).message, nonce: challenge };
    }
    const verdict = await verifyProviderProof(proof, { nonce: challenge, nowMs });
    if (verdict.ok === false) {
      return { genuine: false, reachable: true, reason: verdict.reason, proof, nonce: challenge };
    }
    const pin = pinBridgeKey(proof.bridgeUrl, proof.bridge_pubkey, expectedBridgePubkey);
    if (!pin.ok) {
      return { genuine: false, reachable: true, reason: pin.reason, proof, nonce: challenge };
    }
    return {
      genuine: true,
      verified: verdict.ok === true,
      reachable: true,
      pinned: pin.pinnedNow,
      bridgeUrl: proof.bridgeUrl,
      version: proof.version,
      bridgePubkey: proof.bridge_pubkey,
      proof,
      nonce: challenge,
    };
  }

  /**
   * Start a SignetAuth login: mint the challenge (this app is the relying
   * party) and get a verifier bound to it.
   */
  function startLogin(options = {}) {
    const challenge = newChallenge({
      rpId: options.rpId || defaultRpId,
      origin: options.origin || defaultOrigin,
      ttlMs: options.ttlMs,
      nonce: options.nonce,
    });
    return {
      challenge,
      verify: (assertion) => verifyAssertion(assertion, challenge),
    };
  }

  /**
   * Full login: challenge, wallet signature via the extension, local
   * verification. Returns { assertion, verified, challenge }.
   * `verified` is true, false, or null when no local verifier exists.
   */
  async function signIn({
    name,
    rpId,
    origin,
    ttlMs,
    nonce,
    summary,
    strict = false,
    // The human clicked "sign in": that is the approval gesture the bridge
    // needs to register a site on first use. Silent re-logins pass false.
    approve = true,
    grant,
    // Only for a trusted host that owns the Signet service (CLI, server-side
    // bridge, tests). A browser page must never pass this: the extension
    // supplies the passphrase from the panel.
    passphrase,
  } = {}) {
    const { challenge, verify } = startLogin({ rpId, origin, ttlMs, nonce });
    const assertion = await sign({
      name,
      path: '/v1/wallet/auth-assert',
      body: {
        rp_id: challenge.rp_id,
        origin: challenge.origin,
        nonce: challenge.nonce,
        expires_at_ms: challenge.expires_at_ms,
        approve,
        grant,
        passphrase,
      },
      summary: summary || `Sign in to ${challenge.rp_id}`,
    });
    const verdict = await verify(assertion);
    if (verdict.ok === false) {
      throw new DatuError(ErrorCode.REJECTED, `login assertion rejected: ${verdict.reason}`);
    }
    if (strict && verdict.ok !== true) {
      throw new DatuError(
        ErrorCode.REJECTED,
        `login assertion could not be verified locally: ${verdict.reason}`,
      );
    }
    return { assertion, verified: verdict.ok, challenge };
  }

  /**
   * Phone sign-in, out of the box. No extension, no bridge: returns the
   * link to render as a QR and a promise that settles when the phone
   * returns (same page + #datu-assertion=..., or a server calling accept()).
   * Call resumePhoneSignIn() on page load to pick up a redirect-back.
   */
  function phoneSignIn({ rpId, origin, ttlMs, nonce, redirect } = {}) {
    return beginPhoneSignIn({
      rpId: rpId || defaultRpId,
      origin: origin || defaultOrigin,
      ttlMs,
      nonce,
      redirect,
    });
  }

  /** Pick up a phone redirect-back on page load; null when there is none. */
  const resumePhone = (options = {}) => resumePhoneSignIn(options);

  /**
   * One call, either signer: the extension when it is present, the phone
   * otherwise. Extension results resolve immediately; phone results return
   * the flow ({ link, completed }) so the app can show a QR.
   */
  async function signInAuto({ name, rpId, origin, ttlMs } = {}) {
    let extension = false;
    try {
      extension = Boolean(await rpc.ping());
    } catch {
      extension = false;
    }
    if (extension) {
      const result = await signIn({ name, rpId, origin, ttlMs });
      return { method: 'extension', ...result };
    }
    const flow = phoneSignIn({ rpId, origin, ttlMs });
    return { method: 'phone', challenge: flow.challenge, link: flow.link, completed: flow.completed, accept: flow.accept };
  }

  /** Party signature on a document, as a role (holder, registrar, ...). */
  const partySign = async ({ name, role, document, kind, summary } = {}) => {
    require(role, 'role is required');
    return sign({
      name,
      path: '/v1/wallet/party-sign',
      body: { name, role, kind, document },
      summary: summary || `Sign as ${role}${kind ? ` (${kind})` : ''}`,
    });
  };

  /** Author a ledger entry from a sign request (namespace, payload, refs). */
  const signEntry = async ({ name, request, summary } = {}) => {
    require(request, 'request is required');
    return sign({
      name,
      path: '/v1/wallet/sign-entry',
      body: { name, request },
      summary: summary || `Publish to ${request.namespace || 'a namespace'}`,
    });
  };

  const seal = async ({ name, document, fields, to, toFields, summary } = {}) =>
    sign({
      name,
      path: '/v1/wallet/seal',
      body: { name, document, fields: asList(fields), to: asList(to), to_fields: asList(toFields) },
      summary: summary || `Seal ${asList(fields) ? asList(fields).join(', ') : 'fields'}`,
    });

  const sealDeferred = async ({ name, document, fields, to, toField, summary } = {}) => {
    const holders = asList(to);
    return sign({
      name,
      path: '/v1/wallet/seal-deferred',
      body: {
        name,
        document,
        fields: asList(fields),
        to: holders ? holders[0] : undefined,
        to_field: toField,
      },
      summary: summary || `Defer ${asList(fields) ? asList(fields).join(', ') : 'fields'}`,
    });
  };

  const releaseDeferred = async ({ document, field, release } = {}) => {
    require(field, 'field is required');
    return sign({
      path: '/v1/wallet/release-deferred',
      body: { document, field, release },
      summary: `Release ${field}`,
    });
  };

  const openDeferred = async ({ name, document, field, release, summary } = {}) => {
    require(field, 'field is required');
    return sign({
      name,
      path: '/v1/wallet/deferred-open',
      body: { name, document, field, release },
      summary: summary || `Open ${field}`,
    });
  };

  const openSealed = async ({ name, document, summary } = {}) =>
    sign({
      name,
      path: '/v1/wallet/open',
      body: { name, document },
      summary: summary || 'Decrypt fields addressed to you',
    });

  /** Verify an entry's signatures and party list inside the Signet service. */
  const verifyEntry = async ({ name, entry } = {}) =>
    sign({
      name,
      path: '/v1/wallet/verify-entry',
      body: { name, entry },
      summary: 'Verify an entry',
    });

  /**
   * Load the node's coverage verifier (it serves /coverage.js, which exposes
   * BLAKE3 plus Merkle-path and Ed25519 checks on window.datuCoverage).
   * Browser only; in Node it resolves to null and coverage stays unchecked.
   */
  let coverageVerifierPromise = null;
  async function loadCoverageVerifier() {
    if (typeof window === 'undefined') return null;
    if (window.datuCoverage) return window.datuCoverage;
    if (coverageVerifierPromise) return coverageVerifierPromise;
    coverageVerifierPromise = (async () => {
      try {
        const base = getNode().url;
        const res = await doFetch(`${base}/coverage.js`);
        if (!res.ok) return null;
        const source = await res.text();
        (0, eval)(source);
        return window.datuCoverage || null;
      } catch {
        return null;
      }
    })();
    return coverageVerifierPromise;
  }

  /**
   * Coverage: is this entry witnessed by a fresh checkpoint? Verifies the
   * served Merkle path and checkpoint signature locally when a coverage
   * verifier is supplied (the node serves /coverage.js as window.datuCoverage,
   * or pass coverageVerifier from './verify.js').
   */
  async function verifyCoverage(entryId, { coverageVerifier } = {}) {
    const node = getNode();
    const answer = await node.coverage(entryId);
    const verifier =
      coverageVerifier ||
      (typeof window !== 'undefined' ? window.datuCoverage : null) ||
      (await loadCoverageVerifier());
    const witnesses = answer.witnesses || [];
    const results = [];
    for (const witness of witnesses) {
      if (!verifier || !verifier.verifyWitness) {
        results.push({ ...witness, verdict: 'not checked (no local coverage verifier)' });
        continue;
      }
      try {
        const check = await verifier.verifyWitness(entryId, witness);
        results.push({ ...witness, verdict: check.ok ? 'verified' : `not verified: ${check.reason}` });
      } catch (e) {
        results.push({ ...witness, verdict: `not verified: ${e.message}` });
      }
    }
    return { entryId, witnesses: results, stale: answer.stale || [] };
  }

  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  let nodeClient = createNodeClient({ nodeUrl, fetchImpl });
  function getNode() {
    if (!nodeClient) nodeClient = createNodeClient({ nodeUrl, fetchImpl });
    return nodeClient;
  }

  return {
    bridgeUrl,
    get nodeUrl() {
      return nodeClient.url;
    },
    setNodeUrl(url) {
      nodeClient = createNodeClient({ nodeUrl: url, fetchImpl });
    },
    get node() {
      return getNode();
    },
    rpc,
    ping: () => rpc.ping(),
    identities,
    onState: (fn) => rpc.onState(fn),
    sign,
    bridge,
    startLogin,
    phoneSignIn,
    resumePhoneSignIn: resumePhone,
    signInAuto,
    signIn,
    proveGenuine,
    partySign,
    signEntry,
    seal,
    sealDeferred,
    releaseDeferred,
    openDeferred,
    openSealed,
    verifyEntry,
    verifyCoverage,
    loadCoverageVerifier,
    onError: (e) => mapError(e),
  };
}

export default { connect };
