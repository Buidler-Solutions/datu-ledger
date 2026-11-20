# @greenarmor/datu-client

Integrate a dApp with the DATU accountability DAG: SignetAuth login, party
signatures, sealed and deferred fields, node reads, and local coverage
verification. Zero dependencies, browser-first, with Node support for tests and
server-side verification.

Keys never enter your page. The DATU Signet extension holds the pairing token
and the Signet service holds the keys; this SDK only speaks to them.

## Install

```sh
npm install @greenarmor/datu-client
```

From the repo, before a release: `npm install /path/to/datu-ledger/sdk/datu-client`.

## Connect

```js
import { connect } from '@greenarmor/datu-client';

const datu = await connect({
  bridgeUrl: 'http://127.0.0.1:7588',
  nodeUrl: 'http://127.0.0.1:7474',
});
// throws DatuError(NOT_CONNECTED) when the extension is not installed
```

## Log in (SignetAuth)

```js
const { assertion, verified, challenge } = await datu.signIn({
  name: 'amina',
  rpId: 'app.example.com',
  origin: 'https://app.example.com',
});
if (!verified) throw new Error('assertion did not verify locally');
// send `assertion` to your backend; it verifies one Ed25519 signature
```

Two-step form when your backend issues the challenge:

```js
const { challenge, verify } = datu.startLogin({ rpId: 'app.example.com' });
// ... wallet signs ...
const verdict = await verify(assertionFromWallet); // { ok, reason }
```

Server side: verify with the released binary, no libraries.

```sh
datu signet auth-verify --rp-id app.example.com --origin https://app.example.com \
  --nonce <issued> --expires-at-ms <issued> \
  --pubkey <user key> --signature <from assertion>
```

Wire standard: `specs/signetauth.md`.Wire standard: `specs/signetauth.md`.

## Require attestation (who vouches for this key)

A signature proves the key signed; it does not prove the key is anyone in
particular. Gate the login on the ledger's trust graph:

```js
import { checkAttestation } from '@greenarmor/datu-client';

const verdict = await checkAttestation('http://127.0.0.1:7474', assertion.pubkey, {
  roots: ['<attestor-key-hex>'],   // only these roots count
  roles: ['clerk'],                // claims.role must match
  minCosigners: 1,                 // distinct cosigner weight required
});
if (!verdict.ok) throw new Error(verdict.reason);  // names why, never a bare "verified"
console.log(verdict.vouchers);     // [{ by, label, claims, cosigners, enroll }]
```

Or split it: `fetchIdentityChain(nodeUrl, pubkey)` returns the raw
`/v1/identity` JSON and `requireAttestation(chain, opts)` is the pure policy
function (sync, testable). A revoked attestation never vouches; a key
revoked directly vouches for nothing. Transport problems throw a typed
`DatuError`, policy failures return `{ ok: false, reason }` - the caller
must tell "unreachable" from "unattested". The reference relying party
(`web/signin-demo`) shows the full pattern, with `REQUIRE_ATTESTATION` as
the env-driven version.

## Log in with a phone (no extension, no bridge)

`npm install` is enough for the QR path: a dApp can issue the challenge,
show it, and verify the assertion without any Signet extension present.

```js
import { connect } from '@greenarmor/datu-client';

// detect:false lets the page run on browsers with no extension installed
const datu = await connect({ detect: false, rpId: 'app.example.com', origin: 'https://app.example.com' });

const flow = datu.phoneSignIn();      // { challenge, link, completed }
renderQr(flow.link);                  // any QR library; the link is also scannable from a copy button
const result = await flow.completed;  // { ok: true, pubkey } or { ok: false, reason }
```

The phone returns to the same page with `#datu-assertion=…`; pick it up on
load (the SDK burns the nonce and scrubs the fragment from the URL):

```js
const resumed = await datu.resumePhoneSignIn();
if (resumed?.ok) signedInAs(resumed.pubkey);
```

Or let the SDK choose: `await datu.signInAuto()` returns the extension
result when one is present and the phone flow (`method: 'phone'`) when not.
React: `usePhoneSignIn()` from `@greenarmor/datu-react` does the same with a
`{ begin, link, result }` shape and resumes on mount.

Enforced by the SDK for this path: challenge stored per nonce (survives a
reload), single use (burned on success), expiry against the local clock, and
field match against the challenge you issued. If your backend performs the
relying-party check too, hand its verdict back with `flow.accept(assertion)`;
the SDK re-verifies locally before resolving.


## Prove the wallet is genuine (before asking a human for anything)

An impostor extension can imitate every page-facing API, but it holds no
pairing token, so it can never obtain the bridge-keyed proof this challenge
demands. Run it before sign-in screens and passphrase prompts.

```js
const verdict = await datu.proveGenuine();
if (verdict.genuine && verdict.verified) {
  // genuine Signet extension on a paired bridge
} else if (verdict.genuine) {
  // paired provider answered; this browser just has no local Ed25519
  // verifier (verified === false), decide your own policy
} else if (verdict.reachable) {
  // it ANSWERED with an invalid proof: a definite impostor.
  // hard-block the page and never ask for a passphrase here
} else {
  // no answer at all: the Signet service is down or not paired.
  // say "cannot reach the Signet service"; never call it malicious
}
```

The proof (domain `datu-provider-v1`) echoes your nonce, expires in ~30 s, and
is signed by the bridge's own Ed25519 key. That key is TOFU-pinned per
`bridgeUrl` (localStorage), so a swapped bridge is caught on the next check;
pass `expectedBridgePubkey` to pin explicit trust instead. The handshake
needs no passphrase and proves pairing, not custody: only `signIn` proves a
human holds the keys. `providerProofBytes`, `verifyProviderProof`,
`pinBridgeKey` and `PROVIDER_DOMAIN` are exported for custom hosts.

## Sign documents and entries

```js
await datu.partySign({ name: 'amina', role: 'holder', document, kind: 'land.title.application' });
await datu.signEntry({ name: 'amina', request: { namespace: 'gov.records', payload } });
```

Headless or server-side use (a trusted host that owns the Signet service) can
sign in without the extension by passing `passphrase`; a browser page must
never do that, because then the page holds the secret.

```js
await datu.signIn({ name: 'amina', rpId: 'app.example.com', passphrase: process.env.VAULT_PASS });
```

## Privacy

```js
await datu.seal({ name: 'registrar', document, fields: ['holder_name'], toFields: ['holder_seal'] });
await datu.sealDeferred({ name: 'registrar', document, fields: ['price'], toField: 'holder_seal' });
await datu.releaseDeferred({ document, field: 'price', release });
await datu.openDeferred({ name: 'amina', document, field: 'price', release });
await datu.openSealed({ name: 'amina', document });
```

## Read and prove

```js
const status = await datu.node.status();
const { entries } = await datu.node.entries({ ns: 'gov.titles', limit: 20 });
const entry = await datu.node.entry(id);
const coverage = await datu.verifyCoverage(id); // verifies witness Merkle paths locally
const verdict = await datu.node.contractStatus(anchorId);
```

`verifyCoverage` verifies the served Merkle path and checkpoint signature
locally. It uses `window.datuCoverage` if your app already loaded the node's
`/coverage.js`, otherwise it fetches and evaluates it once itself
(`datu.loadCoverageVerifier()` is exposed too). Outside a browser there is no
verifier, and each witness is reported as not checked rather than pretended.

## Convenience rules

- `fields`, `to`, `toFields` accept an array, a single string, or a comma list
  (`fields: 'name,tax_id'`), so form inputs and env vars pass straight through
- `signIn({ ..., strict: true })` refuses an assertion the SDK could not verify
  locally; without it you get `verified: null` and can decide yourself
- Node statuses are named: `403 -> POLICY_DENIED`, `409 -> CONFLICT`
  (forks are preserved as evidence, not errors to hide), `429 -> RATE_LIMITED`
  with `details.retryAfterS`

## Errors

```js
import { DatuError, ErrorCode } from '@greenarmor/datu-client';

try {
  await datu.signIn({ name: 'amina' });
} catch (e) {
  if (e.code === ErrorCode.NEEDS_APPROVAL) { /* first login to this site */ }
  if (e.code === ErrorCode.ORIGIN_MISMATCH) { /* pinned to another origin */ }
  if (e.code === ErrorCode.NOT_PAIRED) { /* open the panel and pair */ }
}
```

Codes: `NOT_CONNECTED`, `NOT_PAIRED`, `NEEDS_APPROVAL`, `NEEDS_PASSPHRASE`, `ORIGIN_MISMATCH`,
`GRANT_EXPIRED`, `UNKNOWN_ROUTE`, `REJECTED`, `TIMEOUT`, `BRIDGE_ERROR`,
`NODE_ERROR`, `POLICY_DENIED`, `CONFLICT`, `RATE_LIMITED`, `BAD_ARGUMENT`.

## Tests without a wallet

```js
import { connect } from '@greenarmor/datu-client';
import { mockTransport, mockFetch } from '@greenarmor/datu-client/mock';

const datu = await connect({
  transport: mockTransport({ keys: { amina: keypair }, identities: [identity] }),
  fetchImpl: mockFetch({ routes: { '/v1/status': () => ({ entries: 1, checkpoints: 1 }) } }).fetchImpl,
});
```

`mockTransport` signs real assertions with the keys you supply, so your tests
exercise the same verification path as production. `mockFetch` records the
requests your app makes.

## TypeScript

Types ship with the package (`src/index.d.ts`); no build step and no bundler
required, the package is plain ESM.

## Verify against a real stack

```sh
datu signet serve --addr 127.0.0.1:7588 --data-dir /tmp/datu-demo
datu node --http 127.0.0.1:7574 --data-dir /tmp/datu-demo
DATU_PASS=amina-demo node scripts/live-smoke.mjs
```

Prints identities, node status, a verified login, a rejected replay, a grant
re-login, coverage, and a refused phishing origin. The unit suite
(`npm test`) needs no network.

## License

MIT.
