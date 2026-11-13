# @datu/client

Integrate a dApp with the DATU accountability DAG: SignetAuth login, party
signatures, sealed and deferred fields, node reads, and local coverage
verification. Zero dependencies, browser-first, with Node support for tests and
server-side verification.

Keys never enter your page. The DATU Signet extension holds the pairing token
and the Signet service holds the keys; this SDK only speaks to them.

## Install (path or future registry)

```sh
npm install /path/to/datu-ledger/sdk/datu-client
```

## Connect

```js
import { connect } from '@datu/client';

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

Wire standard: `specs/signetauth.md`.

## Sign documents and entries

```js
await datu.partySign({ name: 'amina', role: 'holder', document, kind: 'land.title.application' });
await datu.signEntry({ name: 'amina', request: { namespace: 'gov.records', payload } });
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

`verifyCoverage` uses `window.datuCoverage` when an app has loaded the node's
`/coverage.js`; otherwise it reports each witness as not checked rather than
pretending.

## Errors

```js
import { DatuError, ErrorCode } from '@datu/client';

try {
  await datu.signIn({ name: 'amina' });
} catch (e) {
  if (e.code === ErrorCode.NEEDS_APPROVAL) { /* first login to this site */ }
  if (e.code === ErrorCode.ORIGIN_MISMATCH) { /* pinned to another origin */ }
  if (e.code === ErrorCode.NOT_PAIRED) { /* open the panel and pair */ }
}
```

Codes: `NOT_CONNECTED`, `NOT_PAIRED`, `NEEDS_APPROVAL`, `ORIGIN_MISMATCH`,
`GRANT_EXPIRED`, `UNKNOWN_ROUTE`, `REJECTED`, `TIMEOUT`, `BRIDGE_ERROR`,
`NODE_ERROR`, `BAD_ARGUMENT`.

## Tests without a wallet

```js
import { connect } from '@datu/client';
import { mockTransport, mockFetch } from '@datu/client/mock';

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

## License

MIT.
