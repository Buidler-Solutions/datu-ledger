# hello-DATU

A five-minute starter dApp for the DATU accountability DAG. One page,
no build step: list the identities in your Signet, do a SignetAuth
login (challenge-response, verified in the page), and sign a document
as a party. A mock button runs the same flows with no wallet at all.

## Run it

1. Load the DATU Signet extension in Chrome (web/wallet-extension in
   the repo, or the release zip) and start a Signet service:

   ```sh
   datu signet serve --addr 127.0.0.1:7588
   datu --data-dir <dir> signet identity-create --name you   # then set a passphrase
   ```

2. Serve this folder and open it (localhost is where the extension's
   content script runs):

   ```sh
   cd examples/hello-datu
   npm install --no-save ../sdk/datu-client   # or: npm i @greenarmor/datu-client
   npm start
   # open http://localhost:5174
   ```

3. Click "Sign in with Signet". The first sign-in asks the panel to
   approve this site (origin pinning); afterwards it is silent.

## What each button does

- **list identities**: reads the public identity list from the paired
  Signet through the extension (no token pasting, no keys in the page).
- **Sign in with Signet**: mints a `datu-auth-v1` challenge, the wallet
  signs it, the page verifies the Ed25519 signature locally. This is
  SignetAuth (specs/signetauth.md).
- **sign as holder**: party-signs a demo document through the panel.
- **run without a wallet (mock)**: the same flows over the SDK mock
  transport, so you can see the shape of everything with no setup.

## Tests

```sh
npm test
```

## Use it in your own app

Everything the page does is one import:

```js
import { connect } from '@greenarmor/datu-client';
const datu = await connect({ bridgeUrl: 'http://127.0.0.1:7588' });
const { assertion, verified } = await datu.signIn({ name: 'you' });
```

React app? See `sdk/datu-react` for hooks (`DatuProvider`, `useSignIn`).

MIT licensed, same as the rest of DATU.
