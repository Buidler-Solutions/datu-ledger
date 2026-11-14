# @greenarmor/datu-react

React hooks for [DATU](https://github.com/greenarmor/datu-ledger) over
`@greenarmor/datu-client`: a provider that owns the Signet connection,
plus hooks for SignetAuth sign-in, identity listing, party signing and
coverage checks. Build-free plain JS (no JSX step), React 18 and 19.

Keys never leave the Signet extension: every hook routes signing to it.

## Install

```sh
npm install @greenarmor/datu-react @greenarmor/datu-client
```

## Use

```jsx
import { DatuProvider, useDatu, useIdentities, useSignIn } from '@greenarmor/datu-react';

function LoginButton() {
  const { connecting, error } = useDatu();
  const { identities } = useIdentities();
  const { signIn, pending, result } = useSignIn();
  return (
    <button
      disabled={connecting || pending || !identities.length}
      onClick={() => signIn({ name: identities[0].name })}
    >
      {result ? 'Signed in' : 'Sign in with Signet'}
    </button>
  );
}

export default function App() {
  return (
    <DatuProvider options={{ bridgeUrl: 'http://127.0.0.1:7588' }}>
      <LoginButton />
    </DatuProvider>
  );
}
```

`options` are the `connect()` options: `bridgeUrl`, `nodeUrl`, `rpId`,
`origin`, and test doubles (`transport`, `fetchImpl`). Changing the
serializable part of the options reconnects.

## Hooks

| Hook | Returns |
|---|---|
| `useDatu()` | `{ client, connecting, error, extensionState }` |
| `useIdentities({ bridgeUrl? })` | `{ identities, loading, error, reload }` |
| `useSignIn()` | `{ signIn, pending, result, error, reset }`; `result` is `{ assertion, verified, challenge }` |
| `usePartySign()` | `{ partySign, pending, result, error }` |
| `useCoverage(entryId, { enabled? })` | `{ coverage, loading, error, reload }` |

`signIn` rethrows after storing the error, so `await` callers and render
logic both see failures; `result.verified` mirrors the local verification
verdict (`true`, `false`, or `null` when no local verifier exists).

## Tests

```sh
cd sdk/datu-react
npm install --no-save ../datu-client react react-dom jsdom
npm test
```

MIT licensed, same as the rest of DATU.
