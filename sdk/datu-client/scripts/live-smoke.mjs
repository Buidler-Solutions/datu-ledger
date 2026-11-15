// Live smoke test: the SDK against a running Signet service and node.
// Not part of `npm test` (that suite needs no network); run it by hand:
//
//   datu signet serve --addr 127.0.0.1:7588 --data-dir /tmp/datu-demo
//   datu node --http 127.0.0.1:7574 --data-dir /tmp/datu-demo
//   DATU_PASS=amina-demo node scripts/live-smoke.mjs
//
// Env: DATU_BRIDGE, DATU_NODE, DATU_IDENTITY, DATU_PASS, DATU_ORIGIN.
import { connect, newChallenge, verifyAssertion } from '../src/index.js';

const bridgeUrl = process.env.DATU_BRIDGE || 'http://127.0.0.1:7588';
const nodeUrl = process.env.DATU_NODE || 'http://127.0.0.1:7574';
const identity = process.env.DATU_IDENTITY || 'amina';
const passphrase = process.env.DATU_PASS || 'amina-demo';
const origin = process.env.DATU_ORIGIN || 'http://127.0.0.1:5173';

const token = (
  await (
    await fetch(`${bridgeUrl}/v1/pair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'chrome-extension://live-smoke' },
      body: '{}',
    })
  ).json()
).token;

// Stands in for the extension: same relay, plain HTTP.
const transport = {
  ping: async () => ({ pong: true, version: 'live-smoke' }),
  identities: async () => {
    const res = await fetch(`${bridgeUrl}/v1/wallet/identities`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: '{}',
    });
    return res.json();
  },
  sign: async ({ path, body }) => {
    const res = await fetch(`${bridgeUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
    return { status: res.status, body: json };
  },
  onState: () => () => {},
};

const datu = await connect({ bridgeUrl, nodeUrl, transport });
const ids = await datu.identities();
console.log(`identities: ${ids.map((i) => i.name).join(', ')}`);

const status = await datu.node.status();
console.log(`node: ${status.entries} entries, ${status.checkpoints} checkpoints`);

const { entries } = await datu.node.entries({ limit: 3 });
console.log(`entries read: ${entries.length}`);

const login = await datu.signIn({
  name: identity,
  rpId: new URL(origin).hostname,
  origin,
  passphrase,
});
console.log(`login verified: ${login.verified}, grant: ${Boolean(login.assertion.grant)}`);

const replay = await verifyAssertion(
  login.assertion,
  newChallenge({ rpId: new URL(origin).hostname, origin }),
);
console.log(`replay rejected: ${replay.ok === false}`);

if (login.assertion.grant) {
  const silent = await datu.signIn({
    name: identity,
    rpId: new URL(origin).hostname,
    origin,
    approve: false,
    grant: login.assertion.grant,
  });
  console.log(`grant re-login verified: ${silent.verified}`);
}

if (entries[0]) {
  const coverage = await datu.verifyCoverage(entries[0].id);
  console.log(`coverage: ${coverage.witnesses.length} witness(es), ${coverage.witnesses[0]?.verdict}`);
}

try {
  await datu.signIn({
    name: identity,
    rpId: new URL(origin).hostname,
    origin: 'https://evil.example',
    passphrase,
  });
  console.log('phishing origin: ACCEPTED (bad)');
} catch (e) {
  console.log(`phishing origin refused: ${e.code}`);
}
