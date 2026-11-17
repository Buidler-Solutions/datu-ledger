# Recovery flows (readiness items P1 and P3)

What a person can do when the normal path breaks: forgotten passphrase,
lost device, unavailable WebAuthn. Each flow names the drill that keeps
it honest.

## The invariant

The ledger never depends on any one device or key: history lives on
every node that has synced, and entries verify against public keys. What
is lost with a device is the ability to ACT as that identity, not the
data. Say that to users before they panic.

## Flow 1: forgotten passphrase (Signet vault)

The vault seals private keys under the passphrase. There is no reset by
design; five wrong attempts lock the identity briefly (rate limit, not
data damage).

- Recovery: none for the sealed material itself. If the vault identity
  only signs (not holds funds or titles), create a new vault identity in
  the same data dir, re-attest with the same legal claims
  (`datu attest create --subject <new-key> --claims ...` with a
  `replaces` claim), and publish a takeover note on the old feed if the
  old key is still usable.
- Prevention, told to every user at setup: export the vault backup
  before storing anything that matters; store the passphrase separately
  from the backup; the backup + passphrase together are the identity.
- Drill: the walletd lockout and grant tests
  (`cargo test -p datu-cli walletd`) prove the throttling behavior, and
  `deploy/drills/backup-restore.sh` proves the data survives.

## Flow 2: lost or stolen device

- The ledger: untouched, sync from any peer
  (`datu sync --peer ...` or `datu bundle import`).
- The identity: treat the device as a compromise, not a loss. Run the
  rotation procedure in key-custody.md (new host, new key, history via
  bundle, `attest revoke --key <old>`, re-attest with `replaces`).
- Evidence: revocation entries stay on the ledger forever; the old
  device's entries remain valid history.
- Drill: `deploy/drills/key-rotation.sh` is exactly this flow.

## Flow 3: WebAuthn unavailable (P3 fallback decision)

Some browsers and embedded webviews cannot do platform authenticators.
Decision 2026-11-17: every action that WebAuthn can authorize must also
work through the passphrase Signet vault flow; WebAuthn is an upgrade,
never a requirement.

- The fallback path today: the vault unlock + sign routes
  (passphrase-gated, origin-bound, rate-limited) plus the
  browser-extension bridge. No separate mobile signer.
- If a deployment requires a native mobile signer later, that is a new
  client of the same routes, not a protocol change.

## Flow 4: lost trust-root key

The worst case: the attestor that gates namespaces is gone. It is a
policy problem, not a data problem:

1. Validators edit `policy.json` to list a new attestor (multiple
   attestors are better; deploy them from day one).
2. The new attestor re-attests the writers it recognizes.
3. The old attestor's entries stay valid history; nothing needs
   rewriting.
- Lesson recorded in topology.md: never run a cell with a single
  attestor key on a single machine.
