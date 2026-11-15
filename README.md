# DATU - Decentralized Accountable Trust Union

[![ci](https://github.com/greenarmor/datu-ledger/actions/workflows/ci.yml/badge.svg)](https://github.com/greenarmor/datu-ledger/actions/workflows/ci.yml)

**DATU** - **D**ecentralized **A**ccountable **T**rust **U**nion - is a tokenless,
quantum-resistant accountability ledger: a distributed system for
**accountability and transparency** where:

- **A DAG-type ledger, not a blockchain** - entries link by causal references
  forming a directed acyclic graph; no blocks, no global consensus, no miners
- **Anyone can run a node** - a single static binary, runs on a laptop, Raspberry Pi, or VPS
- **No token, no mining, no staking** - nothing to buy, nothing to speculate on
- **Not internet-dependent** - nodes sync by any channel: LAN, USB stick, Bluetooth, or internet when available
- **Immutable** - records cannot be edited or deleted, ever, provably
- **Quantum-resistant signatures** - every record is hybrid-signed: Ed25519 + ML-DSA-65 (FIPS
  204); sealed *fields* use X25519 today (classical) - a hybrid ML-KEM sealing migration is on
  the roadmap
- **Open to run, gated to write** - anyone runs an observer node freely; official
  namespaces (`gov.*`) admit only attested validators, and the people a record
  is about must sign it themselves

## Guarantees

| Property | How it's enforced |
|---|---|
| Immutability (content) | Entry ID = BLAKE3-256 of canonical bytes; any change breaks the ID, both signatures, and all later links |
| Immutability (storage) | SQLite triggers ABORT every `UPDATE`/`DELETE`; the protocol has no mutation operation |
| Authorship | Every entry is hybrid-signed by its author; both signatures must verify |
| Feed integrity | Per-author hash chain (`seq`, `prev`); rewriting entry N orphans the entire rest of the feed - detected on verify |
| Tamper evidence at scale | Merkle checkpoints signed by nodes; contradictory checkpoints by the same signer are cryptographic fork proof |
| Quantum resistance | ML-DSA-65 (FIPS 204 final) on every entry and checkpoint, alongside Ed25519 |
| Offline operation | Verification is 100% local; sync is file exchange, transport-agnostic |
| Writer gate | Local policy per node: gated namespaces admit only trust roots, explicit writers, or authors attested by a trust root (`--min-cosigners` optional) |
| Citizen consent | Gated documents can require party signatures (`--require-role holder`): the affected person's own hybrid signature over the exact document bytes |
| Predicate contracts | Rules are ledger content in `gov.contracts`: a JSON DSL or a deterministic wasm body, enforced at admission and re-evaluated by anyone with the same pure predicate |
| Membership revocation | Trust roots retire attestations with `identity.revoke` statements; ejection travels the same sync path as admission, and writer gates honor it too |
| Witness time attestation | Coverage proofs pin an entry id into a checkpoint's signed Merkle root: offline-verifiable proof that a witness's ledger held it by a claimed time |
| Deferred delivery | Sealed fields can be made openable only at release: the key half is withheld until the release entry publishes it, sealed to the holder alone |

## Why a DAG, and why no consensus

A typical blockchain and DATU answer different questions. A blockchain is a
**settlement machine**: many writers compete for one canonical chain, so the
network must continuously run consensus - agree on which block sits at each
height, in which order transactions count, and which of two competing forks is
the real one. Consensus is the price of claiming a single, totally ordered
history.

DATU is an **accountability machine**: a provable record of who said, signed,
witnessed, or agreed to what. An entry's validity never depends on its order
relative to other entries, so there is nothing to vote on. DATU needs
**verification, not consensus** - and that difference is structural, not a
missing feature:

1. **Every author is their own chain.** Ordering is per-author and
   deterministic: `seq` + `prev` + a database-level `UNIQUE(author, seq)`
   constraint. There is no shared sequence space, no mempool, no block
   production - nothing to compete over, so nothing to agree on.
2. **Validity is a pure local function.** Each node independently verifies
   both hybrid signatures, the feed chain, and its admission policy. Two
   honest nodes handed the same entries always reach the same verdict; that
   is determinism, not agreement-seeking.
3. **Sync converges on a set, not an order.** Merging DAG histories is set
   union: commutative, order-independent, resumable, and possible over any
   transport. No reorgs, no fork choice, no finality cliff.
4. **Disagreement is evidence, not a fork.** When one author signs two
   different histories at the same `seq`, no vote picks a winner: both sides
   are preserved immutably and surfaced at read time. Misbehavior is made
   cryptographically provable instead of adjudicated by majority.

### What replaces consensus's jobs

| Consensus job in a blockchain | DATU equivalent |
|---|---|
| Finality (block depth) | **Checkpoint coverage**: independent witnesses sign Merkle roots over all entry ids; an entry is progressively settled as more independent checkpoints cover it |
| Rewrite prevention (majority cost) | Append-only stores (immutability triggers), hybrid signatures, and content-addressed ids: rewriting an entry breaks its id, both signatures, and orphans the rest of the feed |
| Misbehavior handling (slashing) | **Fork proof**: contradictory checkpoints by the same signer, or a spliced checkpoint chain, are evidence packages anyone can re-verify with zero other context |
| Validator admission (stake) | Local policy plus on-ledger governance manifests with rotation and revocation: the current authority authorizes the next |

### The honest trade-off

Skipping consensus buys tokenless, permissionless, offline-capable operation,
and it costs three things, stated plainly:

- **No total global order.** There is no answer to "which of two concurrent
  entries by different authors happened first" unless a causal `ref` or a
  witness checkpoint relates them. Timestamps are author claims; provable
  ordering exists only along causal paths.
- **Gradual finality.** Settlement is the widening coverage of independent
  checkpoints, not an instant quorum event.
- **No shared executable state.** DATU is a records and accountability
  ledger, not a smart-contract platform: there is no single agreed world
  state to run logic against.

The closest mental model is **Git plus notarization**, not Bitcoin: Git also
has no consensus, and nobody trusts it less for it. DATU adds per-entry
hybrid signatures, admission policy, cross-author causal links, and witness
checkpoints on top. The governing principle throughout: **records may be
corrected, but history is never silently rewritten.**

## Protocol

### Entry (the DAG node)

```text
EntryBody = {
  version, author (Ed25519 pubkey), author_pq (ML-DSA-65 pubkey), pq_alg,
  namespace,               // e.g. "gov.records", "audit.claims"
  seq,                     // per-author sequence number
  prev,                    // hash of author's previous entry → hash chain
  refs: [entry-id],        // causal links to other entries → DAG edges
  timestamp_ms,            // author's claim (not proof)
  payload                  // opaque bytes, typically JSON (≤256 KiB)
}
Entry = { body, signature: Ed25519(body), pq_signature: ML-DSA-65(body) }
id      = BLAKE3(borsh(body))
```

- **No global consensus is needed.** There is no double-spend problem; concurrent
  statements coexist. Provable ordering exists only along causal paths
  (`prev`/`refs`) - which is exactly what accountability requires.
- Out-of-order delivery is fine: entries whose `prev`/`refs` aren't yet known
  are stored and counted as *pending links*, not errors.

### Checkpoint (tamper evidence)

A node periodically signs:

```text
CheckpointBody = { signer, signer_pq, height, prev, timestamp_ms,
                   entries_count, entry_ids_root: MerkleRoot(all known entry ids) }
```

Checkpoints chain per signer. If a node (or an attacker rewriting its storage)
later serves history that contradicts a checkpoint it previously signed, anyone
holding the old checkpoint can prove it. Checkpoints are tiny - a root is 32
bytes - so they can travel by QR code, radio, or voice.

### Sync (anti-entropy, any transport)

`datu bundle export` produces a self-contained, fully-verifiable file; `import`
verifies every signature and chain before merging anything. Bundles can travel
by USB, LAN copy, email, or anything that moves bytes. Sync is transitive:
A ← USB ← B ← internet ← C converges globally.

### Genesis record (the lineage mark)

The code itself carries a genesis record - a signed `genesis`-namespace entry,
minted once by the founder's dedicated keypair (Ed25519 + ML-DSA-65), whose
payload is the founder's statement. **Every ledger seeded from this code
begins with it**: `Store::open` plants it below the writer policy (policy
gates what peers may land; the genesis is the ledger's own definition), and
it rides every sync, bundle, and delta to any node that ever missed it.

```sh
datu genesis      # verify the record and check this ledger's lineage
```

Nobody - not even a fork - can forge a record claiming this lineage: the
signature, the entry id, and the author key embedded in the code cross-check
on every use. A fork that keeps the constant descends from this lineage; a
fork that mints its own genesis (the minter is `crates/core/examples/
mint_genesis.rs`) walks its own. The founder's private halves live outside
the repo, with the founder.

## Usage

```sh
cargo build --release

datu init                          # create a node (identity + hybrid keys)
datu publish --ns gov.records --payload '{"statement":"..."}'
datu publish --ns audit.claims --ref <entry-id> --payload '{"claim":"..."}'
datu log --ns gov.records
datu get --id <entry-id>
datu verify                        # verify every signature, chain, checkpoint
datu checkpoint                    # sign tamper-evidence over everything seen
datu bundle export --out today.bundle
datu bundle import --input today.bundle
```

### Witnessing and fork proof (citizen audit, Tier 3)

Witnesses (NGOs, press, universities, opposition - anyone) periodically sign
what they have seen and publish the small stream anywhere (email, newspaper,
QR). Citizens compare streams from independent sources:

```sh
datu witness sign                          # sign a checkpoint
 datu witness list                          # every signer's latest root
datu witness export --out witness.cks      # checkpoint-only stream (~KBs)
datu witness import --input witness.cks    # merge another party's stream
datu witness prove --entry <entry-id> --out coverage.json
                                           # time-attestation: this witness
                                           # had seen the entry by its clock
datu witness verify-proof --input coverage.json
                                           # offline check, zero other context

datu prove-fork --a ngo.cks --b ministry.cks --out evidence.json
datu prove-fork --against suspect.bundle   # vs this node's stored history

datu disputes                              # disputes this node holds evidence for
```

**Time attestations.** A checkpoint proves a witness's whole set; a coverage
proof (`witness prove`) pins one entry into it with the Merkle path from the
entry id to the checkpoint's signed root. The pair is self-contained evidence
that the entry existed in that witness's ledger by the checkpoint's claimed
time - no store, no node, no other context needed to verify. That is what
makes landing windows and deadlines *provable* rather than asserted: a
release that claims to land before a closing bound, or an award that must
cite completions stamped before a deadline, can be checked against the
witness clocks that covered it. A single witness is one accountable clock
(author-claimed, attribution permanent); independent witnesses compound.

Verdicts: `NO_CONTRADICTIONS` (exit 0) or `FORK_PROVEN` (exit 2) with an
evidence package containing both contradictory, fully-signed checkpoints -
re-verifiable by anyone with zero other context. Detected evidence kinds:
`same-height-fork` (same signer, same height, different Merkle root - proof
that at least one history is fabricated), `chain-break` (a signer's checkpoint
chain was rewritten or spliced), and `history-mismatch` (a served bundle's
root contradicts a stored witness checkpoint over the same entry count).

**A dispute is preserved, never settled by the protocol.** `datu disputes`
prints every `(author, seq)` collision this node holds evidence for, both
sides, and any resolution records. A resolution is an ordinary entry in
`gov.dispute.*` that `refs` the disputed entry - anyone may publish one
(`datu publish --ns gov.dispute.records --ref <conflicting-id> --payload …`),
and whether it *counts* is a judgement each institution makes for itself. The
ledger only makes the disagreement, and every attempted answer to it,
auditable.

Default node directory is `.datu/` (`--data-dir` to override). It contains:
`secret.key` (Ed25519), `secret.mldsa65` (ML-DSA-65), `node.db` (append-only store),
`wallet/` (identities + index).

## Sign in with your identity (SignetAuth)

A Signet identity is also a login credential: the site issues a one-time
challenge, your wallet signs it, and the site verifies one Ed25519 signature
against your registered public key. No password and no bearer token travel;
the signed bytes are domain-separated (`datu-auth-v1`) so an assertion can
never be replayed as a ledger signature.

```sh
datu signet auth-assert --name amina --rp-id app.example.com   --origin https://app.example.com --nonce <32 hex from the site>   --expires-at-ms <challenge expiry> --out login.json      # wallet side
datu signet auth-verify --rp-id app.example.com --origin https://app.example.com   --nonce <same> --expires-at-ms <same>   --pubkey <identity key> --signature <from login.json>     # relying party side
```

The bridge pins each relying party's origin on first approval, so a phishing
site can never obtain a valid assertion for the real one, and a passphrase
login mints a short-lived in-memory session grant so re-logins do not re-send
it. A device passkey can gate the whole thing behind Touch ID / Windows Hello.
Wire standard and test vector: `specs/signetauth.md`.

## Wallet, dApps, and field-level encryption (Tier 4)

The **wallet is the keychain minus the money**: named identities, each holding an
Ed25519 signing key (authorship), an ML-DSA-65 key (quantum-resistant signature)
and an X25519 sealing key (who can decrypt fields addressed to you). Keystores
are encrypted at rest (Argon2id-stretched passphrase → XChaCha20-Poly1305,
64 MiB / 3 passes; v1 BLAKE3 files still readable). The CLI wallet is the
**reference signer** - the exact JSON contracts a browser-extension or mobile
keychain app would embed. The wallet never needs network access: entries are
self-verifying objects, not messages.

```sh
DATU_WALLET_PASS=... datu wallet create --name bidder     # make an identity
DATU_WALLET_PASS=... datu wallet list                     # name + public keys
DATU_WALLET_PASS=... datu wallet show --name bidder       # publish the seal key
```

### The dApp flow (form with encrypted selected fields)

A web app submits a tender form where `bid_amount` and `tax_id` are encrypted
**to the ministry's seal key**, then the whole document is hybrid-signed and
posted to any node. The entry travels publicly; only the ministry can read the
sealed fields. Every sealed field carries a BLAKE3 commitment so a later
decryption can be *proven* to match what was signed.

```sh
# 1. dApp encrypts selected fields to the reader(s) - one or many seal keys
datu wallet seal --name bidder --to <ministry_seal>,<auditor_seal> \
  --fields bid_amount,tax_id --input form.json --out sealed.json

# 2. dApp fetches the author's chain head and builds a sign request
#    GET /v1/feed/<author> → {"head":…, "next": {"seq":0, "prev":null}}
#    SignRequest = {namespace, seq, prev, refs[], payload_json|payload_base64}

# 3. wallet signs - the only step that touches private keys
DATU_WALLET_PASS=... datu wallet sign --name bidder --request request.json --out entry.json

# 4. submit to any node (no account, no token, no permission needed)
curl -X POST -d @entry.json http://127.0.0.1:7474/v1/entries   # → 201

# 5. the ministry decrypts its fields later (and only its fields)
DATU_WALLET_PASS=... datu wallet open --name ministry --input sealed.json
```

### `datu serve` - node HTTP API + explorer

`datu serve --addr 127.0.0.1:7474` exposes a std-only HTTP API plus a dark-theme
ledger explorer at `/` (entries, search, witnesses, attestations with
revocation tags, disputes - read-only mirror-node view). The entry view surfaces the ledger facts alongside the
record: fresh witness coverage, verified locally (Merkle path against the
checkpoint's signed root, Ed25519 via WebCrypto - the same verifier the
panel uses, served from `/blake3.js` and `/coverage.js`), and any declared
contract's pending/ready verdict with its reasons:

- `GET /v1/status` - node counters, the enforced policy, and (when a manifest
  is pinned) a `manifest` block with `freshness` + the reason for it
- `GET /v1/entries?limit&ns&author` - recent entries
- `GET /v1/entry/{id}` - full entry (payload base64, both signatures)
- `GET /v1/feed/{author}` - head **plus `next`** ({seq, prev}) so dApps build
  correct sign requests without racing the chain
- `GET /v1/checkpoints` - signed tamper-evidence: every witness's latest
  checkpoint (signer, height, entries covered, Merkle root, claimed time)
- `GET /v1/coverage/{entry-id}` (optionally `/{checkpoint-id}`) - witness
  time-attestation over HTTP: for each fresh witness, the checkpoint plus
  the Merkle path that pins this entry into its signed root, in the same
  offline-verifiable shape as `datu witness prove`; `409` with `stale[]`
  reasons when no checkpoint covers the entry right now
- `POST /v1/entries` - submission contract: the node accepts only fully-signed
  entries (Ed25519 + ML-DSA-65 both verified server-side); `201` inserted,
  `200` duplicate (idempotent), `403` denied by this node's writer policy,
  `409` rejected as fork evidence (the losing side is preserved and listed at
  `/v1/conflicts`), `429` over the per-peer submission budget
  (`--submit-per-min`, default 60/min, 0 = off; `Retry-After` header);
  `201`/`200` replies carry `policy_freshness` so a non-current gate is never
  silent
- `GET /v1/conflicts` - recorded feed disputes: both signed sides of every
  `(author, seq)` collision this node has seen (evidence, never resolution);
  each conflict carries `resolutions[]` - any `gov.dispute.*` entry whose
  `refs` name either side - and `null`/empty means the dispute is still open;
  `GET /v1/conflict/{id}` serves the full losing entry; the explorer shows a
  disputes banner + view with open/resolved tags
- `POST /v1/sync/haves` - bloom-filter reconciliation over HTTP
  (`{m, k, bits_b64, cursor, limit}` → `{entries[], cursor, more, checkpoints[]}`;
  the same exchange also runs over raw TCP and over files - see transports);
  `429` over the per-peer sync budget (`--haves-per-min`, default 120/min,
  0 = off; `Retry-After` header) - every page scans the store, so the read
  route is shaped like the write door

A browser-extension wallet implements exactly two JSON contracts:
`SignRequest` in (from the dApp, after checking `GET /v1/feed`), entry-JSON out
(`POST /v1/entries` body). Sealing uses X25519 ECDH (ephemeral sender → each
reader) with XChaCha20-Poly1305 and one shared BLAKE3 commitment per field;
see `datu-sealed-v2` (multi-reader, current write format); legacy `dag-sealed-v2`
and `dag-sealed-v1` blobs stay readable
in `crates/wallet`.

**Deferred delivery.** A field can be sealed *now* and openable *later*:
`datu wallet seal-deferred` encrypts under a fresh content key and splits
the key - one share rides in the ledger object (harmless alone), the other
is kept by the issuer and published only by the release entry, sealed to
the nominated holder (`datu wallet release-deferred` emits exactly that
object). The ledger carries the complete ciphertext from day one, so a
release is a tiny, targeted key act rather than a re-transmission; before
the release the holder is locked out cryptographically, not by policy.
Each deferred field also carries a custody copy of the release half sealed
to the issuer's own seal key: losing the secrets file no longer makes the
field unopenable forever - `datu wallet release-deferred --recover --name
<issuer>` reseals from that copy. `datu wallet open-deferred` (or the
panel's *Open deferred* action, via the bridge route; the desktop FFI
carries the same three actions) recomposes the key, and the per-field
BLAKE3 commitment checks the reveal.
Contract `requires_sealed` demands accept the deferred mark
(`datu-sealed-deferred-v2`) like any other seal.

## Run a node anywhere: transports & the home node (Tier 6)

Entries are self-verifying objects, not messages - so the transport is a
swap-in detail. The same reconciliation (Bloom filter of the ids you have →
peer sends what you lack → verify everything on arrival) runs over four
transports, and **none of them is required**:

| Transport | Command | Use when |
|---|---|---|
| **Native p2p (raw TCP, DATUP2P1)** | `datu sync --peer host:port` | any IP reachability; no web stack at all |
| **HTTP API** | `datu sync --peer http://host:port` | behind a proxy / mixed with dApp traffic |
| **Delta files** | `datu delta make` → `answer` → `merge` | zero network: USB, email, Bluetooth, radio |
| **Full bundles** | `datu bundle export/import` | cold mirror, archival |

Sync is pull-only (run it both ways for bidirectional flow), a Bloom false
positive merely defers an entry to the next sync, and a peer serving
contradictory history aborts with fork evidence instead of merging
(`datu prove-fork` builds the case).

Every transport is bounded on the serving side. Native p2p caps one
connection at 256 pages (each page costs the peer a store scan), answers a
spent budget with a resumable marker instead of an error, and the client
reconnects from its cursor transparently - so a large first sync walks
across connections without failing, and a peer that refuses the budget
without ever serving a page is refused as stalling. The HTTP `haves` route
carries its own per-peer budget (`--haves-per-min`), and the write door its
submission budget (`--submit-per-min`).

### The home node (daemon)

One cheap computer at home runs 24/7 with zero configuration and no central
server - anyone's node is a peer, like running your own daemon:

```sh
datu node                                  # native p2p on 0.0.0.0:7476
datu node --discover --witness             # + find LAN peers (mDNS), witness what it sees
datu node --peer ministry.example:7476 --peer 10.0.0.4:7476 --every 300 \
         --witness --http 127.0.0.1:7474  # + configured peers + optional explorer
```

The daemon announces itself on the LAN (`_dag-sync._tcp`), pulls from
configured and discovered peers each cycle, and signs a witness checkpoint
whenever its view changes - a home computer quietly becomes an independent
witness of everything it has seen. `datu discover` lists the nodes around
you. The HTTP explorer (`--http`) is a convenience frontend for humans and
dApps - node-to-node sync never touches it.

### Offline reconciliation by files

```sh
datu delta make --out req.datureq           # on your laptop, before travel
# ... carry req.datureq to any node by any channel ...
datu delta answer --input req.datureq --out res.datures   # on the peer
# ... carry res.datures back ...
datu delta merge --input res.datures        # verify-then-merge, conflicts = fork evidence
```

## Identity attestations & N-of-M cosigning (Tier 5)

Accounts and logins are replaced by attestations: an institution publishes an
`identity.attest` entry binding claims (legal name, role) to a subject's
Ed25519 key. Others add independent weight by cosigning - a plain
`identity.cosign` entry referencing the attestation id. No registry, no
privilege: anyone can attest, anyone can count cosigners, verifiers choose
their own N-of-M policy.

```sh
datu attest create --subject <ed-pubkey-hex> \
  --claims '{"legal_name":"Acme Ltd","role":"bidder"}' --label "Acme Ltd"
datu sync --peer http://ministry-node:7475      # cosigner must see it first
                                              # (or bare host:port - native p2p)
datu attest cosign --id <attestation-id>        # another node adds weight
datu attest revoke --id <attestation-id>        # a root retires it (append-only)
datu attest status --subject <ed-pubkey-hex>    # attestations + cosigner count
datu attest status --id <attestation-id>        # one attestation in detail
```

Every attestation and cosignature is an ordinary hybrid-signed entry - it
inherits append-only storage, the author's feed chain, checkpoint coverage,
and fork detection for free. Revocation is a new statement, never an edit:
`datu attest revoke` publishes an `identity.revoke` entry naming the
attestation id, with an optional reason for the audit trail. Only
revocations authored by a configured trust root count, and only for the
node whose policy names that root - the ledger records the statement,
verifiers weigh it. A revoke is order-independent (present means revoked,
whenever it syncs), so nodes converge; a later, unrevoked attestation
admits again.

## Three roles: validators, citizens, observers (Tier 7)

Government records need a gate on *who may write* - but the network must stay
free to *run and read*. So there are three roles, and only one of them is
gated:

| Role | Who | Can do | Needs permission to run? |
|---|---|---|---|
| **Validator** (registrar, ministry) | attested institution nodes | write gated namespaces (`gov.*`) | yes - admitted by the local policy of every node that accepts their writes |
| **Citizen / holder** | wallet identities | sign their own transactions; own their data | no - a keypair and a wallet |
| **Observer** | anyone with a computer | run a node, sync, view everything, witness | **never** - no policy file = accepts everything |

The gate is **local node policy** (`<data-dir>/policy.json`), not a global
permission. Each node enforces it on every transport - HTTP submission, p2p
pull, delta merge, bundle import - and it is rooted in the attestation graph
(the same keys that make entries attributable). A rogue writer is simply not
admitted on policy-abiding nodes; no protocol mechanism deletes their entries
- they keep verifying and mirroring among every observer that receives them -
they just never count as official. (Withholding is detectable when
independent replicas or witnesses hold the evidence; propagation itself is
never guaranteed.)

### Validator gate

```sh
datu policy init --attestor <registry-key-hex> --ns 'gov.titles.*' \
  --rule 'gov.titles.*:holder@holder_key'     # default gated: gov.* + identity.attest
datu policy show                               # mode, trust roots, rules
datu policy clear                              # back to a free, open observer
```

Admission to a gated namespace is: the author is a **trust root** or an
**explicit writer**, *or* the author holds an **attestation from a trust
root** (optionally with `--min-cosigners N` independent cosignatures). This is
the procurement story: the registry attests a bidder once; every validator
node that trusts the registry then admits that bidder automatically - the
attestation entry must simply have synced first (bootstrap ordering; a later
sync heals it).

**Per-namespace rules.** `--rule NS:ROLE[@FIELD][=KEY]` (repeatable) adds
party requirements for one namespace pattern only, so a single policy can
demand a `holder` on `gov.titles.*`, a `bidder` on `gov.bids.*`, and pin
`gov.degrees.*:registrar=<registry-key>` - whoever holds the key, nobody else
signs the role. `@FIELD` is **self-binding**: the signing party's key must
equal the value of that document field, so the `holder_key` named inside the
title must be exactly the key that signed as `holder`. Consent cannot be
replayed to another document, role, or person, and tampering after signing
fails the gate.

**Encryption is enforced, not requested.** `--seal-field NS:FIELD` (repeatable)
makes a validator refuse any gated entry that carries that field in plaintext:

```sh
datu policy init --attestor <registry-key> --ns 'gov.titles.*' \
  --rule 'gov.titles.*:holder@holder_key' \
  --seal-field 'gov.titles.*:holder_name' \
  --seal-field 'gov.titles.*:birth_date'
# publishing a title with a plaintext holder_name is denied:
#   policy denied: … requires personal field 'holder_name' to be encrypted
```

A field that is absent is fine (nothing to leak); a present field must be a
`datu-sealed-*` object (legacy `dag-sealed-*` accepted on read). So the holder's name exists in the ledger only as
ciphertext for the registry office and the holder - validators enforce it on
every transport (publish, HTTP submit, p2p pull, delta/bundle merge), and an
open observer that mirrors a plaintext copy still cannot push it into a
validator.

A `--read-only` node (`datu serve --read-only`, `datu node --read-only`) accepts
no new entries at all - a frozen archival view that still serves and witnesses.

### Governance manifests: policy everyone can verify (Tier 7b)

`policy.json` says what *this* node accepts. A **manifest** says what the mesh's
governance *officially is*, as an on-ledger, signed chain anyone can replay
offline - so "registered institution" stops being a claim each operator makes
about a file only they can see:

```sh
datu manifest init --network-id gov-mesh --out mesh.json   # template: this node = first root
datu manifest publish --file mesh.json                     # signs entry #0 of the chain
datu network init --mode permissioned --network-id gov-mesh \
  --member <peer-key> --manifest-root <root-key>            # pin the root, out of band
datu manifest show                                          # chain + compiled policy + provenance
```

The chain is the authority model, nothing else:

- entry **#0** (`supersedes: null`) counts only if authored by a key this node
  **pinned out of band** (`network.json` → `manifest_root`);
- every **later** entry counts only if authored by a key in the *previous*
  manifest's `roots` - **the current authority authorizes the next**;
- rotation = add the new key to `roots`; revocation = omit the old key. Key
  status at signing time is derivable by replaying the chain, so a retired key
  can never speak for the mesh again;
- entries that are junk, name another mesh, or are signed by a non-root key are
  simply never linked. Observers may hold anything; governance comes from
  verifiable linkage only.

**Precedence, and the one way it fails.** When `network.json` pins a
`manifest_root`, the compiled manifest **replaces** `policy.json` (the file is
shadowed, `datu manifest show` says so) and `datu policy show` prints the
manifest provenance. A pin with **no verifiable chain fails closed** - the node
refuses to serve rather than quietly fall back to a local file. Two different
valid continuations of the same manifest (or two pinned-root geneses) are a
**split**: reported as an error, never silently picked - the same
fail-visible-not-fail-silent rule as fork evidence. The current roots are
always admitted as attestors, so governance can always publish the next
manifest; `readonly` is forced off (read-only is an operational flag of a node,
not a governance act).

**Joining a governed mesh takes two steps, in either order.** A pinned node
that has not received the chain yet starts in a *bootstrap* policy: it may
ingest the chain namespace (`gov.mesh.<id>.policy`) and nothing else, so it can
pull governance from a peer or a USB bundle without admitting a single data
entry - then promotes itself to the real manifest the moment the chain
verifies, without a restart. `datu sync`, `datu node`, `datu bundle import`
and `datu delta merge` all run this way; submissions and `datu publish` stay
fail-closed until governance verifies.

**Enforced wherever entries land.** The compiled manifest is the store's
admission policy, so every local write path obeys it - `datu publish`, p2p
`sync`, `datu delta merge`, `datu bundle import`, `datu serve` and `datu node`
alike (a foreign writer's bundle is *skipped by this node's policy*, not merged
and not silently dropped from the report). Two deliberate asymmetries: the
block is never applied to reads - `log`, `get`, `verify`, `status`, `disputes`
keep working while governance is broken, because evidence must stay
inspectable - and `manifest init/publish` plus `network init` may run
*before* a chain exists, so a mesh can be founded at all. Keep `gov.mesh.*`
inside the gated set (the default template's `gov.*` already covers it): the
governance namespace is the one namespace that must not be spammable.

### Is it *current*? Freshness, and verifying without authority

A chain can verify perfectly and still be an old one. So verification and
freshness are reported separately, and neither needs publishing rights:

```sh
datu manifest verify                 # signatures, lineage, authorship, policy version
datu manifest verify --file next.json  # would publishing this extend the chain, and may I sign it?
datu manifest history                # the verified chain, oldest first
datu manifest status                 # freshness + the reason for it
datu manifest conflicts              # competing claims, both sides named
```

| State | Means | Established by |
|---|---|---|
| `current` | this view is corroborated | a verified chain **and** a checkpoint signed by a key that is neither the head manifest's author nor this node, dated at or after it |
| `stale` | freshness cannot be established, or this node is provably behind | no such checkpoint; a held manifest naming a predecessor this node lacks; or a manifest with a policy version this build cannot read |
| `unverified` | nothing verifies here | no genesis from the pinned root, or an unreadable namespace |
| `conflicted` | two *authorized* claims to the same succession | reported, never resolved |

`stale` and `unverified` are **absence of evidence**, stated as such - an
offline node cannot know about a revocation it never received, so it says
*stale*, not *safe*. What that changes:

- recording, syncing, witnessing and publishing all continue under a stale
  policy (offline operation is the point), and every admission says which
  era it happened in (`policy_freshness` in `POST /v1/entries`, `/v1/status`,
  the explorer banner, `datu manifest status`);
- **changing `roots`** - rotation/revocation - is the one act refused on stale
  evidence, because a rotation taken from a stale view can resurrect a retired
  root or bury one this node never learned about. `--accept-stale` overrides it
  deliberately for partition repair, and the result stays reported as stale;
- reads never wait on governance: `log`, `get`, `verify`, `status`, `disputes`,
  `manifest verify/history/status/conflicts` and `attest status` carry no write
  authority. A chainless pinned observer can still read and verify everything.

### Who can read what: reader enclaves

Gating decides *who may write*; sealing decides *who may read*. Sensitive
fields are encrypted once to several reader keys - the registry office and the
holder - while the rest of the record stays public:

```sh
# the document names its own holder and the holder's seal key
# {parcel, district, holder_key, holder_seal, holder_name, birth_date}
DATU_WALLET_PASS=... datu wallet seal --name registrar \
  --to <registry-seal-key> --to-field holder_seal \
  --fields holder_name,birth_date --input title.json --out title.sealed.json

datu parties sign --role registrar --kind land.title.application \
  --input title.sealed.json --out title.reg.json
DATU_WALLET_PASS=... datu wallet cosign-doc --name amina --role holder \
  --input title.reg.json --out title.full.json
datu publish --ns gov.titles.application --file title.full.json

DATU_WALLET_PASS=... datu wallet open --name registrar --input title.full.json  # 2 fields: registry reads all
DATU_WALLET_PASS=... datu wallet open --name amina     --input title.full.json  # 2 fields: holder reads her own
DATU_WALLET_PASS=... datu wallet open --name reporter  --input title.full.json  # 0 fields: everyone else sees commitments only
```

`--to-field` pulls reader keys straight out of the document (a hex string or
an array), so the registrar does not need a separate directory: the record
says who may read it. Sealing happens *before* the party signatures, so the
signatures cover the sealed form - the commitments are tamper-evident, and a
field that was swapped after sealing breaks the digest.

### Citizen consent: party signatures

A record about a person is invalid without that person's signature. The
holder of a title signs the exact document themselves - from their wallet,
with their own keys, not the institution's:

```sh
# 1. the registry prepares and signs the application
datu parties sign --role registrar --kind land.title.application \
  --input title.json --out title.reg.json
# 2. the citizen (holder) consents from their wallet - offline is fine
DATU_WALLET_PASS=... datu wallet cosign-doc --name amina --role holder \
  --input title.reg.json --out title.full.json
# 3. publish; any node verifies every party signature on it
datu publish --ns gov.titles.application --file title.full.json
datu parties show --id <entry-id>
```

A `SignedDocument` binds each signature to `(version, kind, doc, role, key)`,
so a consent cannot be replayed onto a different document, role, or party.
Ed25519 is mandatory; ML-DSA-65 rides along from the wallet, so consent is
quantum-resistant too. Policy decides *whose* signature counts: `--require-role
holder` wants some verified holder; `--rule 'gov.titles.*:holder@holder_key'`
wants **the** holder - the key named inside the document.

### Document contracts: rules as ledger content

Party signatures answer "did the affected people consent?". Contracts answer
"does this document satisfy the rule it claims to follow?" - and the rule
itself is ledger content, content-addressed like everything else. A contract
is a *predicate*, not a program: a pure function over the document and its
direct citations (`refs`, one hop). Nothing executes and nothing mutates, so
evaluation is identical on every node and safe on a no-consensus DAG.
Contracts gate; people act.

A contract spec is a small JSON rule - `admits` (the document kind),
`requires_parties` (verified party roles, with key pins and field binds),
`requires_refs` (cited documents of a kind, optionally with a required
party, a minimum of distinct cosigners, or a pinned entry author: the
authority-feed predicate, where one designated author sequences a feed so
"the authority allocated this" is deterministic), `deadline_from_field`
(citations stamped after it do not count), `not_before_field` /
`not_after_field` (a landing window on the entry's own timestamp;
validator-clock subjective at admission, violations provable later via
witness checkpoints: `datu witness prove` emits the offline-verifiable
coverage proof, and the append-only store rebuilds a checkpoint's exact
signed set from its id prefix, so proofs work against older checkpoints
too, not just the newest), and `requires_sealed` (fields that must be
`datu-sealed-*` ciphertext whenever present). The spec is published as a
party-signed `gov.contract` document into the `gov.contracts` namespace
through the ordinary writer policy, so the entry id *is* the contract's
address. A governed document opts in by naming its rule:

```json
{"parcel": "PH-1", "holder_key": "…", "deadline_ms": 1770000000000,
 "contract": {"id": "<hex contract entry id>", "version": 1}}
```

Validators enforce at admission: a gated-namespace document that declares a
contract is stored only if the contract admits it - kind matches, required
parties verified, required citations present in its `refs` and on time
(citations stamped after the deadline field do not count). Resolution is
fail-closed: the contract entry must be present on this node, in the
contracts namespace, at the pinned version. Open observers mirror everything
and can evaluate the same predicate on demand:

```sh
datu contract new --admits land.title.grant --wasm-file rule.wasm --out spec.json
                                                       # parse-checks the module,
                                                       # base64-encodes it, warns on
                                                       # missing memory/alloc/evaluate
datu publish --ns gov.contracts --file contract.json   # the rule itself
datu contract show --id <contract-entry-id>            # inspect the rule
datu contract show --id <contract-entry-id> --wasm-out rule.wasm
                                                       # extract the module, print its
                                                       # BLAKE3 and export list
datu contract check --id <governed-entry-id>           # condition-by-condition verdict
datu contract status --id <anchor-entry-id>           # pending view (below)
```

`datu verify` recounts contract satisfaction across the whole ledger
(`contracts_failed`) as evidence - what a stricter node would have refused,
or what arrived before the rule did.

### Pending agreements: conditions outstanding

`datu contract status` answers the *pending* question: an anchor document
(an escrow agreement, a reward offer) declares a contract for a **future**
satisfying document. The walker judges the citation-side conditions
against the evidence that exists so far - every stored entry citing the
anchor - and reports `READY` or `OUTSTANDING`, condition by condition, with
the evidence list. Kind, party signatures, window, and seals belong to the
future document itself and are not judged early. The same shape is served
at `GET /v1/contract/status/<anchor-id>` for panels and dApps, which is
how a "pending for me" card renders straight from contract evaluation.

Because contracts are generic predicates over documents and citations,
ecosystem conventions can build on them without new protocol machinery.
One worked example, **document escrow** (data release, not value): a
`datu.cert.escrow` anchor holds the certificate fields sealed to the
registry, names the `holder_key`/`agent_key`, deadline, and its contract;
compliance entries (payment proof, inspection) cite the anchor; the
`datu.cert.release` cites the compliance set, is agent-signed per the
contract's party bind, and re-seals the certificate to the holder's seal
key. Release is not unlocking - the reader ACL is baked into ciphertext,
so a release is a new targeted encryption act (or, with deferred delivery,
the publication of one withheld key share): attributable, refs-linked,
condition-bound. The holder watches the anchor go OUTSTANDING to READY
without ever reading a certificate field. Other conventions fall out the
same way: one-award-per-parcel rewards, conditional registries. A tool for
whoever needs it - documents that declare no contract are untouched.

### WASM contract bodies: arbitrary predicates, same safety

When the JSON DSL is not expressive enough, the same contract entry can
carry a deterministic wasm32 module instead of the requirement fields:
`"wasm": "<base64 module>"`. The entry shape, resolution, admission
gate, and reporting are unchanged - only the predicate engine differs.
`admits` is still checked outside the sandbox (fast fail), then the
module decides alone. Determinism is what makes this safe on a
no-consensus DAG: same module bytes plus same input bytes means the same
verdict on every node, forever. The sandbox rules:

- **Empty linker.** The module is instantiated with zero host functions:
  no clock, no disk, no network, no randomness, no node state. Its whole
  world is the JSON written into its linear memory: `admits`, the
  governed `document` (parties and all), `entry_ts`, and the `closure`
  - exactly what the DSL branch sees, nothing more.
- **Fuel metering replaces gas.** Every evaluation runs with a fixed
  fuel budget; exhaustion traps into a fail-closed denial. There is no
  token and no fee market: metering is a safety cap, not a price.
- **Size caps.** 256 KiB for the module, 512 KiB for the serialized
  input. A closure too large to judge is a denial, not an error.
- **Fail-closed everywhere.** Bad base64, unparseable wasm, missing
  exports, traps, out-of-range returns: every failure path is a normal
  denial with a reason. A hostile rule can at worst deny documents; it
  can never crash a node or admit by accident.

The guest ABI is three exports: `memory` (linear memory), `alloc(size)
-> ptr`, and `evaluate(in_ptr, in_len, out_ptr, out_cap) -> written`,
where returning `0` admits and any other value denies with the reason
bytes written to `out_ptr`. `datu contract check` reports the fuel each
verdict consumed against the cap: metering is reported, never priced. Any wasm32 toolchain works (Rust, C,
AssemblyScript, or hand-written WAT). `datu contract show` elides the
base64 blob instead of dumping it, `datu contract check` executes the
rule with a per-condition `wasm` line carrying the guest's own denial
words, and because a wasm rule cannot be decomposed into pending
citation-side conditions, `datu contract status` reports the honest
answer: readiness arrives with the satisfying document.

## Network modes: who may join and sync

`policy.json` gates whose **entries land** (write admission). `network.json`
decides who may **join** - sync, pull, and share in this node's mesh - a
separate, orthogonal gate at the transport layer:

| `network.json` | Meaning | Who syncs with this node |
|---|---|---|
| *(absent)* | the open network - today's behavior, zero migration | anyone (old peers keep working) |
| `permissionless` + `network_id: "gov-mesh"` | a dedicated free observer of one walled mesh | any peer presenting the same mesh id |
| `permissioned` + `network_id` + `members`/`roots` | a walled, membership-gated mesh | member keys and keys attested on-ledger by a configured root |

```sh
datu network init --mode permissioned --network-id gov-mesh \
  --member <peer-node-key-hex> --root <own-key-hex>
datu network show
datu network clear          # back to the open network
```

`--manifest-root <key-hex>` additionally pins the mesh's governance manifest
chain (`gov.mesh.<network-id>.policy`), which then supplies the writer policy -
see *Governance manifests* above.

**Joining = membership that propagates by the sync it authorizes.** A peer is
admitted with an explicit `members` key *or* any on-ledger attestation
(`identity.attest`) from a configured `roots` trust root - the same
attestation graph that admits writers. A root attests a new node once; every
member that syncs the attestation admits the node automatically. No signed
manifest to re-issue, no operator round-trip to add a peer.

**Leaving = the same ledger.** Ejection is server-side too: `datu attest
revoke --id <attestation-id>` publishes an `identity.revoke` statement by
a trust root, and every node whose `roots` name that root stops admitting
the key the moment the revoke syncs. A key with no attestation to name -
an explicit `members` or `writers` entry - is ejected with `datu attest
revoke --key <subject-key>`, and the ledger outranks the membership list:
the revoked key is refused even while a `network.json` still lists it, and
the writer gate denies it too. Membership revocation therefore rides the
exact transport that carried the admission, and works offline, over HTTP
pull, and across the mesh alike.

**The mesh wall is mutual and everywhere.** Bundles, witness streams, haves
requests and delta responses carry the mesh id; a node refuses foreign ones
in both directions (set vs empty, set vs different). The walled mesh and the
open network can never merge through any transport - p2p, HTTP pull, or
offline files. HTTP *reads* stay public.

**On the wire**, a walled node must learn who is dialing: clients open with a
signed `NodeHello` (fresh Ed25519 signature, ±300 s clock-skew window, no
state kept). Walled servers answer plain old clients with a self-explaining
`hello required` error; open servers need no hello - pre-network-mode peers
interoperate unchanged. A permissioned node whose own key is not a member or
root refuses to start (fail-closed) rather than run isolated.

## Web: registrar dApp + landowner wallet (Tier 8)

Two browser-facing pieces sit on top of the same protocol - no new trust
anchors, no accounts:

- **`web/registrar`** - Vite + React land-title form: fills the application,
  seals personal fields (or defers them to the holder with the *defer until
  release* option, which hands the registrar a release-secrets download
  instead of readable ciphertext), gets the registrar's consent signature,
  collects the landowner's consent, and submits the signed entry to a
  validator node. The registry workspace also carries the release step:
  load a deferred document plus its release-secrets file and the dApp
  produces the share object a release entry publishes plus a release-entry
  skeleton carrying it, and drafts contract specs (JSON DSL or a wasm
  module read and base64-encoded in the browser) (no signature needed - releasing is a ledger act),
  closing the deferred loop without the CLI. After recording a title the
  registry workspace also reports how many fresh witness checkpoints cover
  the new entry, and says plainly that it is the node's report: re-verify
  with `datu witness verify-proof` or the panel's Witnessed view.
- **`web/wallet-extension`** - the citizen's wallet as a **Chrome side panel**
  (MetaMask-style: click the toolbar icon, the panel slides in on the right).
  It is **namespace-agnostic**: land titles, driver licences, procurement
  bids, permits - any gated namespace. It finds every record that concerns
  you (a party signature is yours, or the document names your key in any
  field such as `holder_key`, `licensee_key`, `bidder_key`), verifies
  signatures locally from any node, and decrypts only the fields sealed to
  you. Before signing it enforces the same self-binding rule as the
  validators: `<role>_key` in the document must be your key. Panel v1.4.x
  also surfaces the newer ledger facts: attestation records show a
  `REVOKED by …` badge when a trusted `identity.revoke` statement names
  them, deferred-delivery fields are marked as waiting for their release,
  with an *Open deferred* action that takes the release object and opens
  the field in place through the bridge, and every record gets a
  *Witnessed* view that lists the fresh witness checkpoints covering it
  (signer, claimed time, served proof), backed by `/v1/coverage` - and
  verifies them locally: the panel re-computes the Merkle path with its own
  BLAKE3 and re-checks the checkpoint's Ed25519 signature via WebCrypto, so
  the node only relays witnesses, it cannot misattribute one.
- **One wallet per person, several identities per wallet** for context
  (`alice-home`, `alice-business`). The panel keeps a **wallet profile list**
  (label + bridge URL) and switches between local bridges; pairing tokens
  live in `chrome.storage.session` only. Identities move between wallets and
  devices as **encrypted backups**: `datu wallet export/import` (CLI) or the
  panel's *Backup & move devices* section - the backup uses a separate backup
  passphrase, is re-verified against its own public keys on import, and the
  restored identity unlocks with that backup passphrase.

Both talk to **`datu wallet serve`**, a local bridge (default
`127.0.0.1:7482`) that owns the keystore and performs all signing and sealing:

```
POST /v1/wallet/create             {name, passphrase}
GET  /v1/wallet/identities         public identities (ed + seal keys)
POST /v1/wallet/party-sign         {name, passphrase, role, document, kind?}
POST /v1/wallet/seal               {name, passphrase, document, fields, to[], to_fields[]}
POST /v1/wallet/seal-deferred      {name, passphrase, document, fields, to/to_fields}
POST /v1/wallet/release-deferred   {document, field, release}   → the share object
POST /v1/wallet/open               {name, passphrase, document}
POST /v1/wallet/deferred-open      {name, passphrase, document, field, release}
                                   (alias: open-deferred)
POST /v1/wallet/export             {name, passphrase, backup_passphrase}
POST /v1/wallet/import             {input, backup_passphrase, rename?}
POST /v1/wallet/verify-entry       {entry}  → verify both hybrid signatures locally
POST /v1/wallet/sign-entry         {name, passphrase, request}
```

The route names and response shapes mirror the desktop FFI's action grammar,
so a front end can swap transports without changing screens.

The wallet reads from **any** node - a validator or a free observer - and
verifies each record itself with `verify-entry`, so the serving node is never
trusted: point the extension at an observer, find the titles that name you as
holder, verify the signatures, and decrypt the fields sealed to you. A node
that lies or tampers is caught locally with
`400 signature verification failed`.

```sh
datu wallet serve --addr 127.0.0.1:7482      # keys never leave this process
cd web/registrar && npm install && npm run dev
# chrome://extensions → Developer mode → "Load unpacked" → web/wallet-extension
#   then click the toolbar icon: the wallet slides in as a side panel
#   the extension pairs itself automatically (Settings is only a legacy fallback)
```

The bridge is **paired**, not open: every `/v1` call needs
`Authorization: Bearer <token>` (256-bit, compared in constant time), and
browser extensions each get their **own token from `POST /v1/pair`, bound to
the exact `chrome-extension://<id>` Origin that asked for it** (Chromium
attaches that true Origin to every extension POST and forbids forging it,
while extension GETs carry no Origin at all, hence POST), so a token that
leaks to or is pasted into a different extension is refused. Pair records
live in `wallet/bridge.pairs.json` (0600); the shared `wallet/bridge.token`
still works for local tools that send no browser Origin. Browser
origins are restricted to extension pages plus explicit `--allow-origin`
values, and five wrong passphrases lock that identity for 15 s (429). The
extension (`v1.0.0`) ships icons, a strict CSP, two-step
**review → confirm** before signing, and auto-clears passphrase and decrypted
views after 2 minutes idle; the token itself lives only in
`chrome.storage.session` and is forgotten when the browser closes.

Flow: the registrar seals `holder_name`/`birth_date` to the registry office
and to the landowner's seal key found in the document, signs as `registrar`,
then hands the document to the landowner; the landowner signs as `holder` in
the extension; the dApp authors the entry with the registry's signer identity
and POSTs it. Validators check author admission, party self-binding, and the
sealed-field rule; the private data never appears in plaintext in the ledger,
and third parties can read only the commitments.

## Threat model

**Prevented:** undetected modification or deletion of any record; forged
authorship; feed rewrites (same author+seq with different content is rejected
as fork evidence - and the losing side is preserved, listed at
`/v1/conflicts`); contradictory checkpoints from the same signer.

**Detected, not prevented:** a node deleting its own data (detectable by anyone
who replicated it or holds its checkpoints - that's what replication and
checkpoint gossip are for); total network partition (physics; data flows only
where contacts exist).

**Inherent limits:** timestamps are author claims; there is no global total
order, only causal order. This is the deliberate trade for permissionless,
tokenless, offline-capable operation.

## SDK for dApps

`sdk/datu-client` (published as `@greenarmor/datu-client`) wraps the whole integration
surface: SignetAuth login in one call, party signatures, sealing and deferred
delivery, node reads, coverage verification, typed errors, TypeScript
declarations, and mock transports so a dApp's tests need no wallet.

```js
import { connect } from '@greenarmor/datu-client';
const datu = await connect({ bridgeUrl: 'http://127.0.0.1:7588', nodeUrl: 'http://127.0.0.1:7474' });
const { assertion, verified } = await datu.signIn({ name: 'amina', rpId: 'app.example.com' });
```

## Layout

- `crates/core` - entries, hash chains, Merkle set-roots, checkpoints, hybrid
  crypto, bloom filters, attestation/cosign helpers, party signatures,
  document contracts (predicate specs)
- `crates/store` - append-only storage (immutability triggers), writer policy
  gate, contract admission + evaluation + pending-status walker, bundles,
  delta files, reconciliation pages, full verification
- `crates/p2p` - DATUP2P1: the native node-to-node sync protocol over raw TCP
- `crates/wallet` - keychain identities (Argon2id), reference signer,
  party consent signing, multi-reader field sealing (`datu-sealed-v2`; reads
  legacy `dag-sealed-v2` and `dag-sealed-v1`)
- `crates/cli` - the `datu` binary (node daemon, p2p + mDNS discovery, serve,
  sync, delta, attest, policy, parties, contract, wallet, witness, prove-fork)

## Roadmap

1. NAT traversal helpers (port-forward guides / relay peers) so home nodes
   can dial each other across the internet without a fixed IP
2. Optional anchoring of checkpoints to Bitcoin (Open Timestamps)
3. Compact checkpoint encoding for QR / radio broadcast
4. HPKE sealing + post-quantum KEM (ML-KEM) for long-term field confidentiality
5. Browser-side ML-DSA-65 verification (today the panel and explorer verify
   Ed25519 and the Merkle path; the CLI checks both signatures)
6. Windows builds (the crate should compile; it is untested there)
7. hello nonces/epoch replay hardening on the native p2p door

Shipped since the last revision of this list: cosigner-aware admission and
per-namespace role rules, ledger-carried revocation (`identity.revoke`, both
attestation-level and key-level), deferred delivery with custody recovery,
and witness coverage proofs with local verification in the UIs.

## License

MIT, see `LICENSE`. There is no warranty: this is accountability software,
not a guarantee of any institution's behaviour.
