# Sealing, retention and GDPR mapping (readiness item P5)

A technical-to-legal map for counsel, not legal advice. It states what
the system can and cannot do, so a DPO can write the deployment's actual
policy against facts. Every claim below is enforced by code paths named
next to it.

## The data model in one paragraph

A DATU ledger is append-only: entries are signed, content-addressed,
and never edited or deleted. Sensitive payload fields can be sealed
(per-field encryption with per-field keys and reader ACLs), so the
ledger holds ciphertext plus signatures, and the plaintext is governed
by who holds the field keys. Crypto-shredding is therefore the erasure
mechanism: destroy (or withhold) the keys and the sealed content becomes
unreadable on every node, while the ledger's integrity trail (hashes,
signatures, timestamps) remains verifiable.

## What the system guarantees (enforced)

- No deletion or edit of ledger entries exists as an operation. A
  "corrected" record is a new entry that references the old one.
- Sealed fields are unreadable without their keys: the read path
  enforces a reader ACL and refuses unlisted readers
  (crates/wallet and the node API seal/read routes).
- Field keys can be scoped per record and per reader; revocation is a
  key-custody act, not a database update (key-custody.md).
- Authorship is attributable: every entry names its author key, keys are
  attested to legal identities on the ledger (`attest` entries).

## GDPR questions this raises, and where the system stands

- Art. 5(1)(e) retention: the ledger itself retains metadata
  indefinitely by design; personal data retention is controlled by
  holding the field keys for the retention period and then destroying
  them. Counsel must decide whether that meets "storage limitation" for
  the deployment.
- Art. 17 erasure: crypto-shredding makes data unreadable but does not
  remove ciphertext or hashes. Whether that satisfies erasure in the
  deployment's jurisdiction is a legal determination; document the
  decision and the rationale in the deployment's DPIA.
- Art. 30 records of processing: deployments must maintain them; the
  ledger helps (every processing act can be an entry) but does not
  replace the register.
- Art. 32 security: hybrid signatures, local verification, and the
  sealing/ACL path are the technical measures; key custody is the
  organizational measure.
- Cross-border transfers: there is no central server; transfers happen
  where keys and data are held. The deployment must document which
  jurisdictions hold field keys.
- Roles: the deployment operator is normally controller; witness and
  mirror node operators act as processors for the history they hold.
  Write the DPAs accordingly (template exists in the compliance pack).

## Known gaps to close before regulated deployments

- `require_sealed` enforcement: the incident runbook (doxxed record)
  notes the gap: nothing yet forces a namespace to accept only sealed
  payloads. Close it with a policy rule before carrying special-category
  data.
- Retention schedules per namespace are policy decisions, not yet
  expressible as rules; today they are operational (key destruction
  schedules).
- For counsel: the crypto-shredding erasure argument, the DPIA template
  for the first deployment, and whether entry metadata (authors,
  timestamps, namespaces) is itself personal data in the deployment
  context.
