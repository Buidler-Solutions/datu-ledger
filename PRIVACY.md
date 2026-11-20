# Privacy notice

DATU is a public, append-only accountability ledger. This notice explains,
in plain language, what personal data can end up on it, why, and what you
can do about it. It is the notice for the **software**; each deployment
(registry, cooperative, agency) runs its own node and is the controller for
what it publishes. Version history is the git history of this file.

## The short version

- **Your keys stay on your device.** Private keys are generated in your
  wallet and never leave it. A node only ever holds public keys.
- **The ledger is public and append-only.** Statements are never edited or
  deleted; erasure works by revocation and by not publishing personal data.
- **Personal payloads do not belong on the ledger.** Operators seal fields
  before publishing; sealed content stays in their own database.
- **Consent is a signature, not a checkbox.** You can read back every
  statement you signed with `datu consent` and withdraw by revocation.

## What can appear on the ledger

| Data | Why | Where |
|---|---|---|
| Public keys (Ed25519, ML-DSA-65) | Your identifier; signatures reference it | Entries, attestations, ceremony records |
| Labels and claims (legal name, role, institution) | A registry vouching for who you are | `identity.attest` statements |
| Enrollment and recovery records | Proof that you consented, with your signature | `identity.enroll`, `identity.recover` |
| Records operators publish | Their service (e.g. land titles), sealed where personal | `gov.*` and operator namespaces |
| Checkpoints and signatures | Integrity: who witnessed what, when | Witness streams |

Nothing else. There are no accounts, no passwords, no cookies in the
software, no analytics, no advertising identifiers. A node keeps ordinary
HTTP request logs if its operator configures them; retention is that
operator's policy.

## What never appears on the ledger

- Private keys, passphrases, or wallet contents.
- Sealed documents (encrypted fields; the key half stays with the operator,
  or is released time-locked with deferred delivery).
- The `first_seen` provenance note is a **local observation**: never signed,
  never synced, never served.

## Why we may process it (lawful bases)

The machine-readable register lives in
[`compliance/legal-bases.json`](compliance/legal-bases.json). In summary:

- **Consent (GDPR Art. 6(1)(a), DPA 2012 Sec. 12(a))**: enrollment,
  guardian recovery, and party signatures. The consent record is your
  signature on the specific document, held in the entry itself.
- **Public task or legal obligation (Art. 6(1)(e)/(c))**: a registry
  keeping the registers it is charged with keeping.
- **Legitimate interests (Art. 6(1)(f))**: security and integrity for an
  operator's request logs; local provenance for tamper detection.
- **Contract (Art. 6(1)(b))**: a relying party delivering the service you
  signed in to.

Each operator deployment documents its own basis in its own copy of the
register; the software cannot choose a basis for the operator.

## Your rights, and how they work here

- **Access.** `datu consent` lists every statement you signed; `datu attest
  status --subject <your key>` lists who vouches for your key. Everything is
  also readable over the node's API (`/v1/identity/<key>`, `/v1/entries`).
- **Rectification.** Wrong claims are corrected by a new statement (a fresh
  attestation superseding the old, or a revocation plus re-enrollment),
  never by editing history.
- **Erasure.** Because the ledger is append-only and mirrored, erasure is
  implemented as: a signed revocation (`identity.revoke`) that every
  verifier honours, plus not publishing personal payloads going forward.
  Where a copy already exists on independent mirrors, the operator
  documents it in the records of processing (Art. 17(2) effort note).
- **Restriction and objection.** Ask your operator to stop publishing on
  your behalf; the register entry for their namespace explains the basis.
- **Portability.** `datu bundle export` writes your node's content to a
  file; the format is documented and self-verifying.
- **Complaint.** To your supervisory authority: for the Philippines, the
  National Privacy Commission; in the EU/EEA, your local authority.

## Retention

The ledger itself is kept while any mirror holds it; that is the point of
an accountability ledger. Derived data (projection databases, indexes,
backups) follow the operator's retention schedule, documented in
[`deploy/operations/disk-growth-and-retention.md`](deploy/operations/disk-growth-and-retention.md).

## Contact

- Software questions and reports: the project issue tracker.
- Data about you on a specific node: that node's operator (the party that
  published it); every entry names its author key, and attestations name
  the institution.

## Changes

This notice is versioned with the code. Material changes are recorded in
the compliance documents and announced in release notes.
