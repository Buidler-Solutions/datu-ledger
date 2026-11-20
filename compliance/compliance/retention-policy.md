# Data Retention Policy - DATU Ledger

## Retention Periods

| Data Category | Retention Period | Justification | Deletion Method |
|---------------|-----------------|---------------|-----------------|
| User accounts | Account lifetime + 30 days | Contract fulfillment | Automated deletion |
| Authentication logs | 90 days | Security monitoring | Automated rotation |
| Audit logs | 1 year | Legal obligation | Automated archival |
| Session data | Session duration | Operational | Automatic expiry |
| Backup data | 90 days | Disaster recovery | Automated rotation |

## Deletion Procedures

1. Automated deletion via scheduled jobs
2. Soft delete with scheduled hard delete
3. Anonymisation where deletion is not feasible
4. Backup exclusion for deleted records

## Review Schedule

- Monthly: Review deletion jobs
- Quarterly: Review retention periods
- Annually: Full retention policy review

---

## DATU specifics (this section governs for the ledger itself)

The generic table above describes operator-side accounts, which DATU does
not have. For the ledger the invariant is different and stronger:

- **Statements are append-only.** Entries are never edited or deleted once a
  mirror holds them. Erasure is expressed as a signed `identity.revoke`
  statement (attestation-level or key-level), which every verifier can see.
- **Personal payloads do not belong on the ledger.** Operators seal fields
  before publishing (Signet field-level encryption, with deferred delivery
  for time-locked releases); sealed rows stay in the operator's database.
- **Local provenance never leaves the node.** The `first_seen` note is a
  local observation: never signed, never synced, never served.
- **Operator retention.** SQLite stores, bundles and projection databases
  follow the operator's own retention schedule; `deploy/operations/disk-growth-and-retention.md`
  documents the growth model and pruning of derived data (projection
  snapshots), not of ledger evidence.
- **Right to erasure.** Handled by design: do not publish personal payloads;
  where one already exists, revoke the statement, seal going forward, and
  document the residual copy on mirrors in the operator's ROPA.
