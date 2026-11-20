# Outbox: adopt the ledger without changing your data model

Rung 1 of the adoption ladder: your app keeps its database. You add one
table (`schema.sql`) and one worker (`worker.py`). Writes stay transactional:
insert the business row and the outbox row together; the worker signs and
publishes later.

```bash
sqlite3 /var/lib/app/app.db < examples/datu-outbox/schema.sql

python3 examples/datu-outbox/worker.py \
  --db /var/lib/app/app.db \
  --datu ./target/release/datu \
  --data-dir /var/lib/datu/authority \
  --every 5
```

What the worker does: picks the oldest `pending` row, runs
`datu publish --ns <namespace> --payload <json>` with the authority node's
key, writes back `entry_id` and `state='signed'`. Failures increment
`attempts`, keep the row `pending`, then mark it `failed` after
`--max-attempts`. The application never blocks on the ledger.

Signet variant: if signing must go through the extension, replace
`publish()` with a call to the local Signet bridge
(`POST /v1/wallet/sign-entry` + `POST /v1/entries`); the outbox schema and
state machine are unchanged.

Fill `created_at` and `created_by` when enqueuing (when, and who asked).
The worker maintains `updated_at`/`updated_by` on every state change, and
`deleted_at` marks rows kept for the audit trail after they drain - nothing
is ever hard-deleted, because the outbox is evidence too.

Seal personal fields before inserting the outbox row; the payload is public
to every mirror.
