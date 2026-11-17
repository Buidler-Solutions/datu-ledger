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

Seal personal fields before inserting the outbox row; the payload is public
to every mirror.
