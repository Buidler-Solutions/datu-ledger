# Titles: a layer-2 projection example

The pipeline this example demonstrates:

```
datu node (the ledger)  ->  datu-indexer  ->  projection.db  ->  server.py  ->  dApp
```

1. Run one pass over a node's store:

   ```bash
   ./target/release/datu-indexer \
     --data-dir /var/lib/datu/node \
     --db-url sqlite:///var/lib/datu/projection.db --once
   ```

2. Apply the titles view (layer 2):

   ```bash
   sqlite3 /var/lib/datu/projection.db < examples/projection-titles/schema.sql
   ```

3. Serve it read-only (Python stdlib, no dependencies):

   ```bash
   python3 examples/projection-titles/server.py \
     --db /var/lib/datu/projection.db --port 7490
   curl -s 127.0.0.1:7490/healthz
   curl -s "127.0.0.1:7490/titles?limit=5"
   ```

4. A dApp fetches `/titles` like any JSON API. Every row carries
   `ledger_entry_id`; clicking through to `GET /v1/entry/<id>` (node) and
   `GET /v1/coverage/<id>` proves the row against signed evidence.

The same view over PostgreSQL (indexer `--features postgres`):

```sql
CREATE TABLE titles ...
-- or a view:
CREATE VIEW titles AS SELECT id AS ledger_entry_id,
  COALESCE(payload::jsonb ->> 'parcel', '') AS parcel,
  author AS signer, ts AS recorded_at
FROM entries WHERE namespace LIKE 'gov.titles.%';
```

Design rules this example keeps: the projection is rebuildable
(`datu-indexer --reindex` + re-apply SQL), it never invents semantics the
ledger does not carry, and the read API is read-only by construction.
