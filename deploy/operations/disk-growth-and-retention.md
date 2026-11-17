# Disk growth and retention (readiness item R5)

The ledger is append-only evidence: entries and checkpoints are never
deleted, on purpose. This note gives the sizing model for capacity
planning and the retention rules for the parts that ARE disposable (the
projection layer and other derived data). Nothing here ever removes
ledger evidence; the only ledger-side privacy mechanism is crypto-shredding
of sealed fields (see the sealed-data docs), which is a P5 legal topic,
not a storage one.

## Sizing model (measured 2026-11-17)

Per row, the fixed cost is dominated by the post-quantum signature:

| Component | Bytes (measured average) |
|---|---|
| ML-DSA-65 signature (`pq_signature`) | ~3,309 |
| Ed25519 signature | 64 |
| Entry body (borsh: keys, namespace, payload) | 400 (small `gov.*` record) to ~4,100 (title with sealed fields) |
| Checkpoint body | ~4,070 |
| SQLite row + indexes + WAL slack | ~1.5x the above |

Rules of thumb:

- Small governance records: **~4.5 KiB per entry** of live row data.
- Title-shaped records (sealed fields, party signatures): **~8 KiB per entry**.
- One checkpoint per signer per interval: **~7.5 KiB**; a witness on a
  5-second interval writes ~123 KiB/day, ~45 MiB/year of checkpoints.
- A fresh store carries ~50-100 KiB of schema and page overhead.
- Measured end-to-end (10k-entry soak, one transaction per entry, fresh
  store): **96 MiB on disk, ~9.6 KiB/entry**, i.e. roughly 2.5x the live
  row size from per-commit page overhead; 147 entries/s publish rate,
  full verify clean. Budget with the on-disk number, not the row number.
- Sync lag at that volume (fresh observer pulling 10,001 entries over
  native p2p, paged bloom reconciliation): **2.8 s, ~3.5k entries/s**
  (measured by the sync-lag phase of `deploy/drills/soak.sh`). Catch-up
  after downtime scales with the missing entry count, not store age.

Worked examples (on-disk): 1 million small records ~ 9 GiB; 1 million
title-shaped records ~ 12-16 GiB; a land registry doing 1,000 records/day
grows ~10-15 MiB/day.

Operational variance: long-lived stores accumulate free pages from SQLite
transactions; `du` can overstate live data by 2x or more after heavy
checkpoint churn (observed: two stores with identical logical content at
56 KiB and 456 KiB). A data-dir copy or a bundle import into a fresh
directory is the compaction path (the backup-restore drill exercises it);
there is no in-place shrink, and none is needed for correctness.

## What may be pruned, and how

- **Projections (the indexer's SQL database)**: fully derived and
  rebuildable. Any retention policy the application can tolerate is safe:
  delete rows, drop the database, or run `datu-indexer --reindex` to replay
  the ledger from scratch. Recommended pattern for growing projections is
  a windowed view (recent ordinals) plus `--reindex` rebuilds on schedule,
  not ad-hoc deletes mid-cursor.
- **`rejected` rows in a projection**: operator diagnostics, not evidence.
  Safe to truncate any time.
- **Witness proof files / exported bundles**: regenerable from the store.
  Archive or delete per site policy.
- **Peer tables (`peers.json`)**: cache, not evidence; deleting it only
  costs re-discovery.

## What must never be pruned

- `node.db` entries and checkpoints: the accountability record. If disk is
  the constraint, the answer is a bigger disk or a new node carrying only
  the namespaces that matter (`--namespace` scoped stores), never deletion.
- Sealed-field release entries: they are the crypto-shredding mechanism.

## Monitoring

- Alert on data-dir disk usage at 70% (plan) and 85% (act) of volume.
- The indexer's `/metrics` exposes `entries` and lag; entry count times the
  sizing rules above is the projected footprint.
- After incidents or large imports, compare `du` of the data dir with a
  fresh bundle-import copy to detect freelist bloat.
