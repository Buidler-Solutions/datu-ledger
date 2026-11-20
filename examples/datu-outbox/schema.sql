-- Rung 1: keep your application database, add one outbox table.
-- Written in the same transaction as the business row, drained by worker.py.
CREATE TABLE IF NOT EXISTS datu_outbox(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,              -- e.g. 'land.title.certified'
  namespace TEXT NOT NULL,         -- ledger namespace to publish into
  payload TEXT NOT NULL,           -- JSON payload (seal anything personal)
  entry_id TEXT,                   -- ledger entry id after submission
  state TEXT NOT NULL DEFAULT 'pending',   -- pending | signed | failed
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,     -- audit trail: when it entered the outbox
  updated_at INTEGER NOT NULL,     -- last state change
  created_by TEXT,                 -- actor who enqueued it (staff id, service)
  updated_by TEXT,                 -- actor of the last state change
  deleted_at INTEGER);             -- soft delete: drained rows stay auditable
CREATE INDEX IF NOT EXISTS idx_outbox_state ON datu_outbox(state, id);
