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
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON datu_outbox(state, id);
