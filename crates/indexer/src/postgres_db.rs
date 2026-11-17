//! PostgreSQL dialect (feature "postgres"). Same layer-1 schema, `$n`
//! placeholders and `ON CONFLICT` upserts. Enable with:
//! `cargo build -p datu-indexer --features postgres`

#[cfg(feature = "postgres")]
use crate::{status_json, CheckpointRow, EntryRow, ProjectionDb, RejectRow, Seed};

#[cfg(feature = "postgres")]
pub struct PostgresDb {
    client: postgres::Client,
}

#[cfg(feature = "postgres")]
impl PostgresDb {
    pub fn connect(url: &str) -> Result<Self, String> {
        let client = postgres::Client::connect(url, postgres::NoTls).map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

#[cfg(feature = "postgres")]
impl ProjectionDb for PostgresDb {
    fn ensure_schema(&mut self) -> Result<(), String> {
        self.client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS entries(
                     id TEXT PRIMARY KEY,
                     author TEXT NOT NULL,
                     namespace TEXT NOT NULL,
                     seq BIGINT NOT NULL,
                     ns_seq BIGINT NOT NULL,
                     ts BIGINT NOT NULL,
                     prev_id TEXT,
                     ord BIGINT NOT NULL,
                     payload TEXT,
                     payload_b64 TEXT);
                 CREATE INDEX IF NOT EXISTS idx_entries_ns ON entries(namespace, seq);
                 CREATE INDEX IF NOT EXISTS idx_entries_author ON entries(author, seq);
                 CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(namespace, ts);
                 CREATE TABLE IF NOT EXISTS entry_refs(
                     entry_id TEXT NOT NULL,
                     ref_id TEXT NOT NULL,
                     PRIMARY KEY(entry_id, ref_id));
                 CREATE TABLE IF NOT EXISTS feeds(
                     author TEXT PRIMARY KEY,
                     head_id TEXT NOT NULL,
                     seq BIGINT NOT NULL);
                 CREATE TABLE IF NOT EXISTS checkpoints(
                     id TEXT PRIMARY KEY,
                     signer TEXT NOT NULL,
                     height BIGINT NOT NULL,
                     entries_count BIGINT NOT NULL,
                     root TEXT NOT NULL,
                     ts BIGINT NOT NULL);
                 CREATE TABLE IF NOT EXISTS rejected(
                     id TEXT PRIMARY KEY,
                     author TEXT NOT NULL,
                     namespace TEXT NOT NULL,
                     reason TEXT NOT NULL,
                     at_ms BIGINT NOT NULL);
                 CREATE TABLE IF NOT EXISTS indexer_state(
                     stream TEXT PRIMARY KEY,
                     cursor_ord BIGINT NOT NULL,
                     applied_total BIGINT NOT NULL,
                     checkpoint_height BIGINT NOT NULL,
                     updated_at_ms BIGINT NOT NULL);",
            )
            .map_err(|e| e.to_string())
    }

    fn seed(&mut self) -> Result<Seed, String> {
        let mut seed = Seed::default();
        if let Some(row) = self
            .client
            .query_opt(
                "SELECT cursor_ord, applied_total FROM indexer_state WHERE stream = 'layer1'",
                &[],
            )
            .map_err(|e| e.to_string())?
        {
            seed.cursor = row.get(0);
            seed.applied_total = row.get(1);
        }
        let rows = self
            .client
            .query(
                "SELECT author, namespace, MAX(ns_seq) + 1 FROM entries GROUP BY author, namespace",
                &[],
            )
            .map_err(|e| e.to_string())?;
        for row in rows {
            seed.ns_counts.insert((row.get(0), row.get(1)), row.get(2));
        }
        Ok(seed)
    }

    fn save_batch(
        &mut self,
        entries: &[EntryRow],
        refs: &[(String, String)],
        feeds: &[(String, String, i64)],
        rejected: &[RejectRow],
        cursor: i64,
        applied_total: i64,
    ) -> Result<(), String> {
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        for e in entries {
            tx.execute(
                "INSERT INTO entries(id, author, namespace, seq, ns_seq, ts, prev_id, ord, payload, payload_b64)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &e.id, &e.author, &e.namespace, &e.seq, &e.ns_seq, &e.ts,
                    &e.prev_id, &e.ord, &e.payload, &e.payload_b64,
                ],
            )
            .map_err(|err| err.to_string())?;
        }
        for (entry_id, ref_id) in refs {
            tx.execute(
                "INSERT INTO entry_refs(entry_id, ref_id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[entry_id, ref_id],
            )
            .map_err(|err| err.to_string())?;
        }
        for (author, head, seq) in feeds {
            tx.execute(
                "INSERT INTO feeds(author, head_id, seq) VALUES ($1, $2, $3)
                 ON CONFLICT (author) DO UPDATE SET
                   head_id = excluded.head_id, seq = excluded.seq
                 WHERE excluded.seq >= feeds.seq",
                &[author, head, seq],
            )
            .map_err(|err| err.to_string())?;
        }
        for r in rejected {
            tx.execute(
                "INSERT INTO rejected(id, author, namespace, reason, at_ms)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
                &[&r.id, &r.author, &r.namespace, &r.reason, &r.at],
            )
            .map_err(|err| err.to_string())?;
        }
        tx.execute(
            "INSERT INTO indexer_state(stream, cursor_ord, applied_total, checkpoint_height, updated_at_ms)
             VALUES ('layer1', $1, $2, 0, $3)
             ON CONFLICT (stream) DO UPDATE SET
               cursor_ord = excluded.cursor_ord,
               applied_total = excluded.applied_total,
               updated_at_ms = excluded.updated_at_ms",
            &[&cursor, &applied_total, &crate::now_ms()],
        )
        .map_err(|err| err.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn upsert_checkpoints(&mut self, checkpoints: &[CheckpointRow]) -> Result<(), String> {
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        for cp in checkpoints {
            tx.execute(
                "INSERT INTO checkpoints(id, signer, height, entries_count, root, ts)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (id) DO UPDATE SET
                   signer = excluded.signer, height = excluded.height,
                   entries_count = excluded.entries_count, root = excluded.root,
                   ts = excluded.ts",
                &[
                    &cp.id,
                    &cp.signer,
                    &cp.height,
                    &cp.entries_count,
                    &cp.root,
                    &cp.ts,
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn save_height(&mut self, height: i64, updated_at_ms: i64) -> Result<(), String> {
        self.client
            .execute(
                "UPDATE indexer_state SET checkpoint_height = $1, updated_at_ms = $2 WHERE stream = 'layer1'",
                &[&height, &updated_at_ms],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn status(&mut self) -> Result<serde_json::Value, String> {
        let row = self
            .client
            .query_one(
                "SELECT
                   (SELECT COUNT(*) FROM entries),
                   (SELECT COUNT(*) FROM entry_refs),
                   (SELECT COUNT(*) FROM feeds),
                   (SELECT COUNT(*) FROM checkpoints),
                   (SELECT COUNT(*) FROM rejected),
                   (SELECT COALESCE(cursor_ord, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(applied_total, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(checkpoint_height, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(updated_at_ms, 0) FROM indexer_state WHERE stream = 'layer1')",
                &[],
            )
            .map_err(|e| e.to_string())?;
        Ok(status_json(
            row.get(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
            row.get(5),
            row.get(6),
            row.get(7),
            row.get(8),
        ))
    }

    fn reset(&mut self) -> Result<(), String> {
        self.client
            .batch_execute(
                "DROP TABLE IF EXISTS entries;
                 DROP TABLE IF EXISTS entry_refs;
                 DROP TABLE IF EXISTS feeds;
                 DROP TABLE IF EXISTS checkpoints;
                 DROP TABLE IF EXISTS rejected;
                 DROP TABLE IF EXISTS indexer_state;",
            )
            .map_err(|e| e.to_string())?;
        self.ensure_schema()
    }
}
