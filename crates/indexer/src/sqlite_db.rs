//! SQLite dialect (default feature): the zero-ops projection store.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::{status_json, CheckpointRow, EntryRow, ProjectionDb, RejectRow, Seed};

pub struct SqliteDb {
    conn: Connection,
}

impl SqliteDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

impl ProjectionDb for SqliteDb {
    fn ensure_schema(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS entries(
                     id TEXT PRIMARY KEY,
                     author TEXT NOT NULL,
                     namespace TEXT NOT NULL,
                     seq INTEGER NOT NULL,
                     ns_seq INTEGER NOT NULL,
                     ts INTEGER NOT NULL,
                     prev_id TEXT,
                     ord INTEGER NOT NULL,
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
                     seq INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS checkpoints(
                     id TEXT PRIMARY KEY,
                     signer TEXT NOT NULL,
                     height INTEGER NOT NULL,
                     entries_count INTEGER NOT NULL,
                     root TEXT NOT NULL,
                     ts INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS checkpoint_members(
                     checkpoint_id TEXT NOT NULL,
                     entry_id TEXT NOT NULL,
                     PRIMARY KEY(checkpoint_id, entry_id));
                 CREATE TABLE IF NOT EXISTS rejected(
                     id TEXT PRIMARY KEY,
                     author TEXT NOT NULL,
                     namespace TEXT NOT NULL,
                     reason TEXT NOT NULL,
                     at_ms INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS indexer_state(
                     stream TEXT PRIMARY KEY,
                     cursor_ord INTEGER NOT NULL,
                     applied_total INTEGER NOT NULL,
                     checkpoint_height INTEGER NOT NULL,
                     updated_at_ms INTEGER NOT NULL);",
            )
            .map_err(|e| e.to_string())
    }

    fn seed(&mut self) -> Result<Seed, String> {
        let mut seed = Seed::default();
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT cursor_ord, applied_total FROM indexer_state WHERE stream = 'layer1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        if let Some((cursor, applied)) = row {
            seed.cursor = cursor;
            seed.applied_total = applied;
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT author, namespace, MAX(ns_seq) + 1 FROM entries GROUP BY author, namespace",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows {
            let (author, ns, next) = r.map_err(|e| e.to_string())?;
            seed.ns_counts.insert((author, ns), next);
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
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        for e in entries {
            tx.execute(
                "INSERT OR IGNORE INTO entries(id, author, namespace, seq, ns_seq, ts, prev_id, ord, payload, payload_b64)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    e.id, e.author, e.namespace, e.seq, e.ns_seq, e.ts,
                    e.prev_id, e.ord, e.payload, e.payload_b64
                ],
            )
            .map_err(|err| err.to_string())?;
        }
        for (entry_id, ref_id) in refs {
            tx.execute(
                "INSERT OR IGNORE INTO entry_refs(entry_id, ref_id) VALUES (?1, ?2)",
                params![entry_id, ref_id],
            )
            .map_err(|err| err.to_string())?;
        }
        for (author, head, seq) in feeds {
            tx.execute(
                "INSERT INTO feeds(author, head_id, seq) VALUES (?1, ?2, ?3)
                 ON CONFLICT(author) DO UPDATE SET
                   head_id = excluded.head_id, seq = excluded.seq
                 WHERE excluded.seq >= feeds.seq",
                params![author, head, seq],
            )
            .map_err(|err| err.to_string())?;
        }
        for r in rejected {
            tx.execute(
                "INSERT OR IGNORE INTO rejected(id, author, namespace, reason, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![r.id, r.author, r.namespace, r.reason, r.at],
            )
            .map_err(|err| err.to_string())?;
        }
        tx.execute(
            "INSERT INTO indexer_state(stream, cursor_ord, applied_total, checkpoint_height, updated_at_ms)
             VALUES ('layer1', ?1, ?2, 0, ?3)
             ON CONFLICT(stream) DO UPDATE SET
               cursor_ord = excluded.cursor_ord,
               applied_total = excluded.applied_total,
               updated_at_ms = excluded.updated_at_ms",
            params![cursor, applied_total, crate::now_ms()],
        )
        .map_err(|err| err.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    fn upsert_checkpoints(&mut self, checkpoints: &[CheckpointRow]) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        for cp in checkpoints {
            tx.execute(
                "INSERT OR REPLACE INTO checkpoints(id, signer, height, entries_count, root, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    cp.id,
                    cp.signer,
                    cp.height,
                    cp.entries_count,
                    cp.root,
                    cp.ts
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn ordered_entry_ids(&mut self, limit: usize) -> Result<Vec<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM entries ORDER BY ord ASC LIMIT ?1")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())
    }

    fn insert_checkpoint_members(
        &mut self,
        checkpoint_id: &str,
        entry_ids: &[String],
    ) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        for entry_id in entry_ids {
            tx.execute(
                "INSERT OR IGNORE INTO checkpoint_members(checkpoint_id, entry_id) VALUES (?1, ?2)",
                params![checkpoint_id, entry_id],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn save_height(&mut self, height: i64, updated_at_ms: i64) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE indexer_state SET checkpoint_height = ?1, updated_at_ms = ?2 WHERE stream = 'layer1'",
                params![height, updated_at_ms],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn status(&mut self) -> Result<serde_json::Value, String> {
        let (entries, refs, feeds, checkpoints, members, rejected, cursor, applied, height, updated) = self
            .conn
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM entries),
                   (SELECT COUNT(*) FROM entry_refs),
                   (SELECT COUNT(*) FROM feeds),
                   (SELECT COUNT(*) FROM checkpoints),
                   (SELECT COUNT(*) FROM checkpoint_members),
                   (SELECT COUNT(*) FROM rejected),
                   (SELECT COALESCE(cursor_ord, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(applied_total, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(checkpoint_height, 0) FROM indexer_state WHERE stream = 'layer1'),
                   (SELECT COALESCE(updated_at_ms, 0) FROM indexer_state WHERE stream = 'layer1')",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        Ok(status_json(
            entries,
            refs,
            feeds,
            checkpoints,
            members,
            rejected,
            cursor,
            applied,
            height,
            updated,
        ))
    }

    fn reset(&mut self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "DROP TABLE IF EXISTS entries;
                 DROP TABLE IF EXISTS entry_refs;
                 DROP TABLE IF EXISTS feeds;
                 DROP TABLE IF EXISTS checkpoint_members;
                 DROP TABLE IF EXISTS checkpoints;
                 DROP TABLE IF EXISTS rejected;
                 DROP TABLE IF EXISTS indexer_state;",
            )
            .map_err(|e| e.to_string())?;
        self.ensure_schema()
    }
}
