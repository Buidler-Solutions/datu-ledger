//! MySQL / MariaDB dialect (feature "mysql"). Same layer-1 schema, `?`
//! placeholders and `INSERT ... ON DUPLICATE KEY` upserts. Enable with:
//! `cargo build -p datu-indexer --features mysql`

#[cfg(feature = "mysql")]
use crate::{status_json, CheckpointRow, EntryRow, ProjectionDb, RejectRow, Seed};

#[cfg(feature = "mysql")]
pub struct MysqlDb {
    conn: mysql::PooledConn,
}

#[cfg(feature = "mysql")]
impl MysqlDb {
    pub fn connect(url: &str) -> Result<Self, String> {
        let opts = mysql::Opts::from_url(url).map_err(|e| e.to_string())?;
        let pool = mysql::Pool::new(opts).map_err(|e| e.to_string())?;
        let conn = pool.get_conn().map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
}

#[cfg(feature = "mysql")]
impl ProjectionDb for MysqlDb {
    fn ensure_schema(&mut self) -> Result<(), String> {
        use mysql::prelude::Queryable;
        let ddl = [
            "CREATE TABLE IF NOT EXISTS entries(
                 id VARCHAR(128) PRIMARY KEY,
                 author VARCHAR(255) NOT NULL,
                 namespace VARCHAR(255) NOT NULL,
                 seq BIGINT NOT NULL,
                 ns_seq BIGINT NOT NULL,
                 ts BIGINT NOT NULL,
                 prev_id VARCHAR(128),
                 ord BIGINT NOT NULL,
                 payload LONGTEXT,
                 payload_b64 LONGTEXT)",
            "CREATE INDEX idx_entries_ns ON entries(namespace, seq)",
            "CREATE INDEX idx_entries_author ON entries(author, seq)",
            "CREATE INDEX idx_entries_ts ON entries(namespace, ts)",
            "CREATE TABLE IF NOT EXISTS entry_refs(
                 entry_id VARCHAR(128) NOT NULL,
                 ref_id VARCHAR(128) NOT NULL,
                 PRIMARY KEY(entry_id, ref_id))",
            "CREATE TABLE IF NOT EXISTS feeds(
                 author VARCHAR(255) PRIMARY KEY,
                 head_id VARCHAR(128) NOT NULL,
                 seq BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS checkpoints(
                 id VARCHAR(128) PRIMARY KEY,
                 signer VARCHAR(255) NOT NULL,
                 height BIGINT NOT NULL,
                 entries_count BIGINT NOT NULL,
                 root VARCHAR(128) NOT NULL,
                 ts BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS rejected(
                 id VARCHAR(128) PRIMARY KEY,
                 author VARCHAR(255) NOT NULL,
                 namespace VARCHAR(255) NOT NULL,
                 reason TEXT NOT NULL,
                 at_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS indexer_state(
                 stream VARCHAR(64) PRIMARY KEY,
                 cursor_ord BIGINT NOT NULL,
                 applied_total BIGINT NOT NULL,
                 checkpoint_height BIGINT NOT NULL,
                 updated_at_ms BIGINT NOT NULL)",
        ];
        for stmt in ddl {
            // Index creation is not idempotent on every MySQL version; the
            // statement is only executed when the table was just created.
            let _ = self.conn.query_drop(stmt);
        }
        Ok(())
    }

    fn seed(&mut self) -> Result<Seed, String> {
        use mysql::prelude::Queryable;
        let mut seed = Seed::default();
        if let Ok(Some(row)) = self.conn.query_first::<(Option<i64>, Option<i64>), _>(
            "SELECT cursor_ord, applied_total FROM indexer_state WHERE stream = 'layer1'",
        ) {
            seed.cursor = row.0.unwrap_or(0);
            seed.applied_total = row.1.unwrap_or(0);
        }
        let rows: Vec<(String, String, i64)> = self
            .conn
            .query(
                "SELECT author, namespace, MAX(ns_seq) + 1 FROM entries GROUP BY author, namespace",
            )
            .map_err(|e| e.to_string())?;
        for (author, ns, next) in rows {
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
        use mysql::prelude::Queryable;
        self.conn
            .query_drop("START TRANSACTION")
            .map_err(|e| e.to_string())?;
        let result = (|| -> Result<(), String> {
            for e in entries {
                self.conn
                    .exec_drop(
                        "INSERT IGNORE INTO entries(id, author, namespace, seq, ns_seq, ts, prev_id, ord, payload, payload_b64)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            &e.id, &e.author, &e.namespace, e.seq, e.ns_seq, e.ts,
                            &e.prev_id, e.ord, &e.payload, &e.payload_b64,
                        ),
                    )
                    .map_err(|err| err.to_string())?;
            }
            for (entry_id, ref_id) in refs {
                self.conn
                    .exec_drop(
                        "INSERT IGNORE INTO entry_refs(entry_id, ref_id) VALUES (?, ?)",
                        (entry_id, ref_id),
                    )
                    .map_err(|err| err.to_string())?;
            }
            for (author, head, seq) in feeds {
                self.conn
                    .exec_drop(
                        "INSERT INTO feeds(author, head_id, seq) VALUES (?, ?, ?)
                         ON DUPLICATE KEY UPDATE head_id = VALUES(head_id), seq = VALUES(seq)",
                        (author, head, seq),
                    )
                    .map_err(|err| err.to_string())?;
            }
            for r in rejected {
                self.conn
                    .exec_drop(
                        "INSERT IGNORE INTO rejected(id, author, namespace, reason, at_ms)
                         VALUES (?, ?, ?, ?, ?)",
                        (&r.id, &r.author, &r.namespace, &r.reason, r.at),
                    )
                    .map_err(|err| err.to_string())?;
            }
            self.conn
                .exec_drop(
                    "INSERT INTO indexer_state(stream, cursor_ord, applied_total, checkpoint_height, updated_at_ms)
                     VALUES ('layer1', ?, ?, 0, ?)
                     ON DUPLICATE KEY UPDATE
                       cursor_ord = VALUES(cursor_ord),
                       applied_total = VALUES(applied_total),
                       updated_at_ms = VALUES(updated_at_ms)",
                    (cursor, applied_total, crate::now_ms()),
                )
                .map_err(|err| err.to_string())?;
            Ok(())
        })();
        if result.is_ok() {
            self.conn.query_drop("COMMIT").map_err(|e| e.to_string())?;
        } else {
            let _ = self.conn.query_drop("ROLLBACK");
        }
        result
    }

    fn upsert_checkpoints(&mut self, checkpoints: &[CheckpointRow]) -> Result<(), String> {
        use mysql::prelude::Queryable;
        self.conn
            .query_drop("START TRANSACTION")
            .map_err(|e| e.to_string())?;
        for cp in checkpoints {
            if let Err(e) = self.conn.exec_drop(
                "INSERT INTO checkpoints(id, signer, height, entries_count, root, ts)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                   signer = VALUES(signer), height = VALUES(height),
                   entries_count = VALUES(entries_count), root = VALUES(root),
                   ts = VALUES(ts)",
                (
                    &cp.id,
                    &cp.signer,
                    cp.height,
                    cp.entries_count,
                    &cp.root,
                    cp.ts,
                ),
            ) {
                let _ = self.conn.query_drop("ROLLBACK");
                return Err(e.to_string());
            }
        }
        self.conn.query_drop("COMMIT").map_err(|e| e.to_string())
    }

    fn save_height(&mut self, height: i64, updated_at_ms: i64) -> Result<(), String> {
        use mysql::prelude::Queryable;
        self.conn
            .exec_drop(
                "UPDATE indexer_state SET checkpoint_height = ?, updated_at_ms = ? WHERE stream = 'layer1'",
                (height, updated_at_ms),
            )
            .map_err(|e| e.to_string())
    }

    fn status(&mut self) -> Result<serde_json::Value, String> {
        use mysql::prelude::Queryable;
        let row: Option<(i64, i64, i64, i64, i64, Option<i64>, Option<i64>, Option<i64>, Option<i64>)> =
            self.conn
                .query_first(
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
                )
                .map_err(|e| e.to_string())?;
        let Some((entries, refs, feeds, cps, rejected, cursor, applied, height, updated)) = row
        else {
            return Ok(status_json(0, 0, 0, 0, 0, 0, 0, 0, 0));
        };
        Ok(status_json(
            entries,
            refs,
            feeds,
            cps,
            rejected,
            cursor.unwrap_or(0),
            applied.unwrap_or(0),
            height.unwrap_or(0),
            updated.unwrap_or(0),
        ))
    }

    fn reset(&mut self) -> Result<(), String> {
        use mysql::prelude::Queryable;
        for table in [
            "entries",
            "entry_refs",
            "feeds",
            "checkpoints",
            "rejected",
            "indexer_state",
        ] {
            self.conn
                .query_drop(format!("DROP TABLE IF EXISTS {table}"))
                .map_err(|e| e.to_string())?;
        }
        self.ensure_schema()
    }
}
