//! Optional projection layer for DATU ledgers.
//!
//! The ledger is the evidence: signed, append-only entries. Asking it
//! application-shaped questions (joins, aggregates, search) directly is
//! possible but slow, so an app may run this indexer beside its node: it
//! follows the store's insertion cursor, verifies what it reads, and
//! projects the facts into an ordinary SQL database. The projection is
//! derived and disposable - drop it and replay the ledger, same result.
//!
//! Database flexibility: the engine is database-agnostic. A small
//! [`ProjectionDb`] trait carries the dialect-specific pieces; SQLite is
//! built in (default feature), PostgreSQL and MySQL are behind the
//! `postgres` / `mysql` cargo features. Select with `--db-url`:
//!
//!   sqlite:///var/lib/datu/projection.db
//!   postgres://user:pass@host/db     (feature postgres)
//!   mysql://user:pass@host/db        (feature mysql)

use std::collections::HashMap;
use std::path::Path;

use datu_store::Store;

pub mod mysql_db;
pub mod postgres_db;
pub mod sqlite_db;

#[cfg(feature = "mysql")]
pub use mysql_db::MysqlDb;
#[cfg(feature = "postgres")]
pub use postgres_db::PostgresDb;
pub use sqlite_db::SqliteDb;

/// What to check before a row is projected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Verify every entry's Ed25519 + ML-DSA signatures.
    Signatures,
    /// Trust the local store (only sensible when the node is yours).
    None,
}

impl VerifyMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "signatures" | "" => Ok(Self::Signatures),
            "none" => Ok(Self::None),
            other => Err(format!("unknown verify mode '{other}' (signatures|none)")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IndexerConfig {
    /// Directory of the node whose store is followed (read-only use).
    pub node_dir: std::path::PathBuf,
    /// Namespace allowlist patterns (empty = everything).
    pub namespaces: Vec<String>,
    pub verify: VerifyMode,
    /// Entries per transaction.
    pub batch: usize,
}

impl IndexerConfig {
    pub fn new(node_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            node_dir: node_dir.into(),
            namespaces: Vec::new(),
            verify: VerifyMode::Signatures,
            batch: 500,
        }
    }
}

/// One projected entry row (dialect-neutral).
#[derive(Clone, Debug, Default)]
pub struct EntryRow {
    pub id: String,
    pub author: String,
    pub namespace: String,
    pub seq: i64,
    pub ns_seq: i64,
    pub ts: i64,
    pub prev_id: Option<String>,
    pub ord: i64,
    pub payload: Option<String>,
    pub payload_b64: String,
}

/// An entry that failed verification (or hashing), kept for operators.
#[derive(Clone, Debug, Default)]
pub struct RejectRow {
    pub id: String,
    pub author: String,
    pub namespace: String,
    pub reason: String,
    pub at: i64,
}

/// One checkpoint row.
#[derive(Clone, Debug, Default)]
pub struct CheckpointRow {
    pub id: String,
    pub signer: String,
    pub height: i64,
    pub entries_count: i64,
    pub root: String,
    pub ts: i64,
}

/// Seed state loaded before a pass: cursor, totals, and the per (author,
/// namespace) counters the engine increments to derive `ns_seq` without a
/// database round trip per row.
#[derive(Clone, Debug, Default)]
pub struct Seed {
    pub cursor: i64,
    pub applied_total: i64,
    pub ns_counts: HashMap<(String, String), i64>,
}

/// One pass over the store: stats the CLI prints and the health view shows.
#[derive(Clone, Debug, Default)]
pub struct PassStats {
    pub applied: u64,
    pub filtered: u64,
    pub rejected: u64,
    pub cursor: String,
    pub checkpoint_height: u64,
    /// checkpoint -> entry membership rows written this pass
    pub members: u64,
    /// checkpoints whose covered set this node cannot reconstruct
    pub gaps: u64,
}

/// The dialect seam. Coarse-grained on purpose: one batch per transaction,
/// so each database can use its own batching idioms.
pub trait ProjectionDb {
    fn ensure_schema(&mut self) -> Result<(), String>;
    /// Current cursor, applied total, and per-namespace counters.
    fn seed(&mut self) -> Result<Seed, String>;
    /// Apply one batch atomically: entries, refs, feed heads, rejects, and
    /// the new cursor.
    fn save_batch(
        &mut self,
        entries: &[EntryRow],
        refs: &[(String, String)],
        feeds: &[(String, String, i64)],
        rejected: &[RejectRow],
        cursor: i64,
        applied_total: i64,
    ) -> Result<(), String>;
    fn upsert_checkpoints(&mut self, checkpoints: &[CheckpointRow]) -> Result<(), String>;
    /// The first `limit` projected entry ids in insertion order (the set a
    /// checkpoint with `entries_count = limit` covers, when roots match).
    fn ordered_entry_ids(&mut self, limit: usize) -> Result<Vec<String>, String>;
    /// Record which entries a checkpoint covers.
    fn insert_checkpoint_members(
        &mut self,
        checkpoint_id: &str,
        entry_ids: &[String],
    ) -> Result<(), String>;
    fn save_height(&mut self, height: i64, updated_at_ms: i64) -> Result<(), String>;
    fn status(&mut self) -> Result<serde_json::Value, String>;
    fn reset(&mut self) -> Result<(), String>;
}

/// Open a projection database from a URL:
/// `sqlite:///path`, `postgres://...`, `mysql://...`, or a bare path
/// (treated as SQLite, for backwards compatibility).
pub fn open(db_url: &str) -> Result<Box<dyn ProjectionDb>, String> {
    let url = db_url.trim();
    if let Some(path) = url.strip_prefix("sqlite://") {
        return Ok(Box::new(SqliteDb::open(Path::new(path))?));
    }
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        {
            return Ok(Box::new(PostgresDb::connect(url)?));
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = url;
            return Err(
                "this build has no PostgreSQL support; rebuild with --features postgres".into(),
            );
        }
    }
    if url.starts_with("mysql://") {
        #[cfg(feature = "mysql")]
        {
            return Ok(Box::new(MysqlDb::connect(url)?));
        }
        #[cfg(not(feature = "mysql"))]
        {
            let _ = url;
            return Err("this build has no MySQL support; rebuild with --features mysql".into());
        }
    }
    Ok(Box::new(SqliteDb::open(Path::new(url))?))
}

/// Pattern match: exact, or a trailing `*` wildcard (the policy engine's
/// rule for gated namespaces).
fn ns_matches(pattern: &str, namespace: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => namespace.starts_with(prefix),
        None => pattern == namespace,
    }
}

fn wanted(cfg: &IndexerConfig, namespace: &str) -> bool {
    cfg.namespaces.is_empty()
        || cfg
            .namespaces
            .iter()
            .any(|pattern| ns_matches(pattern, namespace))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Follow the store once: verify and apply every unprojected entry, then
/// refresh the checkpoint list. The cursor is durable across crashes.
pub fn run_once(db: &mut dyn ProjectionDb, cfg: &IndexerConfig) -> Result<PassStats, String> {
    db.ensure_schema()?;
    let store = Store::open(&cfg.node_dir.join("node.db")).map_err(|e| e.to_string())?;

    let mut seed = db.seed()?;
    let mut stats = PassStats::default();
    let mut cursor = seed.cursor;

    loop {
        let batch = store
            .entries_after(cursor, cfg.batch)
            .map_err(|e| e.to_string())?;
        if batch.is_empty() {
            break;
        }
        let mut rows: Vec<EntryRow> = Vec::new();
        let mut refs: Vec<(String, String)> = Vec::new();
        let mut rejected: Vec<RejectRow> = Vec::new();
        let mut feeds: HashMap<String, (String, i64)> = HashMap::new();

        for (ord, entry) in &batch {
            let ns = entry.body.namespace.clone();
            if !wanted(cfg, &ns) {
                stats.filtered += 1;
                cursor = *ord;
                continue;
            }
            let id = match entry.id() {
                Ok(id) => hex::encode(id),
                Err(e) => {
                    rejected.push(RejectRow {
                        id: format!("unhashed:{ord}"),
                        author: entry.body.author.clone(),
                        namespace: ns,
                        reason: format!("id: {e}"),
                        at: now_ms(),
                    });
                    stats.rejected += 1;
                    cursor = *ord;
                    continue;
                }
            };
            if cfg.verify == VerifyMode::Signatures {
                if let Err(e) = entry.verify() {
                    rejected.push(RejectRow {
                        id,
                        author: entry.body.author.clone(),
                        namespace: ns,
                        reason: e.to_string(),
                        at: now_ms(),
                    });
                    stats.rejected += 1;
                    cursor = *ord;
                    continue;
                }
            }
            let key = (entry.body.author.clone(), ns.clone());
            let counter = seed.ns_counts.entry(key).or_insert(0);
            let ns_seq = *counter;
            *counter += 1;

            let payload = String::from_utf8(entry.body.payload.clone()).ok();
            rows.push(EntryRow {
                id: id.clone(),
                author: entry.body.author.clone(),
                namespace: ns.clone(),
                seq: entry.body.seq as i64,
                ns_seq,
                ts: entry.body.timestamp_ms as i64,
                prev_id: entry.body.prev.map(hex::encode),
                ord: *ord,
                payload,
                payload_b64: base64_of(&entry.body.payload),
            });
            for r in &entry.body.refs {
                refs.push((id.clone(), hex::encode(r)));
            }
            let head = feeds
                .entry(entry.body.author.clone())
                .or_insert_with(|| (id.clone(), entry.body.seq as i64));
            if entry.body.seq as i64 >= head.1 {
                *head = (id.clone(), entry.body.seq as i64);
            }
            stats.applied += 1;
            cursor = *ord;
        }

        seed.applied_total += stats.applied as i64;
        let feed_rows: Vec<(String, String, i64)> = feeds
            .into_iter()
            .map(|(a, (head, seq))| (a, head, seq))
            .collect();
        db.save_batch(
            &rows,
            &refs,
            &feed_rows,
            &rejected,
            cursor,
            seed.applied_total,
        )?;
        if batch.len() < cfg.batch {
            break;
        }
    }

    // Checkpoints make "as of when" answerable in the projection.
    let checkpoints = store.all_checkpoints().map_err(|e| e.to_string())?;
    let mut height = 0u64;
    let mut cp_rows: Vec<CheckpointRow> = Vec::new();
    for cp in &checkpoints {
        let id = cp.id().map_err(|e| e.to_string())?;
        if cp.body.height > height {
            height = cp.body.height;
        }
        cp_rows.push(CheckpointRow {
            id: hex::encode(id),
            signer: cp.body.signer.clone(),
            height: cp.body.height as i64,
            entries_count: cp.body.entries_count as i64,
            root: hex::encode(cp.body.entry_ids_root),
            ts: cp.body.timestamp_ms as i64,
        });
    }
    db.upsert_checkpoints(&cp_rows)?;

    // Membership: a checkpoint's set is the first `entries_count` ids in
    // insertion order. Recompute the Merkle root; a match proves this node
    // holds exactly the covered set, so (checkpoint, entry) rows are safe.
    for cp in &cp_rows {
        let count = cp.entries_count as usize;
        let ids = db.ordered_entry_ids(count)?;
        if ids.len() < count {
            stats.gaps += 1;
            continue;
        }
        let mut decoded: Vec<[u8; 32]> = Vec::with_capacity(count);
        let mut ok = true;
        for id in &ids {
            match hex::decode(id)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(bytes) => decoded.push(bytes),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok || hex::encode(datu_core::merkle::merkle_root(&decoded)) != cp.root {
            stats.gaps += 1;
            continue;
        }
        if db.insert_checkpoint_members(&cp.id, &ids).is_ok() {
            stats.members += ids.len() as u64;
        } else {
            stats.gaps += 1;
        }
    }

    db.save_height(height as i64, now_ms())?;

    stats.checkpoint_height = height;
    stats.cursor = format!("cur1:{cursor}");
    Ok(stats)
}

fn base64_of(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Health view shared by every dialect.
pub fn status_json(
    entries: i64,
    refs: i64,
    feeds: i64,
    checkpoints: i64,
    checkpoint_members: i64,
    rejected: i64,
    cursor: i64,
    applied_total: i64,
    height: i64,
    updated_at_ms: i64,
) -> serde_json::Value {
    let lag_s = if updated_at_ms > 0 {
        ((now_ms() - updated_at_ms).max(0) as f64) / 1000.0
    } else {
        0.0
    };
    serde_json::json!({
        "entries": entries,
        "refs": refs,
        "feeds": feeds,
        "checkpoints": checkpoints,
        "checkpoint_members": checkpoint_members,
        "rejected": rejected,
        "cursor": format!("cur1:{cursor}"),
        "applied_total": applied_total,
        "checkpoint_height": height,
        "seconds_since_update": lag_s,
    })
}
