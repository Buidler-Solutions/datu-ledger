//! Append-only ledger storage.
//!
//! Immutability is enforced at the storage layer: triggers physically abort
//! any `UPDATE` or `DELETE` on `entries` and `checkpoints`. There is no code
//! path - in this crate or the protocol - that mutates a stored record.

use borsh::{BorshDeserialize, BorshSerialize};
use datu_core::error::Error as CoreError;
use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

mod contract;
pub mod manifest;
mod policy;

pub use contract::{CitedEntry, ContractCheck, ContractOutlook};
pub use manifest::{manifest_namespace, CompiledManifest, Freshness, ManifestDoc, ManifestStatus};
pub use policy::{NamespaceRule, RoleRule, WritePolicy, POLICY_VERSION};

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Core(CoreError),
    /// Same (author, seq) already stored with a different id: someone is
    /// trying to rewrite (or fork) an author's feed.
    Conflict {
        author: String,
        seq: u64,
        existing: [u8; 32],
        incoming: [u8; 32],
    },
    /// Same (signer, height) already stored with a different id: contradictory
    /// checkpoints are fork evidence.
    Fork {
        signer: String,
        height: u64,
        existing: [u8; 32],
        incoming: [u8; 32],
    },
    Chain(String),
    /// Rejected by this node's *local* writer policy (read-only mode, gated
    /// namespace, unadmitted author, or a missing party signature). Not a
    /// protocol failure: the entry itself may be perfectly valid - this
    /// node simply refuses to store it. Bulk imports skip these entries
    /// instead of aborting.
    Denied(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io error: {e}"),
            StoreError::Sqlite(e) => write!(f, "storage error: {e}"),
            StoreError::Core(e) => write!(f, "{e}"),
            StoreError::Conflict {
                author,
                seq,
                existing,
                incoming,
            } => write!(
                f,
                "feed conflict for {author} seq {seq}: stored {} vs incoming {} - rewrite/fork attempt",
                hex::encode(existing),
                hex::encode(incoming)
            ),
            StoreError::Fork {
                signer,
                height,
                existing,
                incoming,
            } => write!(
                f,
                "checkpoint fork by {signer} at height {height}: {} vs {}",
                hex::encode(existing),
                hex::encode(incoming)
            ),
            StoreError::Chain(m) => write!(f, "chain violation: {m}"),
            StoreError::Denied(m) => write!(f, "policy denied: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<CoreError> for StoreError {
    fn from(e: CoreError) -> Self {
        StoreError::Core(e)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A transport-agnostic sync bundle: the full content of one node, verifiable
/// independently of where it came from (USB stick, LAN, HTTPS, anything).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Bundle {
    pub entries: Vec<Entry>,
    pub checkpoints: Vec<Checkpoint>,
    /// Mesh this bundle came from ("" = the open network). `None` = a
    /// pre-network-mode bundle, which counts as an open-network file.
    pub network_id: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct BundleV1 {
    entries: Vec<Entry>,
    checkpoints: Vec<Checkpoint>,
}

/// A witness stream: checkpoints only, no entry data. Small enough to publish
/// in a newspaper, email around, or print as QR codes. Anyone can later
/// `prove-fork` two streams against each other.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct WitnessStream {
    pub magic: [u8; 8],
    pub checkpoints: Vec<Checkpoint>,
    pub network_id: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct WitnessStreamV1 {
    magic: [u8; 8],
    checkpoints: Vec<Checkpoint>,
}

pub const WITNESS_MAGIC: [u8; 8] = *b"DATUWIT1";

/// An offline reconciliation request: a Bloom filter of the requester's
/// entry ids. Travel this file by USB, email, Bluetooth, radio - any channel
/// that moves bytes. The peer answers with a [`DeltaResponse`] file.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HavesRequest {
    pub magic: [u8; 8],
    pub bloom_m: u64,
    pub bloom_k: u32,
    pub bloom_bits: Vec<u8>,
    pub network_id: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HavesRequestV1 {
    magic: [u8; 8],
    bloom_m: u64,
    bloom_k: u32,
    bloom_bits: Vec<u8>,
}

pub const REQ_MAGIC: [u8; 8] = *b"DATUREQ1";
pub const RES_MAGIC: [u8; 8] = *b"DATURES1";

/// The answer to a [`HavesRequest`]: the entries the requester (probably)
/// lacks plus all checkpoints. Self-verifying: every record is checked
/// before acceptance on merge, so the channel can be hostile.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct DeltaResponse {
    pub magic: [u8; 8],
    pub entries: Vec<Entry>,
    pub checkpoints: Vec<Checkpoint>,
    pub network_id: Option<String>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct DeltaResponseV1 {
    magic: [u8; 8],
    entries: Vec<Entry>,
    checkpoints: Vec<Checkpoint>,
}

/// Decode a bundle, accepting pre-network-mode files as open-network ones.
fn decode_bundle(bytes: &[u8]) -> StoreResult<Bundle> {
    if let Ok(bundle) = Bundle::try_from_slice(bytes) {
        return Ok(bundle);
    }
    let legacy: BundleV1 = BundleV1::try_from_slice(bytes)
        .map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))?;
    Ok(Bundle {
        entries: legacy.entries,
        checkpoints: legacy.checkpoints,
        network_id: None,
    })
}

pub fn decode_witness_stream(bytes: &[u8]) -> StoreResult<WitnessStream> {
    let stream = match WitnessStream::try_from_slice(bytes) {
        Ok(stream) => stream,
        Err(_) => {
            let legacy: WitnessStreamV1 = WitnessStreamV1::try_from_slice(bytes)
                .map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))?;
            WitnessStream {
                magic: legacy.magic,
                checkpoints: legacy.checkpoints,
                network_id: None,
            }
        }
    };
    if stream.magic != WITNESS_MAGIC {
        return Err(StoreError::Chain(
            "not a DAGWIT witness stream (bad magic)".into(),
        ));
    }
    Ok(stream)
}

pub fn decode_haves_request(bytes: &[u8]) -> StoreResult<HavesRequest> {
    let request = match HavesRequest::try_from_slice(bytes) {
        Ok(request) => request,
        Err(_) => {
            let legacy: HavesRequestV1 = HavesRequestV1::try_from_slice(bytes)
                .map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))?;
            HavesRequest {
                magic: legacy.magic,
                bloom_m: legacy.bloom_m,
                bloom_k: legacy.bloom_k,
                bloom_bits: legacy.bloom_bits,
                network_id: None,
            }
        }
    };
    if request.magic != REQ_MAGIC {
        return Err(StoreError::Chain(
            "not a DAGREQ delta request (bad magic)".into(),
        ));
    }
    Ok(request)
}

pub fn decode_delta_response(bytes: &[u8]) -> StoreResult<DeltaResponse> {
    let response = match DeltaResponse::try_from_slice(bytes) {
        Ok(response) => response,
        Err(_) => {
            let legacy: DeltaResponseV1 = DeltaResponseV1::try_from_slice(bytes)
                .map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))?;
            DeltaResponse {
                magic: legacy.magic,
                entries: legacy.entries,
                checkpoints: legacy.checkpoints,
                network_id: None,
            }
        }
    };
    if response.magic != RES_MAGIC {
        return Err(StoreError::Chain(
            "not a DAGRES delta response (bad magic)".into(),
        ));
    }
    Ok(response)
}

/// The mesh wall for offline artifacts: every bundle / delta / witness
/// stream carries the `network_id` of the mesh it came from, and importing
/// one from another mesh - or across the open/walled boundary - is refused.
/// Artifacts written before network modes (no id) count as open-network
/// files: they import into open nodes and are refused by walled ones.
fn ensure_same_network(file: Option<&String>, mine: &str) -> StoreResult<()> {
    let theirs = file.map(|id| id.as_str()).unwrap_or("");
    if theirs != mine {
        return Err(StoreError::Chain(format!(
            "network mismatch: this artifact is from mesh '{}' but this node is on '{}' - the wall refuses (see `datu network`)",
            if theirs.is_empty() { "open" } else { theirs },
            if mine.is_empty() { "open" } else { mine },
        )));
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct ImportSummary {
    pub entries_new: usize,
    pub entries_existing: usize,
    /// Skipped by this node's local policy (read-only, gated namespace,
    /// unadmitted author, missing party signature). Skipping - not
    /// aborting - is deliberate: one node's policy must never let a peer
    /// wedge everyone else's sync. Everything denied here stays perfectly
    /// valid and keeps flowing between open observers.
    pub entries_denied: usize,
    pub checkpoints_new: usize,
    pub checkpoints_existing: usize,
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub feeds: u64,
    pub checkpoints: u64,
    /// References (prev/refs) pointing at entries this node has not (yet) seen.
    pub pending_links: u64,
    /// Is the code-carried genesis record present? Every store opened by
    /// this code seeds it (below the writer policy); `false` means this
    /// ledger was produced by foreign, genesis-stripped code - a lineage
    /// break, not a corruption. Checkpoints make it worse for the stripper:
    /// their merkle roots diverge from every code-abiding witness, which is
    /// fork evidence.
    pub lineage: bool,
    /// Feed conflicts recorded as evidence: an admitted author signed two
    /// different entries at the same (author, seq). Both sides are preserved
    /// (the stored one in `entries`, the incoming one in `conflicts`), so the
    /// dispute is visible, not silently resolved.
    pub conflicts: u64,
    /// Entries declaring a document contract their document does not (or
    /// cannot) satisfy, recounted by the same pure predicate admission
    /// used. Evidence-grade, not fatal: enforcement is admission-time; this
    /// count tells auditors what a stricter node would have refused - or
    /// what arrived on this node against a rule it had not seen yet.
    pub contracts_failed: u64,
}

/// One preserved side of a feed dispute: the incoming entry (id, its bytes
/// retrievable via [`Store::conflict_entry`]) that lost the race for
/// `(author, seq)` to `stored_id`. Both entries are fully signed by the same
/// author - at least one history is fabricated, and the pair is the evidence.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub id: [u8; 32],
    pub author: String,
    pub namespace: String,
    pub seq: u64,
    pub stored_id: [u8; 32],
    pub timestamp_ms: u64,
}

const ENTRY_COLS: &str = "id, author, namespace, seq, ts, body, signature, pq_signature";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
  ord INTEGER PRIMARY KEY AUTOINCREMENT,
  id BLOB NOT NULL UNIQUE,
  author TEXT NOT NULL,
  namespace TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  body BLOB NOT NULL,
  signature BLOB NOT NULL,
  pq_signature BLOB NOT NULL,
  UNIQUE(author, seq)
);
CREATE INDEX IF NOT EXISTS idx_entries_author_seq ON entries(author, seq);
CREATE INDEX IF NOT EXISTS idx_entries_ns ON entries(namespace);
CREATE TRIGGER IF NOT EXISTS entries_immutable_update BEFORE UPDATE ON entries
BEGIN SELECT RAISE(ABORT, 'entries are append-only (immutable)'); END;
CREATE TRIGGER IF NOT EXISTS entries_immutable_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'entries are append-only (immutable)'); END;
CREATE TABLE IF NOT EXISTS checkpoints (
  ord INTEGER PRIMARY KEY AUTOINCREMENT,
  id BLOB NOT NULL UNIQUE,
  signer TEXT NOT NULL,
  height INTEGER NOT NULL,
  body BLOB NOT NULL,
  signature BLOB NOT NULL,
  pq_signature BLOB NOT NULL,
  UNIQUE(signer, height)
);
CREATE TRIGGER IF NOT EXISTS checkpoints_immutable_update BEFORE UPDATE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only (immutable)'); END;
CREATE TRIGGER IF NOT EXISTS checkpoints_immutable_delete BEFORE DELETE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only (immutable)'); END;
CREATE TABLE IF NOT EXISTS conflicts (
  ord INTEGER PRIMARY KEY AUTOINCREMENT,
  id BLOB NOT NULL UNIQUE,
  author TEXT NOT NULL,
  namespace TEXT NOT NULL,
  seq INTEGER NOT NULL,
  stored_id BLOB NOT NULL,
  ts INTEGER NOT NULL,
  body BLOB NOT NULL,
  signature BLOB NOT NULL,
  pq_signature BLOB NOT NULL
);
CREATE TRIGGER IF NOT EXISTS conflicts_immutable_update BEFORE UPDATE ON conflicts
BEGIN SELECT RAISE(ABORT, 'conflicts are append-only (immutable)'); END;
CREATE TRIGGER IF NOT EXISTS conflicts_immutable_delete BEFORE DELETE ON conflicts
BEGIN SELECT RAISE(ABORT, 'conflicts are append-only (immutable)'); END;
";

fn sql_invalid(col: usize) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        col,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored record does not decode",
        )),
    )
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    row_to_entry_at(row, 0)
}

/// Decode an entry row starting at column offset `off` (used when extra
/// leading columns - like `ord` - are selected).
fn row_to_entry_at(row: &rusqlite::Row<'_>, off: usize) -> rusqlite::Result<Entry> {
    let body: Vec<u8> = row.get(off + 5)?;
    let signature: Vec<u8> = row.get(off + 6)?;
    let pq_signature: Vec<u8> = row.get(off + 7)?;
    let body = EntryBody::try_from_slice(&body)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                off + 5,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                )),
            )
        })
        .map_err(|_| sql_invalid(off + 5))?;
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| sql_invalid(off + 6))?;
    Ok(Entry {
        body,
        signature,
        pq_signature,
    })
}

pub struct Store {
    conn: Connection,
    /// Local writer policy. `None` = open observer mode: this node accepts
    /// everything (anyone may run a node, ungated, forever).
    policy: Option<WritePolicy>,
}

impl Store {
    pub fn open(path: &Path) -> StoreResult<Store> {
        Self::open_with_policy(path, None)
    }

    /// Open (or create) a store under a writer policy. `None` = observer.
    pub fn open_with_policy(path: &Path, policy: Option<WritePolicy>) -> StoreResult<Store> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn, policy)
    }

    pub fn open_in_memory() -> StoreResult<Store> {
        Self::init(Connection::open_in_memory()?, None)
    }

    /// In-memory store under a policy (tests, ephemeral validators).
    pub fn open_in_memory_with_policy(policy: Option<WritePolicy>) -> StoreResult<Store> {
        Self::init(Connection::open_in_memory()?, policy)
    }

    fn init(conn: Connection, policy: Option<WritePolicy>) -> StoreResult<Store> {
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.execute_batch(SCHEMA)?;
        let store = Store { conn, policy };
        store.seed_genesis()?;
        Ok(store)
    }

    /// Every ledger begins with the code's genesis record - the founder's
    /// signed statement, the lineage mark carried into every fork. Seeded
    /// *below* the writer policy (policy gates what peers may land; the
    /// genesis is the ledger's own definition) and idempotent: reopening a
    /// seeded store is a no-op. A store that already holds a *different*
    /// entry at the genesis author's seq 0 refuses to open - that ledger
    /// was built from different code (fail-closed, like every tamper).
    fn seed_genesis(&self) -> StoreResult<()> {
        let genesis = datu_core::genesis::genesis_entry()?;
        self.insert_entry_ungated(genesis)?;
        Ok(())
    }

    /// This store's writer policy, if any.
    pub fn policy(&self) -> Option<&WritePolicy> {
        self.policy.as_ref()
    }

    pub fn path(&self) -> Option<&str> {
        self.conn.path()
    }

    // ---- entries ----

    pub fn entry_count(&self) -> StoreResult<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    pub fn has_entry(&self, id: &[u8; 32]) -> StoreResult<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM entries WHERE id = ?1",
                params![id.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn get_entry(&self, id: &[u8; 32]) -> StoreResult<Option<Entry>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {ENTRY_COLS} FROM entries WHERE id = ?1"))?;
        let mut rows = stmt.query(params![id.as_slice()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_entry(row)?)),
            None => Ok(None),
        }
    }

    fn entry_by_author_seq(&self, author: &str, seq: u64) -> StoreResult<Option<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLS} FROM entries WHERE author = ?1 AND seq = ?2"
        ))?;
        let mut rows = stmt.query(params![author, seq as i64])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_entry(row)?)),
            None => Ok(None),
        }
    }

    /// The author's latest stored entry (highest seq), if any.
    pub fn latest(&self, author: &str) -> StoreResult<Option<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLS} FROM entries WHERE author = ?1 ORDER BY seq DESC LIMIT 1"
        ))?;
        let mut rows = stmt.query(params![author])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_entry(row)?)),
            None => Ok(None),
        }
    }

    /// Full feed for one author, ordered by seq.
    pub fn feed(&self, author: &str) -> StoreResult<Vec<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLS} FROM entries WHERE author = ?1 ORDER BY seq ASC"
        ))?;
        let rows = stmt.query_map(params![author], row_to_entry)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// How many entries this author already has in this exact namespace -
    /// the basis for `max_entries_per_author` policy caps (one ballot per
    /// voter in an election namespace).
    pub fn count_by_author_in_namespace(&self, namespace: &str, author: &str) -> StoreResult<u64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM entries WHERE namespace = ?1 AND author = ?2")?;
        let count: u64 = stmt.query_row(params![namespace, author], |row| row.get(0))?;
        Ok(count)
    }

    /// Zero-based ordinal of an entry inside its author's entries in the
    /// same namespace: the namespace's own sequence, derived on read. The
    /// signed `seq` stays the author's global feed number, so a key's whole
    /// history remains one tamper-evident chain while each namespace can be
    /// read as its own numbered log. The set of predecessors is fixed, so
    /// an entry's ordinal never changes once written.
    pub fn namespace_seq(&self, author: &str, namespace: &str, seq: u64) -> StoreResult<u64> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) FROM entries WHERE author = ?1 AND namespace = ?2 AND seq <= ?3",
        )?;
        let count: u64 =
            stmt.query_row(params![author, namespace, seq as i64], |row| row.get(0))?;
        Ok(count.saturating_sub(1))
    }

    /// Entries with an internal `ord` greater than the cursor, oldest
    /// first: the tail a projection/indexer follows. The `ord` is returned
    /// alongside so the caller can persist a durable cursor (surfaced to
    /// HTTP callers only as an opaque token).
    pub fn entries_after(&self, after: i64, limit: usize) -> StoreResult<Vec<(i64, Entry)>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT ord, {ENTRY_COLS} FROM entries WHERE ord > ?1 ORDER BY ord ASC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![after, limit as i64], |row| {
            let ord: i64 = row.get(0)?;
            Ok((ord, row_to_entry_at(row, 1)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Highest internal insertion ordinal (0 when the store is empty).
    pub fn max_ord(&self) -> StoreResult<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(MAX(ord), 0) FROM entries")?;
        let ord: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(ord)
    }

    pub fn entry_ids(&self) -> StoreResult<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare("SELECT id FROM entries ORDER BY ord")?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let arr: [u8; 32] = blob.as_slice().try_into().map_err(|_| sql_invalid(0))?;
            Ok(arr)
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn all_entries(&self) -> StoreResult<Vec<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLS} FROM entries ORDER BY ord ASC"
        ))?;
        let rows = stmt.query_map([], row_to_entry)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list(
        &self,
        namespace: Option<&str>,
        author: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<Entry>> {
        self.list_page(namespace, author, limit, 0)
    }

    /// [`Self::list`] with an offset: page through the whole store (the
    /// explorer's globe view walks every page to pin every entry).
    pub fn list_page(
        &self,
        namespace: Option<&str>,
        author: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> StoreResult<Vec<Entry>> {
        let (sql, binds): (String, Vec<String>) = match (namespace, author) {
            (Some(ns), Some(a)) => (
                format!(
                    "SELECT {ENTRY_COLS} FROM entries WHERE namespace = ?1 AND author = ?2 ORDER BY ord DESC LIMIT {limit} OFFSET {offset}"
                ),
                vec![ns.to_string(), a.to_string()],
            ),
            (Some(ns), None) => (
                format!(
                    "SELECT {ENTRY_COLS} FROM entries WHERE namespace = ?1 ORDER BY ord DESC LIMIT {limit} OFFSET {offset}"
                ),
                vec![ns.to_string()],
            ),
            (None, Some(a)) => (
                format!(
                    "SELECT {ENTRY_COLS} FROM entries WHERE author = ?1 ORDER BY ord DESC LIMIT {limit} OFFSET {offset}"
                ),
                vec![a.to_string()],
            ),
            (None, None) => (
                format!(
                    "SELECT {ENTRY_COLS} FROM entries ORDER BY ord DESC LIMIT {limit} OFFSET {offset}"
                ),
                vec![],
            ),
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), row_to_entry)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// The single write path for entries. Fully verifies the entry, applies
    /// this node's writer policy, rejects feed rewrites (same author+seq,
    /// different id) and broken prev links. Returns Ok(false) if the exact
    /// entry is already stored (idempotent).
    ///
    /// Ordering: idempotent duplicates pass ungated; policy denial is then
    /// checked *before* conflict detection - an unadmitted author's feed
    /// games are simply not this node's business (Denied), while conflicts
    /// by admitted writers surface as fork-relevant `Conflict` errors.
    pub fn insert_entry(&self, entry: &Entry) -> StoreResult<bool> {
        self.insert_entry_inner(entry, false)
    }

    /// Same insertion path, minus the writer policy - used only for the
    /// code-carried genesis record, which no local policy may refuse.
    fn insert_entry_ungated(&self, entry: &Entry) -> StoreResult<bool> {
        self.insert_entry_inner(entry, true)
    }

    fn insert_entry_inner(&self, entry: &Entry, skip_gate: bool) -> StoreResult<bool> {
        entry.verify()?;
        let id = entry.id()?;
        if let Some(existing) = self.entry_by_author_seq(&entry.body.author, entry.body.seq)? {
            let existing_id = existing.id().map_err(StoreError::Core)?;
            if existing_id == id {
                return Ok(false);
            }
        }
        if !skip_gate {
            self.gate(entry)?;
        }
        if let Some(existing) = self.entry_by_author_seq(&entry.body.author, entry.body.seq)? {
            let existing_id = existing.id().map_err(StoreError::Core)?;
            let _ = self.record_conflict(entry, &id, &existing_id);
            return Err(StoreError::Conflict {
                author: entry.body.author.clone(),
                seq: entry.body.seq,
                existing: existing_id,
                incoming: id,
            });
        }
        if let Some(prev_id) = entry.body.prev {
            if entry.body.seq > 0 {
                if let Some(prev_entry) =
                    self.entry_by_author_seq(&entry.body.author, entry.body.seq - 1)?
                {
                    if prev_entry.id().map_err(StoreError::Core)? != prev_id {
                        return Err(StoreError::Chain(format!(
                            "entry seq {} by {} does not chain to the stored predecessor",
                            entry.body.seq,
                            &entry.body.author[..8.min(entry.body.author.len())]
                        )));
                    }
                }
            }
        }
        self.conn.execute(
            "INSERT INTO entries (id, author, namespace, seq, ts, body, signature, pq_signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.as_slice(),
                entry.body.author,
                entry.body.namespace,
                entry.body.seq as i64,
                entry.body.timestamp_ms as i64,
                Entry::body_bytes(&entry.body).map_err(StoreError::Core)?,
                entry.signature.as_slice(),
                entry.pq_signature.as_slice(),
            ],
        )?;
        Ok(true)
    }

    /// Preserve the losing side of a feed conflict as standalone evidence:
    /// the incoming entry already passed full verification (both hybrid
    /// signatures), so the stored bytes re-verify with zero other context.
    /// Best-effort by design - a recording failure must never mask the
    /// `Conflict` error that fork handling depends on. Replays of the same
    /// conflicting entry are deduplicated by id.
    fn record_conflict(
        &self,
        entry: &Entry,
        id: &[u8; 32],
        stored_id: &[u8; 32],
    ) -> StoreResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO conflicts (id, author, namespace, seq, stored_id, ts, body, signature, pq_signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.as_slice(),
                entry.body.author,
                entry.body.namespace,
                entry.body.seq as i64,
                stored_id.as_slice(),
                entry.body.timestamp_ms as i64,
                Entry::body_bytes(&entry.body).map_err(StoreError::Core)?,
                entry.signature.as_slice(),
                entry.pq_signature.as_slice(),
            ],
        )?;
        Ok(())
    }

    /// Recorded feed conflicts, newest first - the dispute surface for
    /// explorers and audits. Detection is not resolution: these feeds are
    /// disputed until a governance record says otherwise.
    pub fn list_conflicts(&self, limit: usize) -> StoreResult<Vec<ConflictRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, author, namespace, seq, stored_id, ts FROM conflicts ORDER BY ord DESC LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![limit as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let id: Vec<u8> = row.get(0)?;
            let stored_id: Vec<u8> = row.get(4)?;
            out.push(ConflictRecord {
                id: id.as_slice().try_into().map_err(|_| sql_invalid(0))?,
                author: row.get(1)?,
                namespace: row.get(2)?,
                seq: row.get::<_, i64>(3)? as u64,
                stored_id: stored_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| sql_invalid(4))?,
                timestamp_ms: row.get::<_, i64>(5)? as u64,
            });
        }
        Ok(out)
    }

    pub fn conflicts_count(&self) -> StoreResult<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM conflicts", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    /// The full recorded incoming entry of a conflict - self-verifying
    /// evidence, fetchable by id for `prove-fork`-style workflows.
    pub fn conflict_entry(&self, id: &[u8; 32]) -> StoreResult<Option<Entry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT body, signature, pq_signature FROM conflicts WHERE id = ?1")?;
        let mut rows = stmt.query(params![id.as_slice()])?;
        match rows.next()? {
            Some(row) => {
                let body: Vec<u8> = row.get(0)?;
                let signature: Vec<u8> = row.get(1)?;
                let pq_signature: Vec<u8> = row.get(2)?;
                let body = EntryBody::try_from_slice(&body).map_err(|_| sql_invalid(0))?;
                let signature: [u8; 64] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| sql_invalid(1))?;
                Ok(Some(Entry {
                    body,
                    signature,
                    pq_signature,
                }))
            }
            None => Ok(None),
        }
    }

    /// Entries whose causal refs include `id` - used for N-of-M cosign
    /// tracking (who references this attestation?). Refs live inside the
    /// signed body, so this decodes and scans; fine at ledger scale.
    pub fn referencing(&self, id: &[u8; 32]) -> StoreResult<Vec<Entry>> {
        let mut out = Vec::new();
        for entry in self.all_entries()? {
            if entry.body.refs.iter().any(|r| r == id) {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Set-reconciliation page: entries this store holds that the caller
    /// (probably) does not, according to `have` - a Bloom filter of the
    /// caller's entry ids. Paged by internal ordinal; pass the returned
    /// cursor back until `more` is false. A false positive merely defers an
    /// entry to the next sync: nothing is ever lost or trusted unverified.
    pub fn missing_page(
        &self,
        have: &datu_core::bloom::BloomFilter,
        cursor: Option<i64>,
        limit: usize,
    ) -> StoreResult<(Vec<Entry>, Option<i64>, bool)> {
        let mut out: Vec<Entry> = Vec::new();
        let mut cur = cursor.unwrap_or(0);
        const CHUNK: usize = 512;
        loop {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT ord, {ENTRY_COLS} FROM entries WHERE ord > ?1 ORDER BY ord ASC LIMIT {CHUNK}"
            ))?;
            let mut rows = stmt.query(params![cur])?;
            let mut saw_row = false;
            while let Some(row) = rows.next()? {
                saw_row = true;
                cur = row.get::<_, i64>(0)?;
                let id_blob: Vec<u8> = row.get(1)?;
                let id: [u8; 32] = id_blob.as_slice().try_into().map_err(|_| sql_invalid(1))?;
                if have.contains(&id) {
                    continue;
                }
                out.push(row_to_entry_at(row, 1)?);
                if out.len() >= limit {
                    return Ok((out, Some(cur), true));
                }
            }
            if !saw_row {
                return Ok((out, None, false));
            }
        }
    }

    // ---- checkpoints ----

    fn checkpoint_by_signer_height(
        &self,
        signer: &str,
        height: u64,
    ) -> StoreResult<Option<Checkpoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, signer, height, body, signature, pq_signature FROM checkpoints WHERE signer = ?1 AND height = ?2",
        )?;
        let mut rows = stmt.query(params![signer, height as i64])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_checkpoint(row)?)),
            None => Ok(None),
        }
    }

    /// The signer's latest stored checkpoint (highest height), if any.
    pub fn last_checkpoint(&self, signer: &str) -> StoreResult<Option<Checkpoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, signer, height, body, signature, pq_signature FROM checkpoints WHERE signer = ?1 ORDER BY height DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![signer])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_checkpoint(row)?)),
            None => Ok(None),
        }
    }

    pub fn all_checkpoints(&self) -> StoreResult<Vec<Checkpoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, signer, height, body, signature, pq_signature FROM checkpoints ORDER BY ord ASC",
        )?;
        let rows = stmt.query_map([], row_to_checkpoint)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn checkpoint_count(&self) -> StoreResult<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |r| {
                r.get::<_, i64>(0)
            })? as u64)
    }

    /// Build the inclusion proof that `checkpoint` covered `entry_id`: the
    /// witness time-attestation ("this signer's ledger had seen this entry
    /// by this claimed time") in offline-verifiable form.
    ///
    /// The checkpoint's claimed set must equal this node's current id set:
    /// a historical checkpoint over a set this node has since outgrown can
    /// no longer be recomputed, so this explains the gap instead of
    /// guessing. Fetch the checkpoint from a node holding the same set, or
    /// sign a fresh one.
    pub fn coverage_proof(
        &self,
        entry_id: &[u8; 32],
        checkpoint: &Checkpoint,
    ) -> StoreResult<datu_core::checkpoint::CoverageProof> {
        let ids = self.entry_ids()?;
        // The checkpoint's set is exactly the ids its signer had seen, and
        // this store is append-only in insertion order - so that set is the
        // first `entries_count` ids here whenever this node holds every
        // entry the signer held. Rebuilding the prefix makes proofs work
        // against historical checkpoints too, not only the newest one; a
        // root mismatch (missing entries, different history) fails closed.
        let count = checkpoint.body.entries_count as usize;
        let set = if count <= ids.len() {
            let prefix = &ids[..count];
            (datu_core::merkle::merkle_root(prefix) == checkpoint.body.entry_ids_root)
                .then_some(prefix)
        } else {
            None
        };
        let checkpoint_hex = hex::encode(checkpoint.id().map_err(StoreError::Core)?);
        let set = set.ok_or_else(|| {
            StoreError::Denied(format!(
                "checkpoint {checkpoint_hex} covers a set this node cannot reconstruct ({} ids now, {} at signing, root differs): this node is missing entries the witness had, or holds a different history",
                ids.len(),
                checkpoint.body.entries_count
            ))
        })?;
        datu_core::checkpoint::CoverageProof::build(set, entry_id).ok_or_else(|| {
            StoreError::Denied(format!(
                "entry {} is not in checkpoint {}'s covered set",
                hex::encode(entry_id),
                hex::encode(checkpoint.id().unwrap_or_default())
            ))
        })
    }

    /// The single write path for checkpoints. Verifies the signature, rejects
    /// contradictory same-height checkpoints (fork evidence), and checks the
    /// signer's chain. Idempotent for an identical checkpoint.
    pub fn append_checkpoint(&self, checkpoint: &Checkpoint) -> StoreResult<bool> {
        checkpoint.verify()?;
        let id = checkpoint.id()?;
        if let Some(existing) =
            self.checkpoint_by_signer_height(&checkpoint.body.signer, checkpoint.body.height)?
        {
            let existing_id = existing.id().map_err(StoreError::Core)?;
            if existing_id == id {
                return Ok(false);
            }
            return Err(StoreError::Fork {
                signer: checkpoint.body.signer.clone(),
                height: checkpoint.body.height,
                existing: existing_id,
                incoming: id,
            });
        }
        if checkpoint.body.height > 0 {
            if let Some(prev) = self
                .checkpoint_by_signer_height(&checkpoint.body.signer, checkpoint.body.height - 1)?
            {
                if checkpoint.body.prev != Some(prev.id().map_err(StoreError::Core)?) {
                    return Err(StoreError::Chain(
                        "checkpoint does not chain to the signer's previous checkpoint".into(),
                    ));
                }
            }
        }
        self.conn.execute(
            "INSERT INTO checkpoints (id, signer, height, body, signature, pq_signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.as_slice(),
                checkpoint.body.signer,
                checkpoint.body.height as i64,
                Checkpoint::body_bytes(&checkpoint.body).map_err(StoreError::Core)?,
                checkpoint.signature.as_slice(),
                checkpoint.pq_signature.as_slice(),
            ],
        )?;
        Ok(true)
    }

    // ---- bundles (sneakernet / any-channel sync) ----

    pub fn export_bundle(&self, network_id: &str) -> StoreResult<Vec<u8>> {
        let bundle = Bundle {
            entries: self.all_entries()?,
            checkpoints: self.all_checkpoints()?,
            network_id: Some(network_id.to_string()),
        };
        borsh::to_vec(&bundle).map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))
    }

    /// Verify-then-merge a bundle. Every entry and checkpoint is fully
    /// verified before anything is accepted; conflicts abort with evidence.
    /// Bundles from another mesh are refused by the network wall.
    pub fn import_bundle(&self, bytes: &[u8], my_network_id: &str) -> StoreResult<ImportSummary> {
        let bundle = decode_bundle(bytes)?;
        ensure_same_network(bundle.network_id.as_ref(), my_network_id)?;
        let mut summary = ImportSummary::default();
        for entry in &bundle.entries {
            match self.insert_entry(entry) {
                Ok(true) => summary.entries_new += 1,
                Ok(false) => summary.entries_existing += 1,
                Err(StoreError::Denied(_)) => summary.entries_denied += 1,
                Err(e) => return Err(e),
            }
        }
        for checkpoint in &bundle.checkpoints {
            if self.append_checkpoint(checkpoint)? {
                summary.checkpoints_new += 1;
            } else {
                summary.checkpoints_existing += 1;
            }
        }
        Ok(summary)
    }

    // ---- witness streams (checkpoint-only exchange) ----

    pub fn export_witness_stream(&self, network_id: &str) -> StoreResult<Vec<u8>> {
        let stream = WitnessStream {
            magic: WITNESS_MAGIC,
            checkpoints: self.all_checkpoints()?,
            network_id: Some(network_id.to_string()),
        };
        borsh::to_vec(&stream).map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))
    }

    /// Verify-then-merge a checkpoint stream. A stream containing a
    /// checkpoint contradicting one already stored aborts with `Fork` -
    /// that is the desired behavior: use `prove-fork` to analyze it instead.
    pub fn import_witness_stream(
        &self,
        bytes: &[u8],
        my_network_id: &str,
    ) -> StoreResult<ImportSummary> {
        let stream = decode_witness_stream(bytes)?;
        ensure_same_network(stream.network_id.as_ref(), my_network_id)?;
        let mut summary = ImportSummary::default();
        for checkpoint in &stream.checkpoints {
            if self.append_checkpoint(checkpoint)? {
                summary.checkpoints_new += 1;
            } else {
                summary.checkpoints_existing += 1;
            }
        }
        Ok(summary)
    }

    // ---- delta files (offline reconciliation over any channel) ----

    /// Build a "what I have" request file (a Bloom filter of my entry ids).
    /// Give the file to any peer; they answer with a delta response file.
    pub fn export_haves_request(&self, fpr: f64, network_id: &str) -> StoreResult<Vec<u8>> {
        let ids = self.entry_ids()?;
        let mut bloom = datu_core::BloomFilter::new_for(ids.len().max(16), fpr);
        for id in &ids {
            bloom.insert(id);
        }
        let request = HavesRequest {
            magic: REQ_MAGIC,
            bloom_m: bloom.bit_count(),
            bloom_k: bloom.hash_count(),
            bloom_bits: bloom.bit_bytes(),
            network_id: Some(network_id.to_string()),
        };
        borsh::to_vec(&request).map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))
    }

    /// Answer a request file with everything the requester (probably) lacks:
    /// their missing entries plus all of this node's checkpoints. Returns
    /// the response bytes and how many entries were suppressed as
    /// already-known. Serving is untrusted work - the requester verifies
    /// every record on merge.
    pub fn answer_delta(
        &self,
        request_bytes: &[u8],
        my_network_id: &str,
    ) -> StoreResult<(Vec<u8>, u64)> {
        let request = decode_haves_request(request_bytes)?;
        ensure_same_network(request.network_id.as_ref(), my_network_id)?;
        let bloom = datu_core::BloomFilter::from_parts(
            request.bloom_m,
            request.bloom_k,
            &request.bloom_bits,
        )
        .ok_or_else(|| StoreError::Chain("malformed bloom filter in request".into()))?;
        let mut entries = Vec::new();
        let mut suppressed = 0u64;
        for entry in self.all_entries()? {
            let id = entry.id().map_err(StoreError::Core)?;
            if bloom.contains(&id) {
                suppressed += 1;
            } else {
                entries.push(entry);
            }
        }
        let response = DeltaResponse {
            magic: RES_MAGIC,
            entries,
            checkpoints: self.all_checkpoints()?,
            network_id: Some(my_network_id.to_string()),
        };
        let bytes = borsh::to_vec(&response)
            .map_err(|e| StoreError::Core(CoreError::Encoding(e.to_string())))?;
        Ok((bytes, suppressed))
    }

    /// Verify-then-merge a delta response file. Same semantics as bundles:
    /// every signature checked first, conflicts abort as fork evidence.
    /// Responses from another mesh are refused by the network wall.
    pub fn merge_delta(
        &self,
        response_bytes: &[u8],
        my_network_id: &str,
    ) -> StoreResult<ImportSummary> {
        let response = decode_delta_response(response_bytes)?;
        ensure_same_network(response.network_id.as_ref(), my_network_id)?;
        let mut summary = ImportSummary::default();
        for entry in &response.entries {
            match self.insert_entry(entry) {
                Ok(true) => summary.entries_new += 1,
                Ok(false) => summary.entries_existing += 1,
                Err(StoreError::Denied(_)) => summary.entries_denied += 1,
                Err(e) => return Err(e),
            }
        }
        for checkpoint in &response.checkpoints {
            if self.append_checkpoint(checkpoint)? {
                summary.checkpoints_new += 1;
            } else {
                summary.checkpoints_existing += 1;
            }
        }
        Ok(summary)
    }

    // ---- full verification ----

    /// Recompute and verify everything in the store: every signature, every
    /// stored id, every feed chain, every checkpoint and its chain. Pending
    /// (not-yet-seen) references are counted, not treated as errors.
    pub fn verify_all(&self) -> StoreResult<VerifyReport> {
        let mut authors: BTreeSet<String> = BTreeSet::new();
        let mut entries: u64 = 0;
        let mut pending_links: u64 = 0;
        let mut contracts_failed: u64 = 0;

        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLS} FROM entries ORDER BY ord ASC"
        ))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let entry = row_to_entry(row)?;
            entry.verify()?;
            let id = entry.id().map_err(StoreError::Core)?;
            let stored_id: Vec<u8> = row.get(0)?;
            if stored_id != id {
                return Err(StoreError::Chain(format!(
                    "stored id does not match recomputed id for entry seq {} by {}",
                    entry.body.seq,
                    &entry.body.author[..8.min(entry.body.author.len())]
                )));
            }
            authors.insert(entry.body.author.clone());
            entries += 1;
            if let Some(prev_id) = entry.body.prev {
                if !self.has_entry(&prev_id)? {
                    pending_links += 1;
                }
            }
            for r in &entry.body.refs {
                if !self.has_entry(r)? {
                    pending_links += 1;
                }
            }
            if let Some(check) = self.check_contract(&entry)? {
                if !check.admitted {
                    contracts_failed += 1;
                }
            }
        }

        for author in &authors {
            let feed = self.feed(author)?;
            for pair in feed.windows(2) {
                let a = &pair[0];
                let b = &pair[1];
                if b.body.seq == a.body.seq + 1
                    && b.body.prev != Some(a.id().map_err(StoreError::Core)?)
                {
                    return Err(StoreError::Chain(format!(
                        "feed break for author {} at seq {}",
                        &author[..8.min(author.len())],
                        b.body.seq
                    )));
                }
            }
        }

        let mut cps_stmt = self.conn.prepare(
            "SELECT id, signer, height, body, signature, pq_signature FROM checkpoints ORDER BY signer ASC, height ASC",
        )?;
        let mut cps_rows = cps_stmt.query([])?;
        let mut checkpoints: u64 = 0;
        let mut last: Option<(String, u64, [u8; 32])> = None;
        while let Some(row) = cps_rows.next()? {
            let checkpoint = row_to_checkpoint(row)?;
            checkpoint.verify()?;
            let id = checkpoint.id().map_err(StoreError::Core)?;
            let stored_id: Vec<u8> = row.get(0)?;
            if stored_id != id {
                return Err(StoreError::Chain(
                    "stored checkpoint id does not match recomputed id".into(),
                ));
            }
            checkpoints += 1;
            if let Some((prev_signer, prev_height, prev_id)) = &last {
                if prev_signer == &checkpoint.body.signer
                    && checkpoint.body.height == prev_height + 1
                    && checkpoint.body.prev != Some(*prev_id)
                {
                    return Err(StoreError::Chain(format!(
                        "checkpoint chain break for signer {} at height {}",
                        &checkpoint.body.signer[..8.min(checkpoint.body.signer.len())],
                        checkpoint.body.height
                    )));
                }
            }
            last = Some((checkpoint.body.signer.clone(), checkpoint.body.height, id));
        }

        Ok(VerifyReport {
            entries,
            feeds: authors.len() as u64,
            checkpoints,
            pending_links,
            conflicts: self.conflicts_count()?,
            contracts_failed,
            lineage: match datu_core::genesis::genesis_entry() {
                Ok(genesis) => match genesis.id() {
                    Ok(id) => self.has_entry(&id).unwrap_or(false),
                    Err(_) => false,
                },
                Err(_) => false,
            },
        })
    }
}

fn row_to_checkpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<Checkpoint> {
    let body: Vec<u8> = row.get(3)?;
    let signature: Vec<u8> = row.get(4)?;
    let pq_signature: Vec<u8> = row.get(5)?;
    let body = CheckpointBody::try_from_slice(&body).map_err(|_| sql_invalid(3))?;
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| sql_invalid(4))?;
    Ok(Checkpoint {
        body,
        signature,
        pq_signature,
    })
}
