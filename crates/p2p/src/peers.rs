//! Peer exchange (PEX): how a node learns the rest of the ecosystem.
//!
//! mDNS finds peers on a LAN; `--peer` names them by hand. Peer exchange is
//! the third leg: ask any peer you already sync with "who else do you know?"
//! and merge the answer. One seed therefore grows into the whole reachable
//! network - which is what an ecosystem explorer mirrors: a node that pulls
//! from everything it has learned holds the union of every transaction.
//!
//! The anti-poisoning rule: an address a peer *told* us about (source `pex`)
//! or that was *announced* to us (source `announce`) is never re-shared until
//! this node has actually synced with it (`last_success_ms > 0`). A liar can
//! fill our pull list with dead addresses - each costs one failed dial - but
//! cannot inject anything into what we tell others. Only addresses this node
//! verified by syncing (or that the operator named: `seed`/`configured`) ever
//! propagate. The mesh wall applies as everywhere: entries are learned and
//! shared only within one network id.
//!
//! Wire: one `PeersRequest` frame (first frame magic `DATUPEX1`, or the frame
//! after an admitted hello on walled meshes), one `PeersResponse` frame, then
//! the connection closes. Peers running older datu answer "unknown frame" -
//! callers treat that as "no exchange", never an error worth stopping for.

use crate::NetworkPolicy;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Magic of the peer-exchange frames.
pub const PEERS_MAGIC: [u8; 8] = *b"DATUPEX1";
/// Where the table persists between runs, inside the data dir.
pub const PEERS_FILE: &str = "peers.json";
/// Hard cap on remembered addresses: learned peers are cheap, not infinite.
pub const PEER_CAP: usize = 1024;
/// Addresses served in one exchange (most recently synced first).
pub const SHARE_LIMIT: usize = 64;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// "Who else do you know?" - one frame, then we read one response.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PeersRequest {
    pub magic: [u8; 8],
    /// Hex ed25519 key of the asking node (advisory on the open network).
    pub node_key: String,
    /// Mesh the asking node is on ("" = the open network).
    pub network_id: String,
    /// The asker's dialable sync address (host:port), recorded as an announce.
    pub announce: Option<String>,
    pub limit: u16,
}

/// One learned address, as it travels between nodes.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq)]
pub struct PeerWire {
    pub addr: String,
    /// Hex node key, empty when unknown.
    pub node_key: String,
    /// Mesh the peer is on ("" = open network or unknown to the sharer).
    pub network_id: String,
    /// When the *sharing* node last synced with it (0 = never verified).
    pub last_success_ms: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PeersResponse {
    pub magic: [u8; 8],
    pub peers: Vec<PeerWire>,
}

/// How an address entered the table. `seed`/`configured` are the operator's
/// word and always shareable; the rest must be earned by a successful sync.
pub const SOURCE_SEED: &str = "seed";
pub const SOURCE_CONFIGURED: &str = "configured";
pub const SOURCE_MDNS: &str = "mdns";
const SOURCE_PEX: &str = "pex";
const SOURCE_ANNOUNCE: &str = "announce";

/// A learned address (mdns / pex / announce) that never synced is dropped
/// from the table after this many consecutive failures...
const STALE_FAILURES: u64 = 12;
/// ...and only once it has been known this long, so a node that is merely
/// restarting is not forgotten.
const STALE_MIN_AGE_MS: u64 = 10 * 60 * 1000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PeerEntry {
    pub addr: String,
    #[serde(default)]
    pub node_key: String,
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub source: String,
    pub first_seen_ms: u64,
    #[serde(default)]
    pub last_success_ms: u64,
    #[serde(default)]
    pub last_attempt_ms: u64,
    #[serde(default)]
    pub last_error: String,
    /// Consecutive failed dials since the last success (0 = never failed).
    #[serde(default)]
    pub failures: u64,
}

impl PeerEntry {
    /// The operator named it, or this node synced with it: either way this
    /// address is verified enough to tell others about.
    fn shareable(&self) -> bool {
        self.source == SOURCE_SEED || self.source == SOURCE_CONFIGURED || self.last_success_ms > 0
    }
}

/// Thread-safe table of every node this one knows about, persisted as
/// `peers.json` in the data dir. Shared between the sync daemon (which
/// records what happens), the p2p listener (which answers exchanges) and
/// the HTTP API (which shows it in the explorer).
pub struct PeerTable {
    inner: Mutex<HashMap<String, PeerEntry>>,
    path: Option<PathBuf>,
}

impl Default for PeerTable {
    fn default() -> Self {
        PeerTable {
            inner: Mutex::new(HashMap::new()),
            path: None,
        }
    }
}

fn valid_addr(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() || addr.len() > 260 {
        return false;
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return false;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // Something shaped like an IPv4 literal but not one ("999.999.1.1") is
    // junk, not a hostname: digits and dots only ever mean an address.
    let numeric = !host.is_empty() && host.chars().all(|c| c.is_ascii_digit() || c == '.');
    if numeric && host.parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    // A wildcard or loopback announcement is useless to anyone else; a peer
    // that dials it would only reach itself.
    !(host == "0.0.0.0" || host == "::")
}

impl PeerTable {
    pub fn new() -> PeerTable {
        PeerTable::default()
    }

    /// Load the persisted table from `<data-dir>/peers.json`; a missing or
    /// corrupt file starts fresh (the table is a cache, never authoritative).
    pub fn load(data_dir: &Path) -> PeerTable {
        let path = data_dir.join(PEERS_FILE);
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<HashMap<String, PeerEntry>>(&text).ok())
            .unwrap_or_default();
        let table = PeerTable {
            inner: Mutex::new(map),
            path: Some(path),
        };
        table.prune();
        table
    }

    /// Best-effort persist; a failed write costs nothing but a re-learn.
    pub fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let guard = self.inner.lock().unwrap();
        let mut ordered: Vec<(&String, &PeerEntry)> = guard.iter().collect();
        ordered.sort_by(|a, b| a.0.cmp(b.0));
        let map: HashMap<&String, &PeerEntry> = ordered.into_iter().collect();
        if let Ok(text) = serde_json::to_string_pretty(&map) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PeerEntry>> {
        self.inner.lock().unwrap()
    }

    /// Insert or refresh an address. Known node key / mesh win over empty
    /// ones; the operator's sources (`seed`/`configured`) are never demoted
    /// by a learned one.
    pub fn upsert(&self, addr: &str, node_key: &str, network_id: &str, source: &str) {
        let addr = addr.trim().to_string();
        if !valid_addr(&addr) {
            return;
        }
        let now = now_ms();
        let mut guard = self.lock();
        match guard.get_mut(&addr) {
            Some(entry) => {
                if entry.node_key.is_empty() && !node_key.is_empty() {
                    entry.node_key = node_key.to_string();
                }
                if entry.network_id.is_empty() && !network_id.is_empty() {
                    entry.network_id = network_id.to_string();
                }
                if (entry.source == SOURCE_SEED || entry.source == SOURCE_CONFIGURED)
                    && source != SOURCE_SEED
                    && source != SOURCE_CONFIGURED
                {
                    // keep the operator's word
                } else {
                    entry.source = source.to_string();
                }
            }
            None => {
                guard.insert(
                    addr.clone(),
                    PeerEntry {
                        addr,
                        node_key: node_key.to_string(),
                        network_id: network_id.to_string(),
                        source: source.to_string(),
                        first_seen_ms: now,
                        last_success_ms: 0,
                        last_attempt_ms: 0,
                        last_error: String::new(),
                        failures: 0,
                    },
                );
            }
        }
    }

    /// Called before dialing: orders the round-robin.
    pub fn record_attempt(&self, addr: &str) {
        let now = now_ms();
        if let Some(entry) = self.lock().get_mut(addr.trim()) {
            entry.last_attempt_ms = now;
        }
    }

    /// A sync actually moved bytes: this address is now verified and may be
    /// shared with others.
    pub fn record_success(&self, addr: &str, node_key: &str, network_id: &str) {
        self.upsert(addr, node_key, network_id, SOURCE_PEX);
        let now = now_ms();
        if let Some(entry) = self.lock().get_mut(addr.trim()) {
            entry.last_success_ms = now;
            entry.last_error.clear();
            entry.failures = 0;
        }
    }

    pub fn record_failure(&self, addr: &str, error: &str) {
        let now = now_ms();
        let addr = addr.trim();
        let mut guard = self.lock();
        let Some(entry) = guard.get_mut(addr) else {
            return;
        };
        entry.last_attempt_ms = now;
        entry.last_error = error.chars().take(120).collect();
        entry.failures = entry.failures.saturating_add(1);
        // Stale mDNS records and dead hearsay: an address only the network
        // told us about, which has never once answered and keeps failing,
        // is noise in the explorer. The operator's own seed/configured
        // addresses are never swept.
        let learned = !matches!(entry.source.as_str(), SOURCE_SEED | SOURCE_CONFIGURED);
        if learned
            && entry.last_success_ms == 0
            && entry.failures >= STALE_FAILURES
            && now.saturating_sub(entry.first_seen_ms) >= STALE_MIN_AGE_MS
        {
            guard.remove(addr);
        }
    }

    /// Test hook: backdate an entry as if it had been known longer.
    #[doc(hidden)]
    pub fn age_for_test(&self, addr: &str, age_ms: u64) {
        let now = now_ms();
        if let Some(entry) = self.lock().get_mut(addr.trim()) {
            entry.first_seen_ms = now.saturating_sub(age_ms);
        }
    }

    /// Merge addresses a peer told us about. Same mesh only; hearsay success
    /// is not recorded as ours - an entry stays unverified (never re-shared)
    /// until this node syncs with it itself.
    pub fn merge_pex(&self, peers: &[PeerWire], our_mesh: &str) -> usize {
        let mut learned = 0;
        for peer in peers {
            if peer.network_id != our_mesh {
                continue;
            }
            let known = self.lock().contains_key(peer.addr.trim());
            self.upsert(&peer.addr, &peer.node_key, &peer.network_id, SOURCE_PEX);
            if !known {
                learned += 1;
            }
        }
        learned
    }

    /// Record a peer's self-announcement from an exchange request.
    pub fn record_announce(&self, addr: &str, node_key: &str, network_id: &str, our_mesh: &str) {
        if network_id != our_mesh {
            return; // the wall: never learn a foreign-mesh address
        }
        self.upsert(addr, node_key, network_id, SOURCE_ANNOUNCE);
    }

    /// Learned addresses to pull from this cycle: oldest attempt first, so
    /// every known peer gets its turn even on slow cycles. Excludes the
    /// operator's own list (dialed anyway), foreign meshes, and addresses
    /// the wall already rejected (a mesh mismatch is permanent, not flaky).
    pub fn candidates(&self, our_mesh: &str, exclude: &[String], limit: usize) -> Vec<String> {
        let guard = self.lock();
        let mut picked: Vec<PeerEntry> = guard
            .values()
            .filter(|e| e.source != SOURCE_SEED && e.source != SOURCE_CONFIGURED)
            .filter(|e| e.network_id.is_empty() || e.network_id == our_mesh)
            .filter(|e| !e.last_error.contains("network mismatch"))
            .filter(|e| !exclude.iter().any(|x| x == &e.addr))
            .cloned()
            .collect();
        picked.sort_by(|a, b| {
            a.last_attempt_ms
                .cmp(&b.last_attempt_ms)
                .then_with(|| a.last_success_ms.cmp(&b.last_success_ms))
                .then_with(|| a.addr.cmp(&b.addr))
        });
        picked.truncate(limit);
        picked.into_iter().map(|e| e.addr).collect()
    }

    /// What this node tells others: verified (or operator-named) addresses,
    /// same mesh as the asker, most recently synced first.
    pub fn shareable(&self, mesh: &str, limit: usize) -> Vec<PeerWire> {
        let guard = self.lock();
        let mut picked: Vec<PeerEntry> = guard
            .values()
            .filter(|e| e.shareable())
            .filter(|e| {
                if mesh.is_empty() {
                    // open network: an empty id means open-or-unknown, both dialable
                    e.network_id.is_empty()
                } else {
                    e.network_id == mesh
                }
            })
            .cloned()
            .collect();
        picked.sort_by(|a, b| {
            b.last_success_ms
                .cmp(&a.last_success_ms)
                .then_with(|| a.addr.cmp(&b.addr))
        });
        picked.truncate(limit);
        picked
            .into_iter()
            .map(|e| PeerWire {
                addr: e.addr,
                node_key: e.node_key,
                network_id: if mesh.is_empty() {
                    String::new()
                } else {
                    e.network_id
                },
                last_success_ms: e.last_success_ms,
            })
            .collect()
    }

    /// Keep the table bounded: drop the least useful learned entries first.
    pub fn prune(&self) {
        let mut guard = self.lock();
        if guard.len() <= PEER_CAP {
            return;
        }
        let mut ranked: Vec<PeerEntry> = guard.values().cloned().collect();
        ranked.sort_by(|a, b| {
            let pinned = |e: &PeerEntry| e.source == SOURCE_SEED || e.source == SOURCE_CONFIGURED;
            pinned(b)
                .cmp(&pinned(a))
                .then_with(|| a.last_success_ms.cmp(&b.last_success_ms))
                .then_with(|| a.last_attempt_ms.cmp(&b.last_attempt_ms))
                .then_with(|| a.first_seen_ms.cmp(&b.first_seen_ms))
        });
        let drop: Vec<String> = ranked[PEER_CAP..].iter().map(|e| e.addr.clone()).collect();
        for addr in drop {
            guard.remove(&addr);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Full table for the explorer: most recently synced first.
    pub fn snapshot(&self) -> Vec<PeerEntry> {
        let mut all: Vec<PeerEntry> = self.lock().values().cloned().collect();
        all.sort_by(|a, b| {
            b.last_success_ms
                .cmp(&a.last_success_ms)
                .then_with(|| a.addr.cmp(&b.addr))
        });
        all
    }

    pub fn count_with_success(&self) -> usize {
        self.lock()
            .values()
            .filter(|e| e.last_success_ms > 0)
            .count()
    }
}

/// Sanity-check an announce from the wire before trusting the table with it.
pub fn plausible_announce(announce: &str) -> bool {
    valid_addr(announce)
}

/// Ask one peer "who else do you know?" - one connection, one exchange, done.
/// `hello` follows the same rule as pull sync: sent when this node is on a
/// walled mesh, omitted on the open network so older peers keep working.
/// A peer running older datu answers with an Error frame; that surfaces as
/// `Err("peer does not speak peer exchange: …")` for the caller to shrug at.
pub fn exchange_peers(
    peer_addr: &str,
    hello: Option<&crate::NodeHello>,
    node_key: &str,
    network_id: &str,
    announce: Option<&str>,
    limit: u16,
) -> Result<PeersResponse, String> {
    use std::net::TcpStream;
    let mut stream =
        TcpStream::connect(peer_addr).map_err(|e| format!("cannot connect to {peer_addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    if let Some(hello) = hello {
        crate::write_frame(&mut stream, hello)?;
    }
    let request = PeersRequest {
        magic: PEERS_MAGIC,
        node_key: node_key.to_string(),
        network_id: network_id.to_string(),
        announce: announce
            .filter(|a| plausible_announce(a))
            .map(str::to_string),
        limit,
    };
    crate::write_frame(&mut stream, &request)?;
    let bytes = crate::read_frame_bytes(&mut stream)?;
    if bytes.starts_with(&PEERS_MAGIC) {
        return PeersResponse::try_from_slice(&bytes)
            .map_err(|e| format!("peer sent an invalid exchange frame: {e}"));
    }
    match crate::ServerMessage::try_from_slice(&bytes) {
        Ok(crate::ServerMessage::Error(message)) => {
            Err(format!("peer does not speak peer exchange: {message}"))
        }
        _ => Err("peer answered the exchange with an unexpected frame".into()),
    }
}

/// Answer a peer-exchange request from our table.
///
/// Cross-mesh asks get an empty answer rather than an error: an open node
/// asked about a walled mesh simply knows nobody there, and a walled node
/// never reaches this point without an admitted hello that matched the wall.
pub fn answer_peers(
    request: &PeersRequest,
    table: Option<&PeerTable>,
    our_network: Option<&NetworkPolicy>,
) -> Result<PeersResponse, String> {
    if request.magic != PEERS_MAGIC {
        return Err("bad peer-exchange magic (this is a DATUPEX1 frame)".into());
    }
    let our_mesh = our_network
        .map(|n| n.network_id.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(announce) = request.announce.as_deref() {
        if plausible_announce(announce) {
            if let Some(table) = table {
                table.record_announce(announce, &request.node_key, &request.network_id, &our_mesh);
            }
        }
    }
    let same_mesh = request.network_id == our_mesh;
    let peers = if same_mesh {
        table
            .map(|t| {
                t.shareable(
                    &our_mesh,
                    request.limit.clamp(1, SHARE_LIMIT as u16) as usize,
                )
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(PeersResponse {
        magic: PEERS_MAGIC,
        peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PeerTable {
        PeerTable::new()
    }

    #[test]
    fn invalid_addresses_are_ignored() {
        let t = table();
        for bad in [
            "",
            "no-port",
            "host:notaport",
            "0.0.0.0:7476",
            "999.999.999.999:1",
        ] {
            t.upsert(bad, "", "", SOURCE_PEX);
        }
        assert_eq!(t.len(), 0, "none of the junk addresses landed");
        t.upsert("10.0.0.4:7476", "aa", "", SOURCE_PEX);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn hearsay_is_never_shared_until_synced() {
        let t = table();
        // A peer told us about two nodes; we have not synced with either.
        t.merge_pex(
            &[
                PeerWire {
                    addr: "10.0.0.5:7476".into(),
                    node_key: "bb".into(),
                    network_id: String::new(),
                    last_success_ms: 99_000, // their claim, not our fact
                },
                PeerWire {
                    addr: "10.0.0.6:7476".into(),
                    node_key: String::new(),
                    network_id: String::new(),
                    last_success_ms: 0,
                },
            ],
            "",
        );
        assert_eq!(t.len(), 2);
        assert!(
            t.shareable("", SHARE_LIMIT).is_empty(),
            "unverified addresses must not propagate"
        );
        // We sync with one of them: now it may be shared.
        t.record_success("10.0.0.5:7476", "bb", "");
        let shared = t.shareable("", SHARE_LIMIT);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].addr, "10.0.0.5:7476");
        // The success we recorded is ours, not the hearsay timestamp.
        assert!(shared[0].last_success_ms > 99_000);
    }

    #[test]
    fn operator_sources_share_without_a_sync() {
        let t = table();
        t.upsert("10.0.0.7:7476", "", "", SOURCE_SEED);
        t.upsert("10.0.0.8:7476", "", "", SOURCE_CONFIGURED);
        assert_eq!(t.shareable("", SHARE_LIMIT).len(), 2);
        // A learned refresh must not demote the operator's word.
        t.upsert("10.0.0.7:7476", "", "", SOURCE_PEX);
        let snapshot = t.snapshot();
        assert_eq!(
            snapshot
                .iter()
                .find(|e| e.addr == "10.0.0.7:7476")
                .unwrap()
                .source,
            SOURCE_SEED
        );
    }

    #[test]
    fn mesh_wall_filters_learn_share_and_candidates() {
        let t = table();
        t.merge_pex(
            &[PeerWire {
                addr: "10.0.0.9:7476".into(),
                node_key: String::new(),
                network_id: "mesh-a".into(),
                last_success_ms: 1,
            }],
            "mesh-b",
        );
        assert_eq!(t.len(), 0, "a foreign-mesh address is not even learned");
        t.merge_pex(
            &[PeerWire {
                addr: "10.0.0.9:7476".into(),
                node_key: String::new(),
                network_id: "mesh-a".into(),
                last_success_ms: 1,
            }],
            "mesh-a",
        );
        assert_eq!(t.len(), 1);
        // Open network never sees mesh-a addresses, and vice versa.
        assert!(t.shareable("", SHARE_LIMIT).is_empty());
        assert!(t.shareable("mesh-b", SHARE_LIMIT).is_empty());
        assert!(
            t.shareable("mesh-a", SHARE_LIMIT).is_empty(),
            "hearsay is not shared even in-mesh: sync first"
        );
        t.record_success("10.0.0.9:7476", "", "mesh-a");
        assert_eq!(t.shareable("mesh-a", SHARE_LIMIT).len(), 1);
        // A mesh mismatch is remembered as permanent: not a candidate again.
        t.record_failure("10.0.0.9:7476", "network mismatch: the wall refuses");
        assert!(
            t.candidates("mesh-a", &[], 10).is_empty(),
            "wall-refused peers must not be retried"
        );
    }

    #[test]
    fn candidates_rotate_oldest_attempt_first() {
        let t = table();
        t.upsert("10.0.1.1:7476", "", "", SOURCE_MDNS);
        t.upsert("10.0.1.2:7476", "", "", SOURCE_MDNS);
        t.upsert("10.0.1.3:7476", "", "", SOURCE_MDNS);
        t.record_attempt("10.0.1.2:7476");
        let picked = t.candidates("", &[], 2);
        assert_eq!(
            picked,
            vec!["10.0.1.1:7476".to_string(), "10.0.1.3:7476".to_string()],
            "never-attempted first, attempted last; operator-excluded by caller"
        );
        // The operator's own list is excluded from learned candidates.
        t.upsert("10.0.1.4:7476", "", "", SOURCE_CONFIGURED);
        assert!(!t
            .candidates("", &["10.0.1.1:7476".into()], 10)
            .contains(&"10.0.1.4:7476".into()));
    }

    #[test]
    fn cap_evicts_least_useful_learned_entries() {
        let t = table();
        t.upsert("198.51.100.7:7476", "", "", SOURCE_SEED);
        for i in 0..PEER_CAP {
            let host = format!("10.{}.{}.1", i / 200, i % 200);
            t.upsert(&format!("{host}:7476"), "", "", SOURCE_PEX);
        }
        assert!(t.len() > PEER_CAP);
        t.prune();
        assert_eq!(t.len(), PEER_CAP);
        let snapshot = t.snapshot();
        assert!(
            snapshot.iter().any(|e| e.addr == "198.51.100.7:7476"),
            "the operator's seed survives the eviction"
        );
    }

    #[test]
    fn persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("datu-pex-test-{}", now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = PeerTable::load(&dir);
        t.upsert("10.0.3.1:7476", "cc", "", SOURCE_PEX);
        t.record_success("10.0.3.1:7476", "cc", "");
        t.save();
        let reloaded = PeerTable::load(&dir);
        assert_eq!(reloaded.len(), 1);
        let entry = &reloaded.snapshot()[0];
        assert_eq!(entry.addr, "10.0.3.1:7476");
        assert!(entry.last_success_ms > 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn answer_peers_shares_verified_and_records_announce() {
        let t = table();
        t.upsert("10.0.4.1:7476", "dd", "", SOURCE_MDNS);
        t.record_success("10.0.4.1:7476", "dd", "");
        t.record_announce("10.0.4.2:7476", "ee", "", "");
        let request = PeersRequest {
            magic: PEERS_MAGIC,
            node_key: "ff".into(),
            network_id: String::new(),
            announce: Some("10.0.4.3:7476".into()),
            limit: 16,
        };
        let response = answer_peers(&request, Some(&t), None).unwrap();
        assert_eq!(response.magic, PEERS_MAGIC);
        let addrs: Vec<&str> = response.peers.iter().map(|p| p.addr.as_str()).collect();
        assert_eq!(addrs, vec!["10.0.4.1:7476"], "only the verified address");
        // The asker's announce landed in the table.
        assert!(t
            .snapshot()
            .iter()
            .any(|e| e.addr == "10.0.4.3:7476" && e.node_key == "ff"));
        // Cross-mesh ask: politely empty.
        let foreign = PeersRequest {
            network_id: "mesh-x".into(),
            ..request
        };
        let response = answer_peers(&foreign, Some(&t), None).unwrap();
        assert!(response.peers.is_empty());
        // Bad magic is refused.
        let bad = PeersRequest {
            magic: *b"NOTPEEX1",
            ..foreign
        };
        assert!(answer_peers(&bad, Some(&t), None).is_err());
    }
}
