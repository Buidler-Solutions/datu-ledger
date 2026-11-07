//! DATUP2P1: the native node-to-node sync protocol over raw TCP.
//!
//! No HTTP, no web stack, no third-party server: any two nodes that can
//! reach each other by IP reconcile directly. This is the protocol a home
//! node on a cheap computer speaks - the same bloom-filter reconciliation
//! as the HTTP and offline-file paths, over a minimal wire format:
//!
//! ```text
//! frame   = [u32 LE length][borsh message]
//! client → server: NodeHello (optional, first frame - network admission)
//! client → server: PullRequest   (bloom filter of ids the client has)
//! server → client: ServerMessage::Pull(PullResponse)  pages of what it lacks
//!                  | ServerMessage::Error(String)     then closes
//! ```
//!
//! Serving is untrusted work: the client verifies every signature before
//! accepting anything, so the peer and the network need no prior trust.
//!
//! # Network modes
//!
//! A node with **no** `network.json` is *permissionless*: it serves anyone
//! (today's behavior, the open network). A node with one may be
//! **permissioned**: peers must open with a signed [`NodeHello`] and be
//! admitted - an explicit `members` key or an on-ledger attestation from a
//! configured `root` (the same attestation graph that admits writers). A
//! non-empty `network_id` is a *mesh wall*: nodes only sync with peers
//! carrying the same id, in both directions, so a permissioned mesh and the
//! open network can never merge.

use borsh::{BorshDeserialize, BorshSerialize};
use datu_store::{Store, StoreError};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAGIC: [u8; 8] = *b"DATUP2P1";
/// Hard cap on a single frame; pages are far below this.
pub const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// Magic of the optional admission frame sent before the first pull.
pub const HELLO_MAGIC: [u8; 8] = *b"DATUHEL1";
/// How far a hello timestamp may drift from ours (clock-skew window).
pub const HELLO_MAX_SKEW_MS: u64 = 300_000;
/// Domain separator for hello signatures - never sign bare protocol fields.
const HELLO_DOMAIN: &[u8] = b"DATU-node-hello-v1";
/// What a walled server answers to a plain request from an unidentified
/// peer. The message itself explains the fix; clients surface it verbatim.
pub const HELLO_REQUIRED: &str = "hello required: this node is on a walled network - present a signed node hello (see `datu network` )";

pub const NETWORK_POLICY_VERSION: u8 = 1;

/// Who may **join** (sync with this node) - separate from the write policy
/// (`policy.json`), which decides whose *entries* land. Absent file =
/// permissionless, the open network: anyone may sync.
///
/// - `mode: "permissioned"` - peers must present a signed [`NodeHello`] and
///   be admitted: an explicit `members` key, or any key attested on-ledger
///   by a `roots` trust root (membership that propagates by the same sync
///   it authorizes - no manifest to re-issue, ever).
/// - `network_id` - the mesh wall. Nodes only sync with peers carrying the
///   same id ("" = the open network); `mode: "permissionless"` + an id is a
///   dedicated free observer of one walled mesh: it mirrors that mesh and
///   nothing else.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkPolicy {
    pub version: u8,
    /// "permissioned" or "permissionless".
    pub mode: String,
    /// Mesh boundary ("" = the open network).
    #[serde(default)]
    pub network_id: String,
    /// Node identity keys admitted to sync (hex ed25519).
    #[serde(default)]
    pub members: Vec<String>,
    /// Trust roots: any node key they attest on-ledger is admitted too.
    #[serde(default)]
    pub roots: Vec<String>,
}

impl NetworkPolicy {
    pub fn permissionless() -> NetworkPolicy {
        NetworkPolicy {
            version: NETWORK_POLICY_VERSION,
            mode: "permissionless".into(),
            network_id: String::new(),
            members: Vec::new(),
            roots: Vec::new(),
        }
    }

    pub fn is_permissioned(&self) -> bool {
        self.mode == "permissioned"
    }

    /// May our own node run under this policy? Fail-closed startup check:
    /// a permissioned node whose key is neither member nor root refuses to
    /// start rather than run isolated.
    pub fn self_admitted(&self, own_key: &str) -> bool {
        self.members.iter().any(|k| k == own_key) || self.roots.iter().any(|k| k == own_key)
    }

    pub fn from_json(text: &str) -> Result<NetworkPolicy, String> {
        let policy: NetworkPolicy =
            serde_json::from_str(text).map_err(|e| format!("bad network JSON: {e}"))?;
        if policy.version != NETWORK_POLICY_VERSION {
            return Err(format!(
                "unsupported network policy version {} (expected {NETWORK_POLICY_VERSION})",
                policy.version
            ));
        }
        if policy.mode != "permissioned" && policy.mode != "permissionless" {
            return Err(format!(
                "mode must be 'permissioned' or 'permissionless', not '{}'",
                policy.mode
            ));
        }
        Ok(policy)
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

/// Human name for a mesh id in error messages.
pub fn mesh_name(id: &str) -> &str {
    if id.is_empty() {
        "the open network"
    } else {
        id
    }
}

/// Signed peer introduction: proves control of the node identity key and
/// carries the mesh id. Sent as the first frame; a fresh signature per
/// connection plus the clock-skew window is the replay protection.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct NodeHello {
    pub magic: [u8; 8],
    /// Hex ed25519 verifying key of the dialing node.
    pub node_key: String,
    /// Mesh the dialer is on ("" = the open network).
    pub network_id: String,
    pub timestamp_ms: u64,
    /// Ed25519 signature over the domain-separated hello bytes.
    pub signature: [u8; 64],
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hello_bytes(node_key: &str, network_id: &str, timestamp_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(HELLO_DOMAIN);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(node_key.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(network_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&timestamp_ms.to_le_bytes());
    bytes
}

/// Build this node's introduction. Signed fresh on every connection, so a
/// captured hello cannot be replayed outside the clock-skew window.
pub fn sign_hello(key: &ed25519_dalek::SigningKey, network_id: &str) -> NodeHello {
    let node_key = hex::encode(key.verifying_key().as_bytes());
    let timestamp_ms = now_ms();
    let signature = key
        .sign(&hello_bytes(&node_key, network_id, timestamp_ms))
        .to_bytes();
    NodeHello {
        magic: HELLO_MAGIC,
        node_key,
        network_id: network_id.to_string(),
        timestamp_ms,
        signature,
    }
}

/// Verify a hello: signature over the domain-separated bytes, then the
/// clock-skew window.
pub fn verify_hello(hello: &NodeHello) -> Result<(), String> {
    if hello.magic != HELLO_MAGIC {
        return Err("bad hello magic".into());
    }
    let key_bytes: [u8; 32] = hex::decode(&hello.node_key)
        .map_err(|_| "hello node_key is not hex".to_string())?
        .try_into()
        .map_err(|_| "hello node_key must be 32 bytes".to_string())?;
    let verifying =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| "bad hello node_key".to_string())?;
    let signature = Signature::from_bytes(&hello.signature);
    verifying
        .verify(&hello_bytes(&hello.node_key, &hello.network_id, hello.timestamp_ms), &signature)
        .map_err(|_| "hello signature does not verify".to_string())?;
    let now = now_ms();
    let skew = now.abs_diff(hello.timestamp_ms);
    if skew > HELLO_MAX_SKEW_MS {
        return Err(format!(
            "hello timestamp outside the clock-skew window ({skew}ms off)"
        ));
    }
    Ok(())
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PullRequest {
    pub magic: [u8; 8],
    pub bloom_m: u64,
    pub bloom_k: u32,
    pub bloom_bits: Vec<u8>,
    pub cursor: Option<i64>,
    pub limit: u16,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PullResponse {
    pub entries: Vec<datu_core::Entry>,
    /// Sent only on the first page (cursor = None).
    pub checkpoints: Vec<datu_core::Checkpoint>,
    pub cursor: Option<i64>,
    pub more: bool,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum ServerMessage {
    Pull(PullResponse),
    Error(String),
}

fn write_frame<T: BorshSerialize>(stream: &mut TcpStream, message: &T) -> Result<(), String> {
    let bytes = borsh::to_vec(message).map_err(|e| e.to_string())?;
    let len = u32::try_from(bytes.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_le_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| format!("send failed: {e}"))
}

fn read_frame_bytes(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("connection closed mid-frame: {e}"))?;
    let len = u32::from_le_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err("bad frame length".into());
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("truncated frame: {e}"))?;
    Ok(buf)
}

/// Answer one PullRequest from the store.
pub fn answer(request: &PullRequest, store: &Store) -> Result<ServerMessage, String> {
    if request.magic != MAGIC {
        return Err("bad protocol magic (this is a DATUP2P1 port)".into());
    }
    let bloom = datu_core::BloomFilter::from_parts(
        request.bloom_m,
        request.bloom_k,
        &request.bloom_bits,
    )
    .ok_or_else(|| "malformed bloom filter".to_string())?;
    let limit = request.limit.clamp(1, 2000) as usize;
    let (entries, cursor, more) = store
        .missing_page(&bloom, request.cursor, limit)
        .map_err(|e| e.to_string())?;
    let checkpoints = if request.cursor.is_none() {
        store.all_checkpoints().map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };
    Ok(ServerMessage::Pull(PullResponse {
        entries,
        checkpoints,
        cursor,
        more,
    }))
}

/// Does this server demand a hello before serving? Any node with a mesh
/// id - or permissioned admission - must learn who is dialing before it
/// shares anything. Pure open nodes stay promiscuous.
fn requires_hello(network: Option<&NetworkPolicy>) -> bool {
    network
        .map(|n| n.is_permissioned() || !n.network_id.is_empty())
        .unwrap_or(false)
}

/// Admission at the door: verify the hello signature, enforce the mesh wall
/// (`network_id` must match ours, empty = the open network), and - when this
/// node is permissioned - require membership or an on-ledger attestation
/// from a configured root.
fn admit_peer(
    hello: &NodeHello,
    store: &Store,
    network: Option<&NetworkPolicy>,
) -> Result<(), String> {
    verify_hello(hello)?;
    let ours = network.map(|n| n.network_id.as_str()).unwrap_or("");
    if hello.network_id != ours {
        return Err(format!(
            "network mismatch: this node is on {}, the peer presented {} - the wall refuses",
            mesh_name(ours),
            mesh_name(&hello.network_id)
        ));
    }
    if let Some(net) = network {
        if net.is_permissioned() && !net.members.iter().any(|k| k == &hello.node_key) {
            let attested = store
                .key_attested_by(&hello.node_key, &net.roots)
                .map_err(|e| format!("cannot check attestations: {e}"))?;
            if !attested {
                return Err(format!(
                    "not admitted: key {} is not a member of this network and holds no attestation from a configured root (see `datu network`)",
                    &hello.node_key[..8.min(hello.node_key.len())]
                ));
            }
        }
    }
    Ok(())
}

/// Refuse and close *cleanly*. A compliant client already has its request
/// on the wire; closing with it unread would make the OS send a TCP reset
/// that destroys our error message in transit - the one frame that tells
/// the dialer why they were refused. So: deliver the error (FIN), then
/// drain until the peer hangs up or a short timeout bounds hostile peers.
fn refuse(stream: &mut TcpStream, message: String) {
    let _ = write_frame(stream, &ServerMessage::Error(message));
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut sink = [0u8; 4096];
    loop {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Serve PullRequests until the client hangs up. Errors only abort this
/// connection. `first` is the already-read request that triggered serving.
fn serve_pull_loop(stream: &mut TcpStream, store: &Store, first: PullRequest) {
    let mut pending = Some(first);
    loop {
        let request = match pending.take() {
            Some(r) => r,
            None => {
                let bytes = match read_frame_bytes(stream) {
                    Ok(b) => b,
                    Err(_) => return, // client done
                };
                match PullRequest::try_from_slice(&bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = write_frame(
                            stream,
                            &ServerMessage::Error(format!("bad request frame: {e}")),
                        );
                        return;
                    }
                }
            }
        };
        match answer(&request, store) {
            Ok(message) => {
                if write_frame(stream, &message).is_err() {
                    return;
                }
            }
            Err(message) => {
                let _ = write_frame(stream, &ServerMessage::Error(message));
                return;
            }
        }
    }
}

/// Serve one p2p connection. The first frame decides the door: a
/// [`NodeHello`] is verified and admitted (or refused), a bare
/// [`PullRequest`] is served directly on the open network - and refused
/// with [`HELLO_REQUIRED`] on a walled one.
pub fn handle_connection(mut stream: TcpStream, store: &Store, network: Option<&NetworkPolicy>) {
    let bytes = match read_frame_bytes(&mut stream) {
        Ok(b) => b,
        Err(_) => return, // client gone before saying anything
    };
    if bytes.starts_with(&HELLO_MAGIC) {
        let hello = match NodeHello::try_from_slice(&bytes) {
            Ok(h) => h,
            Err(e) => {
                refuse(&mut stream, format!("bad hello frame: {e}"));
                return;
            }
        };
        if let Err(message) = admit_peer(&hello, store, network) {
            refuse(&mut stream, message);
            return;
        }
        // Admitted: the next frame (if any) starts the pull loop.
        let bytes = match read_frame_bytes(&mut stream) {
            Ok(b) => b,
            Err(_) => return, // hello-only probe
        };
        match PullRequest::try_from_slice(&bytes) {
            Ok(request) => serve_pull_loop(&mut stream, store, request),
            Err(e) => {
                let _ = write_frame(
                    &mut stream,
                    &ServerMessage::Error(format!("expected a pull request after the hello: {e}")),
                );
            }
        }
    } else if bytes.starts_with(&MAGIC) {
        if requires_hello(network) {
            refuse(&mut stream, HELLO_REQUIRED.into());
            return;
        }
        match PullRequest::try_from_slice(&bytes) {
            Ok(request) => serve_pull_loop(&mut stream, store, request),
            Err(e) => {
                let _ = write_frame(
                    &mut stream,
                    &ServerMessage::Error(format!("bad request frame: {e}")),
                );
            }
        }
    } else {
        refuse(&mut stream, "unknown frame (expected DATUP2P1 or DATUHEL1)".into());
    }
}

/// What a full pull from one peer changed locally.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PullStats {
    pub entries_new: usize,
    pub entries_existing: usize,
    /// Skipped by our local writer policy (gated namespace, unadmitted
    /// author, read-only). Skipped, never fatal: the peer keeps serving.
    pub entries_denied: usize,
    pub checkpoints_new: usize,
}

/// Client: pull everything `peer_addr` has that this store lacks, verify
/// every record, and merge. A peer serving contradictory history aborts
/// with a conflict error - that is fork evidence, not a sync failure.
///
/// `hello` is this node's signed introduction, sent before the first
/// request when we are on a walled mesh; `None` on the open network.
pub fn pull_and_merge(
    peer_addr: &str,
    store: &Store,
    page_limit: u16,
    hello: Option<&NodeHello>,
) -> Result<PullStats, String> {
    let mut stream =
        TcpStream::connect(peer_addr).map_err(|e| format!("cannot connect to {peer_addr}: {e}"))?;
    if let Some(hello) = hello {
        write_frame(&mut stream, hello).map_err(|e| {
            format!(
                "{e} - if this peer runs an older datu without network modes, walled-mesh sync needs matching versions"
            )
        })?;
    }
    let ids = store.entry_ids().map_err(|e| e.to_string())?;
    let mut bloom = datu_core::BloomFilter::new_for(ids.len().max(16), 0.001);
    for id in &ids {
        bloom.insert(id);
    }
    let mut stats = PullStats::default();
    let mut cursor: Option<i64> = None;
    loop {
        let request = PullRequest {
            magic: MAGIC,
            bloom_m: bloom.bit_count(),
            bloom_k: bloom.hash_count(),
            bloom_bits: bloom.bit_bytes(),
            cursor,
            limit: page_limit,
        };
        write_frame(&mut stream, &request)?;
        let bytes = read_frame_bytes(&mut stream)?;
        let message = ServerMessage::try_from_slice(&bytes)
            .map_err(|e| format!("peer sent an invalid frame: {e}"))?;
        let response = match message {
            ServerMessage::Pull(r) => r,
            ServerMessage::Error(m) => return Err(format!("peer refused: {m}")),
        };
        for entry in &response.entries {
            match store.insert_entry(entry) {
                Ok(true) => stats.entries_new += 1,
                Ok(false) => stats.entries_existing += 1,
                Err(StoreError::Denied(_)) => stats.entries_denied += 1,
                Err(e) => {
                    return Err(format!(
                        "peer {peer_addr} serves history contradicting ours: {e} - \
                         this is fork evidence; collect their witness stream and run `datu prove-fork`"
                    ))
                }
            }
        }
        for checkpoint in &response.checkpoints {
            match store.append_checkpoint(checkpoint) {
                Ok(true) => stats.checkpoints_new += 1,
                Ok(false) => {}
                Err(e) => {
                    return Err(format!(
                        "peer {peer_addr} serves a contradictory checkpoint: {e} - fork evidence"
                    ))
                }
            }
        }
        cursor = response.cursor;
        if !response.more || cursor.is_none() {
            return Ok(stats);
        }
    }
}
