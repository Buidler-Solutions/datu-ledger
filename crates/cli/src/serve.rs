//! `datu serve`: a local HTTP endpoint + ledger explorer.
//!
//! Any node can run this. It is a *mirror node*: it serves and accepts only
//! fully-signed, self-verifying records. A lying explorer is caught by
//! witnesses; a lying submitter is rejected by signature verification. The
//! operator of this server is never a trust anchor.
//!
//! Routes:
//!   GET  /                     explorer (HTML)
//!   GET  /v1/status            node summary
//!   GET  /v1/entries           ?limit&ns&author - recent entries
//!   GET  /v1/entry/{id}        full signed entry (JSON)
//!   GET  /v1/feed/{author}     author's feed + head (for dApps building a
//!                              sign request: seq/prev of the next entry)
//!   GET  /v1/checkpoints       every signer's latest witness root
//!   GET  /v1/peers             ?announce=&key=&network= - the peer table
//!                              (HTTP peer exchange: shares known nodes,
//!                              records the asker's announce)
//!   GET  /v1/conflicts         recorded feed disputes (preserved evidence)
//!   GET  /v1/conflict/{id}     full incoming entry of one dispute
//!   POST /v1/entries           submit a signed entry (JSON, base64 payload;
//!                              rate-limited per peer IP, 429 + Retry-After)
//!   POST /v1/sync/haves        set-reconciliation: send a Bloom filter of
//!                              the ids you have, receive what you lack

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use datu_core::bloom::BloomFilter;
use datu_core::{Checkpoint, CheckpointBody, Entry};
use datu_p2p::peers::{PeerTable, SHARE_LIMIT};
use datu_p2p::NetworkPolicy;
use datu_store::{Store, StoreError, WritePolicy};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use datu_wallet::wire::{entry_from_submission, entry_full_json};

/// Hard cap on an HTTP request body (a single entry JSON is ≤ ~350 KB).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Request-line plus headers budget: a slowloris or header-flood client
/// cannot grow an allocation past this, and the read timeout bounds stalls.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HEADER_COUNT: usize = 64;
/// Concurrent connection ceiling: thread-per-connection is fine, unbounded
/// threads are not.
pub const MAX_CONNECTIONS: usize = 256;
/// Per-socket I/O deadline (read and write).
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Default per-peer submission budget for `POST /v1/entries`.
pub const DEFAULT_SUBMIT_PER_MIN: usize = 60;

/// Default budget for the sync reconciliation route, per peer IP per
/// minute: one full pull of a 240k-entry ledger per window. Generous for
/// honest syncs (a fresh node pages through in well under a minute),
/// bounded for scan amplification (every haves page walks the store).
pub const DEFAULT_HAVES_PER_MIN: usize = 120;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Per-peer sliding-window limiter for unauthenticated routes - spam
/// resistance without accounts or tokens. Configured per route: the write
/// door prices retries against spam, the sync route against scan
/// amplification. `per_min == 0` disables it.
pub struct PeerLimiter {
    per_min: usize,
    hits: Mutex<std::collections::HashMap<String, Vec<u64>>>,
}

impl PeerLimiter {
    pub fn new(per_min: usize) -> Self {
        PeerLimiter {
            per_min,
            hits: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// `None` = allowed (and counted); `Some(retry_after_secs)` = this peer
    /// is over the window. Fails open: this is spam shaping, not a security
    /// boundary - every submission still verifies cryptographically.
    pub fn check(&self, peer: &str, now_ms: u64) -> Option<u64> {
        if self.per_min == 0 {
            return None;
        }
        const WINDOW_MS: u64 = 60_000;
        let mut hits = self.hits.lock().ok()?;
        let window = hits.entry(peer.to_string()).or_default();
        window.retain(|t| now_ms.saturating_sub(*t) < WINDOW_MS);
        if window.len() >= self.per_min {
            let oldest = window.first().copied().unwrap_or(now_ms);
            let retry = WINDOW_MS - now_ms.saturating_sub(oldest);
            return Some((retry / 1000).max(1));
        }
        window.push(now_ms);
        if hits.len() > 10_000 {
            hits.retain(|_, w| !w.is_empty());
        }
        None
    }
}

/// What this node can say about its own governance (design §H), computed once
/// at startup and attached to every admission decision the node reports.
#[derive(Clone, Debug)]
pub(crate) struct Governance {
    pub freshness: String,
    pub reason: String,
    pub manifest_id: Option<String>,
}

fn governance(data_dir: &Path) -> Result<Option<Governance>, String> {
    let Some(net) = crate::read_network(data_dir)? else {
        return Ok(None);
    };
    let Some(root) = net.manifest_root.clone() else {
        return Ok(None);
    };
    let store = Store::open(&data_dir.join("node.db")).map_err(|e| e.to_string())?;
    let st =
        datu_store::manifest::status(&store, &net.network_id, std::slice::from_ref(&root), None)?;
    Ok(Some(Governance {
        freshness: st.freshness.as_str().to_string(),
        reason: st.reason,
        manifest_id: st.manifest_id,
    }))
}

pub fn serve(
    data_dir: &Path,
    addr: &str,
    policy: Option<WritePolicy>,
    submit_per_min: usize,
    haves_per_min: usize,
    peers: Option<Arc<PeerTable>>,
) -> Result<(), String> {
    // Fail fast if there is no node to serve.
    let store = Store::open_with_policy(&data_dir.join("node.db"), policy.clone())
        .map_err(|e| e.to_string())?;
    drop(store);
    let network = crate::read_network(data_dir)?;
    let governance = Arc::new(governance(data_dir)?);
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    println!("datu node serving http://{addr}");
    match &network {
        None => println!("  network:   open (permissionless - any node may join and sync)"),
        Some(n) if n.is_permissioned() => println!(
            "  network:   permissioned mesh '{}' ({} member(s), {} attestation root(s))",
            if n.network_id.is_empty() {
                "(unnamed)"
            } else {
                &n.network_id
            },
            n.members.len(),
            n.roots.len()
        ),
        Some(n) if !n.network_id.is_empty() => {
            println!(
                "  network:   walled mesh '{}' (permissionless mirror)",
                n.network_id
            )
        }
        Some(_) => println!("  network:   open (permissionless - any node may join and sync)"),
    }
    match &policy {
        None => println!("  mode:      open observer (no policy file: accepts everything)"),
        Some(p) if p.readonly => {
            println!("  mode:      read-only mirror (no new entries accepted; view + witness only)")
        }
        Some(p) => println!(
            "  mode:      validator gate ({} trust root(s), {} explicit writer(s), gated: {})",
            p.attestors.len(),
            p.writers.len(),
            p.gated.join(", ")
        ),
    }
    match governance.as_ref() {
        None => {}
        Some(g) => println!(
            "  governance: manifest {} - {}{}",
            g.manifest_id
                .as_deref()
                .map(crate::short)
                .unwrap_or("(none)"),
            g.freshness,
            if g.freshness == "current" {
                String::new()
            } else {
                format!(" ({})", g.reason)
            }
        ),
    }
    println!("  explorer:  http://{addr}/");
    println!("  submit:    POST http://{addr}/v1/entries   (signed entry JSON)");
    if submit_per_min > 0 {
        println!(
            "  limits:    {submit_per_min} submissions/min per peer IP (--submit-per-min, 0 = off)"
        );
    }
    if haves_per_min > 0 {
        println!("  sync:      {haves_per_min} haves requests/min per peer IP (--haves-per-min, 0 = off)");
    }
    println!("  feed head: GET  http://{addr}/v1/feed/{{author}}");
    println!("  peers:     GET  http://{addr}/v1/peers   (peer exchange over HTTP)");
    println!("ctrl-c to stop");
    let dir = data_dir.to_path_buf();
    let limiter = (submit_per_min > 0).then(|| Arc::new(PeerLimiter::new(submit_per_min)));
    let haves_limiter = (haves_per_min > 0).then(|| Arc::new(PeerLimiter::new(haves_per_min)));
    let empty_table = Arc::new(PeerTable::new());
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if now > MAX_CONNECTIONS {
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            let _ = respond_json(
                &mut stream,
                "503 Service Unavailable",
                &serde_json::json!({ "error": "too many concurrent connections" }),
            );
            continue;
        }
        let active = active.clone();
        let dir = dir.clone();
        let policy = policy.clone();
        let network = network.clone();
        let limiter = limiter.clone();
        let haves_limiter = haves_limiter.clone();
        let governance = governance.clone();
        let peers = peers.clone().unwrap_or_else(|| empty_table.clone());
        std::thread::spawn(move || {
            let _ = handle(
                stream,
                &dir,
                policy,
                network,
                limiter,
                haves_limiter,
                governance,
                peers,
            );
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle(
    stream: TcpStream,
    data_dir: &Path,
    policy: Option<WritePolicy>,
    network: Option<NetworkPolicy>,
    limiter: Option<Arc<PeerLimiter>>,
    haves_limiter: Option<Arc<PeerLimiter>>,
    governance: Arc<Option<Governance>>,
    peers: Arc<PeerTable>,
) -> Result<(), String> {
    let mut stream = stream;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    if let Err(e) = handle_inner(
        &mut stream,
        data_dir,
        policy,
        network,
        limiter,
        haves_limiter,
        governance,
        peers,
    ) {
        let _ = respond_json(
            &mut stream,
            "400 Bad Request",
            &serde_json::json!({ "error": e }),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_inner(
    stream: &mut TcpStream,
    data_dir: &Path,
    policy: Option<WritePolicy>,
    network: Option<NetworkPolicy>,
    limiter: Option<Arc<PeerLimiter>>,
    haves_limiter: Option<Arc<PeerLimiter>>,
    governance: Arc<Option<Governance>>,
    peers: Arc<PeerTable>,
) -> Result<(), String> {
    let request = match read_request(stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let (method, path, body) = request;
    let route = path.split('?').next().unwrap_or("/").to_string();
    let query = path.split_once('?').map(|x| x.1).unwrap_or("").to_string();

    if method == "OPTIONS" {
        respond(stream, "204 No Content", "text/plain", "")?;
        return Ok(());
    }

    let store =
        Store::open_with_policy(&data_dir.join("node.db"), policy).map_err(|e| e.to_string())?;

    match (method.as_str(), route.as_str()) {
        ("GET", "/") => respond(stream, "200 OK", "text/html; charset=utf-8", EXPLORER_HTML),
        // Locally-verifying pages share one implementation of BLAKE3 and the
        // coverage-path check with the wallet extension.
        ("GET", "/blake3.js") => respond(stream, "200 OK", "application/javascript", BLAKE3_JS),
        ("GET", "/coverage.js") => respond(stream, "200 OK", "application/javascript", COVERAGE_JS),
        ("GET", "/v1/status") => {
            let report = store.verify_all().map_err(|e| e.to_string())?;
            let policy = match store.policy() {
                None => serde_json::json!({ "mode": "open-observer" }),
                Some(p) if p.readonly => serde_json::json!({ "mode": "read-only" }),
                Some(p) => serde_json::json!({
                    "mode": "validator",
                    "gated": p.gated,
                    "attestors": p.attestors.len(),
                    "writers": p.writers.len(),
                    "min_cosigners": p.min_cosigners,
                    "required_roles": p.required_roles,
                }),
            };
            let network = match &network {
                None => serde_json::json!({ "mode": "open", "network_id": "" }),
                Some(n) => serde_json::json!({
                    "mode": n.mode,
                    "network_id": n.network_id,
                    "members": n.members.len(),
                    "roots": n.roots.len(),
                }),
            };
            let json = serde_json::json!({
                "ok": true,
                "entries": report.entries,
                "feeds": report.feeds,
                "checkpoints": report.checkpoints,
                "pending_links": report.pending_links,
                "conflicts": report.conflicts,
                "contracts_failed": report.contracts_failed,
                "policy": policy,
                "network": network,
                "manifest": match governance.as_ref() {
                    None => serde_json::Value::Null,
                    Some(g) => serde_json::json!({
                        "freshness": g.freshness,
                        "reason": g.reason,
                        "manifest_id": g.manifest_id,
                    }),
                },
            });
            respond_json(stream, "200 OK", &json)
        }
        ("GET", "/v1/entries") => {
            // Two shapes: classic offset paging (ns/author filters) and the
            // indexer tail `?after=<cursor>`: oldest-first, resumable, with
            // the next opaque cursor in the answer. The cursor encodes the
            // store's internal insertion ordinal and nothing else.
            let after = query
                .split('&')
                .find_map(|pair| pair.strip_prefix("after="))
                .and_then(decode_cursor);
            let (ns, author, limit, offset) = parse_list_query(&query);
            if let Some(after_ord) = after {
                let batch = store
                    .entries_after(after_ord, limit)
                    .map_err(|e| e.to_string())?;
                let next_cursor = batch
                    .last()
                    .map(|(ord, _)| encode_cursor(*ord))
                    .unwrap_or_else(|| encode_cursor(after_ord));
                let items: Vec<serde_json::Value> = batch
                    .iter()
                    .map(|(_, e)| entry_summary_json(&store, e).map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?;
                respond_json(
                    stream,
                    "200 OK",
                    &serde_json::json!({ "entries": items, "next_cursor": next_cursor }),
                )?;
                return Ok(());
            }
            let entries = store
                .list_page(ns.as_deref(), author.as_deref(), limit, offset)
                .map_err(|e| e.to_string())?;
            let items: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| entry_summary_json(&store, e).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            respond_json(stream, "200 OK", &serde_json::json!({ "entries": items }))
        }
        ("GET", "/v1/entry") | ("GET", "/v1/entry/") => respond_json(
            stream,
            "400 Bad Request",
            &serde_json::json!({"error":"missing entry id"}),
        ),
        ("GET", e) if e.starts_with("/v1/entry/") => {
            let id_hex = &e["/v1/entry/".len()..];
            match hex::decode(id_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(id) => match store.get_entry(&id).map_err(|e| e.to_string())? {
                    Some(entry) => {
                        let mut json = entry_full_json(&entry)?;
                        if let Some(obj) = json.as_object_mut() {
                            // This node's own note about where it first saw
                            // the entry. Not signed, not synced, not a
                            // ledger fact - labelled accordingly in the UI.
                            obj.insert(
                                "first_seen".into(),
                                serde_json::json!(store.first_seen_of(&id).unwrap_or(None)),
                            );
                        }
                        respond_json(stream, "200 OK", &json)
                    }
                    None => respond_json(
                        stream,
                        "404 Not Found",
                        &serde_json::json!({"error":"entry not found"}),
                    ),
                },
                None => respond_json(
                    stream,
                    "400 Bad Request",
                    &serde_json::json!({"error":"bad entry id"}),
                ),
            }
        }
        // Pending view of a governed agreement: the contract an anchor
        // declares, judged over the entries citing it. The read shape for
        // "conditions outstanding" surfaces (Signet panel, registrar dApp).
        ("GET", c) if c.starts_with("/v1/contract/status/") => {
            let id_hex = &c["/v1/contract/status/".len()..];
            let id = match hex::decode(id_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(id) => id,
                None => {
                    respond_json(
                        stream,
                        "400 Bad Request",
                        &serde_json::json!({"error":"bad entry id"}),
                    )?;
                    return Ok(());
                }
            };
            match store.contract_outlook(&id).map_err(|e| e.to_string())? {
                None => respond_json(
                    stream,
                    "404 Not Found",
                    &serde_json::json!({
                        "error": "entry declares no contract"
                    }),
                ),
                Some(outlook) => {
                    let conditions: Vec<serde_json::Value> = outlook
                        .conditions
                        .iter()
                        .map(|condition| {
                            serde_json::json!({
                                "kind": condition.kind.as_str(),
                                "requirement": condition.requirement,
                                "required": condition.required,
                                "found": condition.found,
                                "met": condition.met,
                            })
                        })
                        .collect();
                    let citing: Vec<serde_json::Value> = outlook
                        .citing
                        .iter()
                        .map(|cited| {
                            serde_json::json!({
                                "id": hex::encode(cited.id),
                                "author": cited.author,
                                "namespace": cited.namespace,
                                "kind": cited.kind,
                                "timestamp_ms": cited.timestamp_ms,
                            })
                        })
                        .collect();
                    respond_json(
                        stream,
                        "200 OK",
                        &serde_json::json!({
                            "ok": true,
                            "anchor": hex::encode(id),
                            "contract_id": hex::encode(outlook.contract_id),
                            "version": outlook.version,
                            "kind": outlook.kind,
                            "admits": outlook.admits,
                            "ready": outlook.ready,
                            "reasons": outlook.reasons,
                            "conditions": conditions,
                            "citing": citing,
                        }),
                    )
                }
            }
        }
        ("GET", f) if f.starts_with("/v1/feed/") => {
            let author = &f["/v1/feed/".len()..];
            let feed = store.feed(author).map_err(|e| e.to_string())?;
            let head = feed
                .last()
                .map(|e| {
                    Ok::<_, String>(serde_json::json!({
                        "seq": e.body.seq,
                        "id": hex::encode(e.id().map_err(|e| e.to_string())?),
                    }))
                })
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
            // Next-entry guidance for dApps building a sign request:
            let next = match feed.last() {
                Some(e) => serde_json::json!({
                    "seq": e.body.seq + 1,
                    "prev": hex::encode(e.id().map_err(|e| e.to_string())?),
                }),
                None => serde_json::json!({ "seq": 0, "prev": null }),
            };
            let items: Vec<serde_json::Value> = feed
                .iter()
                .map(|e| entry_summary_json(&store, e).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "author": author, "head": head, "next": next, "entries": items,
                }),
            )
        }
        ("GET", "/v1/checkpoints") => {
            let mut latest: std::collections::BTreeMap<String, datu_core::Checkpoint> =
                std::collections::BTreeMap::new();
            for cp in store.all_checkpoints().map_err(|e| e.to_string())? {
                let update = match latest.get(&cp.body.signer) {
                    Some(prev) => prev.body.height < cp.body.height,
                    None => true,
                };
                if update {
                    latest.insert(cp.body.signer.clone(), cp);
                }
            }
            let items: Vec<serde_json::Value> = latest
                .values()
                .map(|cp| {
                    Ok(serde_json::json!({
                        "id": hex::encode(cp.id().map_err(|e| e.to_string())?),
                        "signer": cp.body.signer,
                        "height": cp.body.height,
                        "entries_count": cp.body.entries_count,
                        "entry_ids_root": hex::encode(cp.body.entry_ids_root),
                        "timestamp_ms": cp.body.timestamp_ms,
                    }))
                })
                .collect::<Result<_, String>>()?;
            respond_json(stream, "200 OK", &serde_json::json!({ "witnesses": items }))
        }
        // The peer table, read by three audiences: the explorer's ecosystem
        // view, other nodes doing HTTP peer exchange, and humans. `announce`
        // (with `key`/`network`) records the asker so their node becomes
        // discoverable by the next asker - the same deal as the native wire.
        ("GET", "/v1/peers") => {
            let mut announce = None;
            let mut node_key = String::new();
            let mut asker_mesh = String::new();
            for pair in query.split('&') {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("");
                let value = parts.next().unwrap_or("");
                if value.is_empty() {
                    continue;
                }
                match key {
                    "announce" => announce = Some(value.to_string()),
                    "key" => node_key = value.to_string(),
                    "network" => asker_mesh = value.to_string(),
                    _ => {}
                }
            }
            let our_mesh = network
                .as_ref()
                .map(|n| n.network_id.clone())
                .unwrap_or_default();
            if let Some(announce) = announce
                .as_deref()
                .filter(|a| datu_p2p::peers::plausible_announce(a))
            {
                peers.record_announce(announce, &node_key, &asker_mesh, &our_mesh);
            }
            // The wall, politely: a cross-mesh ask is answered, but empty.
            let shared: Vec<serde_json::Value> = if asker_mesh == our_mesh {
                peers
                    .shareable(&our_mesh, SHARE_LIMIT)
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "addr": p.addr,
                            "node_key": p.node_key,
                            "network_id": p.network_id,
                            "last_success_ms": p.last_success_ms,
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let known: Vec<serde_json::Value> = peers
                .snapshot()
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "addr": e.addr,
                        "node_key": e.node_key,
                        "network_id": e.network_id,
                        "source": e.source,
                        "first_seen_ms": e.first_seen_ms,
                        "last_success_ms": e.last_success_ms,
                        "last_attempt_ms": e.last_attempt_ms,
                        "last_error": e.last_error,
                    })
                })
                .collect();
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "network": {
                        "mode": network.as_ref().map(|n| n.mode.as_str()).unwrap_or("open"),
                        "network_id": our_mesh,
                    },
                    "peers": shared,
                    "known": known,
                }),
            )
        }
        // Witness time-attestation over HTTP: the offline-verifiable proof
        // that a checkpoint's signer had seen this entry as of the claimed
        // time. `/v1/coverage/<entry>` tries every fresh witness (latest
        // checkpoint per signer); `/v1/coverage/<entry>/<checkpoint>` pins
        // one. The artifact mirrors `datu witness prove`, so a client can
        // re-verify with zero other context.
        ("GET", c) if c.starts_with("/v1/coverage/") => {
            let rest = &c["/v1/coverage/".len()..];
            let mut parts = rest.split('/');
            let entry_hex = parts.next().unwrap_or("");
            let checkpoint_hex = parts.next().filter(|part| !part.is_empty());
            let entry_id: [u8; 32] = hex::decode(entry_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or("entry id must be 32-byte hex")?;
            let checkpoints = store.all_checkpoints().map_err(|e| e.to_string())?;
            let candidates: Vec<datu_core::Checkpoint> = match checkpoint_hex {
                Some(id_hex) => {
                    let want: [u8; 32] = hex::decode(id_hex)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or("checkpoint id must be 32-byte hex")?;
                    checkpoints
                        .into_iter()
                        .filter(|cp| cp.id().map(|x| x == want).unwrap_or(false))
                        .collect()
                }
                None => {
                    let mut latest: std::collections::BTreeMap<String, datu_core::Checkpoint> =
                        std::collections::BTreeMap::new();
                    for cp in checkpoints {
                        let update = match latest.get(&cp.body.signer) {
                            Some(prev) => prev.body.height < cp.body.height,
                            None => true,
                        };
                        if update {
                            latest.insert(cp.body.signer.clone(), cp);
                        }
                    }
                    latest.into_values().collect()
                }
            };
            if candidates.is_empty() {
                return respond_json(
                    stream,
                    "404 Not Found",
                    &serde_json::json!({"error": "no such checkpoint on this node"}),
                );
            }
            let mut witnesses = Vec::new();
            let mut stale = Vec::new();
            for cp in candidates {
                match store.coverage_proof(&entry_id, &cp) {
                    Ok(proof) => {
                        let checkpoint_b64 =
                            B64.encode(borsh::to_vec(&cp).map_err(|e| e.to_string())?);
                        // The pieces a browser needs to verify locally: the
                        // exact signed body bytes (Ed25519 via WebCrypto), the
                        // root and set size the Merkle path must reach, and the
                        // signature over those bytes. ML-DSA-65 stays a CLI
                        // check (no browser verifier).
                        let body_b64 = B64
                            .encode(Checkpoint::body_bytes(&cp.body).map_err(|e| e.to_string())?);
                        witnesses.push(serde_json::json!({
                            "signer": cp.body.signer,
                            "checkpoint_id": hex::encode(cp.id().map_err(|e| e.to_string())?),
                            "height": cp.body.height,
                            "timestamp_ms": cp.body.timestamp_ms,
                            "entries_count": cp.body.entries_count,
                            "entry_ids_root": hex::encode(cp.body.entry_ids_root),
                            "signature": hex::encode(cp.signature),
                            "body_b64": body_b64,
                            "checkpoint_b64": checkpoint_b64,
                            "proof": proof,
                        }));
                    }
                    Err(e) => stale.push(serde_json::json!({
                        "signer": cp.body.signer,
                        "checkpoint_id": hex::encode(cp.id().map_err(|e| e.to_string())?),
                        "reason": e.to_string(),
                    })),
                }
            }
            if witnesses.is_empty() {
                return respond_json(
                    stream,
                    "409 Conflict",
                    &serde_json::json!({
                        "ok": false,
                        "entry": entry_hex,
                        "witnesses": [],
                        "stale": stale,
                        "error": "no fresh witness covers this entry right now; a checkpoint's set must match this node's (sign one with `datu witness prove`)",
                    }),
                );
            }
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "entry": entry_hex,
                    "witnesses": witnesses,
                    "stale": stale,
                }),
            )
        }
        // Identity chain for a key: every attestation naming it, who cosigned,
        // what was revoked and by whom. This is the JSON the explorer, the
        // wallet and any dApp render; the wording lives in one place.
        ("GET", e) if e.starts_with("/v1/identity/") => {
            let key = &e["/v1/identity/".len()..];
            if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return respond_json(
                    stream,
                    "400 Bad Request",
                    &serde_json::json!({"error": "key must be 64 hex characters"}),
                );
            }
            let chain = identity_chain_json(&store, key).map_err(|e| e.to_string())?;
            respond_json(stream, "200 OK", &chain)
        }
        ("GET", "/v1/conflicts") => {
            let count = store.conflicts_count().map_err(|e| e.to_string())?;
            // Resolution records (design §A/C): entries in gov.dispute.*
            // referencing either side of a dispute. One scan, matched per
            // conflict below.
            let resolutions: Vec<(String, datu_core::Entry)> = store
                .all_entries()
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|e| e.body.namespace.starts_with("gov.dispute."))
                .filter_map(|e| e.id().ok().map(|id| (hex::encode(id), e)))
                .collect();
            let items: Vec<serde_json::Value> = store
                .list_conflicts(200)
                .map_err(|e| e.to_string())?
                .iter()
                .map(|c| {
                    let sides = [c.id, c.stored_id];
                    let linked: Vec<serde_json::Value> = resolutions
                        .iter()
                        .filter(|(_, e)| e.body.refs.iter().any(|r| sides.contains(r)))
                        .map(|(id, e)| {
                            serde_json::json!({
                                "id": id,
                                "namespace": e.body.namespace,
                                "author": e.body.author,
                                "resolution_preview": String::from_utf8_lossy(&e.body.payload).chars().take(120).collect::<String>(),
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "id": hex::encode(c.id),
                        "author": c.author,
                        "namespace": c.namespace,
                        "seq": c.seq,
                        "stored_id": hex::encode(c.stored_id),
                        "timestamp_ms": c.timestamp_ms,
                        "resolutions": linked,
                    })
                })
                .collect();
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "conflicts": items, "count": count,
                }),
            )
        }
        ("GET", c) if c.starts_with("/v1/conflict/") => {
            let id_hex = &c["/v1/conflict/".len()..];
            match hex::decode(id_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(id) => match store.conflict_entry(&id).map_err(|e| e.to_string())? {
                    Some(entry) => {
                        let mut json = entry_full_json(&entry)?;
                        if let Some(obj) = json.as_object_mut() {
                            obj.insert(
                                "conflicts_with".into(),
                                serde_json::json!("this entry lost (author, seq) to a stored entry - both are signed by the same author; at least one history is fabricated"),
                            );
                        }
                        respond_json(stream, "200 OK", &json)
                    }
                    None => respond_json(
                        stream,
                        "404 Not Found",
                        &serde_json::json!({"error":"no recorded conflict with that id"}),
                    ),
                },
                None => respond_json(
                    stream,
                    "400 Bad Request",
                    &serde_json::json!({"error":"bad conflict id"}),
                ),
            }
        }
        ("POST", "/v1/entries") => {
            if let Some(limiter) = &limiter {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                if let Some(retry_after) = limiter.check(&peer, now_ms()) {
                    return respond_json_retry(
                        stream,
                        "429 Too Many Requests",
                        retry_after,
                        &serde_json::json!({
                            "ok": false,
                            "error": "submission rate limit exceeded for this peer",
                            "retry_after_s": retry_after,
                        }),
                    );
                }
            }
            let submission: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| format!("bad JSON: {e}"))?;
            let entry = entry_from_submission(&submission)?;
            match store.insert_entry(&entry) {
                Ok(true) => {
                    let id = entry.id().map_err(|e| e.to_string())?;
                    respond_json(
                        stream,
                        "201 Created",
                        &serde_json::json!({
                            "ok": true, "id": hex::encode(id), "seq": entry.body.seq,
                            "policy_freshness": governance.as_ref().as_ref().map(|g| &g.freshness),
                        }),
                    )
                }
                Ok(false) => respond_json(
                    stream,
                    "200 OK",
                    &serde_json::json!({
                        "ok": true, "duplicate": true,
                        "policy_freshness": governance.as_ref().as_ref().map(|g| &g.freshness),
                    }),
                ),
                Err(StoreError::Denied(m)) => respond_json(
                    stream,
                    "403 Forbidden",
                    &serde_json::json!({ "ok": false, "denied": m }),
                ),
                Err(StoreError::Conflict {
                    author,
                    seq,
                    existing,
                    incoming,
                }) => respond_json(
                    stream,
                    "409 Conflict",
                    &serde_json::json!({
                        "ok": false,
                        "rejected": format!(
                            "feed conflict for {author} seq {seq}: stored {} vs incoming {} - rewrite/fork attempt",
                            hex::encode(existing), hex::encode(incoming)
                        ),
                        "conflict": {
                            "author": author, "seq": seq,
                            "stored_id": hex::encode(existing),
                            "incoming_id": hex::encode(incoming),
                            "evidence_recorded": true,
                        },
                    }),
                ),
                Err(e) => respond_json(
                    stream,
                    "409 Conflict",
                    &serde_json::json!({
                        "ok": false, "rejected": e.to_string(),
                    }),
                ),
            }
        }
        ("POST", "/v1/sync/haves") => {
            // Every page walks the store, so an unthrottled client turns a
            // read route into CPU amplification. Shaped like submissions:
            // per-peer window, Retry-After, and it fails open - served
            // data still verifies cryptographically.
            if let Some(haves) = &haves_limiter {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                if let Some(retry_after) = haves.check(&peer, now_ms()) {
                    return respond_json_retry(
                        stream,
                        "429 Too Many Requests",
                        retry_after,
                        &serde_json::json!({
                            "ok": false,
                            "error": "sync rate limit exceeded for this peer",
                            "retry_after_s": retry_after,
                        }),
                    );
                }
            }
            let body_json: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| format!("bad JSON: {e}"))?;
            let m = body_json["m"].as_u64().unwrap_or(0);
            let k = body_json["k"].as_u64().unwrap_or(0) as u32;
            let bits = body_json["bits_b64"]
                .as_str()
                .and_then(|b| B64.decode(b).ok())
                .unwrap_or_default();
            let cursor = body_json["cursor"].as_i64();
            let limit = body_json["limit"].as_u64().unwrap_or(500).clamp(1, 2000) as usize;
            let have = match BloomFilter::from_parts(m, k, &bits) {
                Some(f) => f,
                None => {
                    return respond_json(
                        stream,
                        "400 Bad Request",
                        &serde_json::json!({
                            "error": "malformed bloom filter (m, k, bits_b64)"
                        }),
                    )
                }
            };
            let (entries, next_cursor, more) = store
                .missing_page(&have, cursor, limit)
                .map_err(|e| e.to_string())?;
            let items: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| entry_full_json(e).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            let checkpoints: Vec<serde_json::Value> = if cursor.is_none() {
                store
                    .all_checkpoints()
                    .map_err(|e| e.to_string())?
                    .iter()
                    .map(checkpoint_full_json)
                    .collect::<Result<_, _>>()?
            } else {
                Vec::new()
            };
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "entries": items,
                    "cursor": next_cursor,
                    "more": more,
                    "checkpoints": checkpoints,
                }),
            )
        }
        (m, _) => respond_json(
            stream,
            "404 Not Found",
            &serde_json::json!({"error": format!("no route for {m} {route}")}),
        ),
    }
}

/// Opaque indexer cursor: "cur1:" plus the store's insertion ordinal.
/// Treat it as a token; never parse it on the client side.
fn encode_cursor(ord: i64) -> String {
    format!("cur1:{ord}")
}
fn decode_cursor(raw: &str) -> Option<i64> {
    raw.trim().strip_prefix("cur1:")?.parse::<i64>().ok()
}

fn parse_list_query(query: &str) -> (Option<String>, Option<String>, usize, usize) {
    let mut ns = None;
    let mut author = None;
    let mut limit = 50usize;
    let mut offset = 0usize;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if value.is_empty() {
            continue;
        }
        match key {
            "ns" => ns = Some(value.to_string()),
            "author" => author = Some(value.to_string()),
            "limit" => limit = value.parse().unwrap_or(50).min(500),
            "offset" => offset = value.parse().unwrap_or(0).min(1_000_000),
            _ => {}
        }
    }
    (ns, author, limit, offset)
}

fn payload_preview(entry: &Entry) -> String {
    String::from_utf8_lossy(&entry.body.payload)
        .chars()
        .take(120)
        .collect()
}

/// The identity chain for a key, as one JSON document every client renders.
///
/// Plain ledger facts only: attestations naming the key (author = attestor),
/// their cosignatures (distinct authors), and revocations, matched the way the
/// verifier matches them - by attestation id, or by subject key for the
/// direct ejection path. Trust policy (which roots count, how many cosigners
/// are enough) stays with the reader; this endpoint invents no verdicts, it
/// just lays out what is signed.
fn identity_chain_json(store: &Store, key: &str) -> Result<serde_json::Value, String> {
    use datu_core::attest::{attestations_for, cosigners_for, parse_revoke, NS_ATTEST};
    let entries = store.all_entries().map_err(|e| e.to_string())?;

    // revocations, split by what they name
    let mut revoked_attestations: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    let mut revoked_key: Option<serde_json::Value> = None;
    let mut revocations: Vec<serde_json::Value> = Vec::new();
    for entry in &entries {
        let Some(rev) = parse_revoke(entry) else {
            continue;
        };
        let names_this_key = rev.subject.as_deref() == Some(key);
        let names_att = rev.attestation.clone();
        if !names_this_key && names_att.is_none() {
            continue;
        }
        let json = serde_json::json!({
            "by": entry.body.author,
            "attestation": rev.attestation,
            "subject": rev.subject,
            "reason": rev.reason,
            "timestamp_ms": entry.body.timestamp_ms,
        });
        if names_this_key {
            revoked_key = Some(json.clone());
        }
        if let Some(att) = &names_att {
            revoked_attestations.insert(att.clone(), json.clone());
        }
        revocations.push(json);
    }

    // attestations naming the key, oldest first, with their distinct cosigners
    let mut attestations: Vec<serde_json::Value> = Vec::new();
    let mut all_cosigners: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (entry, doc) in attestations_for(entries.iter(), key) {
        let id = entry.id().map_err(|e| e.to_string())?;
        let id_hex = hex::encode(id);
        let cosigners: Vec<String> = cosigners_for(entries.iter(), &id)
            .into_iter()
            .map(|(e, _)| e.body.author.clone())
            .collect();
        for c in &cosigners {
            all_cosigners.insert(c.clone());
        }
        let revoked = revoked_attestations.get(&id_hex).cloned();
        attestations.push(serde_json::json!({
            "id": id_hex,
            "by": entry.body.author,
            "label": doc.label,
            "claims": doc.claims,
            "timestamp_ms": entry.body.timestamp_ms,
            "cosigners": cosigners,
            // A revocation is a statement, not an edit: the attestation stays,
            // flagged, and the revoker is named.
            "revoked": revoked.is_some(),
            "revoked_by": revoked.clone(),
        }));
    }

    Ok(serde_json::json!({
        "key": key,
        "attestations": attestations,
        "revocations": revocations,
        "revoked_by_key": revoked_key,
        "counts": {
            "attestations": attestations.len(),
            "distinct_cosigners": all_cosigners.len(),
            "revoked": attestations.iter().filter(|a| a["revoked"] == true).count(),
        },
        // Every entry here was signature-verified by this store; the chain is
        // evidence, and the reader's policy decides its weight.
        "verified": true,
        "namespace": NS_ATTEST,
        "note": "Attestations are signed statements, not a verdict. Which roots count is your policy."
    }))
}

fn entry_summary_json(store: &Store, entry: &Entry) -> Result<serde_json::Value, String> {
    let ns_seq = store
        .namespace_seq(&entry.body.author, &entry.body.namespace, entry.body.seq)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "id": hex::encode(entry.id().map_err(|e| e.to_string())?),
        "author": entry.body.author,
        "namespace": entry.body.namespace,
        "seq": entry.body.seq,
        "ns_seq": ns_seq,
        "prev": entry.body.prev.map(hex::encode),
        "timestamp_ms": entry.body.timestamp_ms,
        "refs": entry.body.refs.iter().map(hex::encode).collect::<Vec<_>>(),
        "payload_preview": payload_preview(entry),
        // This node's own note: where it first saw the record. Never signed
        // and never served to peers - a local observation, not a ledger fact.
        "first_seen": entry
            .id()
            .ok()
            .and_then(|id| store.first_seen_of(&id).ok().flatten()),
    }))
}

/// Full wire format for a checkpoint - enough to reconstruct and verify it.
pub fn checkpoint_full_json(cp: &Checkpoint) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "version": cp.body.version,
        "signer": cp.body.signer,
        "signer_pq": cp.body.signer_pq,
        "pq_alg": cp.body.pq_alg,
        "height": cp.body.height,
        "prev": cp.body.prev.map(hex::encode),
        "timestamp_ms": cp.body.timestamp_ms,
        "entries_count": cp.body.entries_count,
        "entry_ids_root": hex::encode(cp.body.entry_ids_root),
        "signature": hex::encode(cp.signature),
        "pq_signature": B64.encode(&cp.pq_signature),
        "id": hex::encode(cp.id().map_err(|e| e.to_string())?),
    }))
}

pub fn checkpoint_from_json(value: &serde_json::Value) -> Result<Checkpoint, String> {
    let prev = match &value["prev"] {
        serde_json::Value::String(p) => Some(
            hex::decode(p)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("bad prev id")?,
        ),
        _ => None,
    };
    let root: [u8; 32] = value["entry_ids_root"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or("bad entry_ids_root")?;
    let signature: [u8; 64] = value["signature"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or("bad signature")?;
    let pq_signature = value["pq_signature"]
        .as_str()
        .and_then(|b| B64.decode(b).ok())
        .ok_or("bad pq_signature")?;
    let num = |key: &str| value[key].as_u64().ok_or_else(|| format!("missing {key}"));
    Ok(Checkpoint {
        body: CheckpointBody {
            version: num("version")? as u8,
            signer: value["signer"]
                .as_str()
                .ok_or("missing signer")?
                .to_string(),
            signer_pq: value["signer_pq"].as_str().unwrap_or("").to_string(),
            pq_alg: value["pq_alg"].as_str().unwrap_or("").to_string(),
            height: num("height")?,
            prev,
            timestamp_ms: num("timestamp_ms")?,
            entries_count: num("entries_count")?,
            entry_ids_root: root,
        },
        signature,
        pq_signature,
    })
}

fn read_request(stream: &TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut budget = MAX_HEADER_BYTES;
    let read_line = |reader: &mut BufReader<TcpStream>, limit: usize| -> Option<String> {
        let mut line = String::new();
        reader
            .by_ref()
            .take(limit as u64)
            .read_line(&mut line)
            .ok()?;
        if line.is_empty() || (line.len() >= limit && line.as_bytes().last() != Some(&10)) {
            return None; // empty or unterminated within the budget
        }
        Some(line)
    };
    let request_line = read_line(&mut reader, budget)?;
    budget = budget.checked_sub(request_line.len())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    let mut headers = 0usize;
    loop {
        headers += 1;
        if headers > MAX_HEADER_COUNT {
            return None;
        }
        let header = read_line(&mut reader, budget)?;
        budget = budget.checked_sub(header.len())?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    // Refuse oversized bodies outright instead of allocating them: an
    // unauthenticated Content-Length must never size an allocation.
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some((method, path, body))
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn respond_json(
    stream: &mut TcpStream,
    status: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    respond(stream, status, "application/json; charset=utf-8", &body)
}

fn respond_json_retry(
    stream: &mut TcpStream,
    status: &str,
    retry_after_s: u64,
    value: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nRetry-After: {retry_after_s}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|e| e.to_string())
}

const BLAKE3_JS: &str = include_str!("../../../web/wallet-extension/blake3.js");
const COVERAGE_JS: &str = include_str!("../../../web/wallet-extension/coverage.js");

const EXPLORER_HTML: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DATU Ledger Explorer</title>
<style>
 body{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}
 h1{font-size:1.2rem} a{color:#58a6ff;text-decoration:none} .muted{color:#8b949e}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 td,th{border-bottom:1px solid #21262d;padding:.45rem .6rem;text-align:left;font-size:.8rem}
 th{color:#8b949e;text-transform:uppercase;font-size:.7rem}
 #modal{display:none;position:fixed;inset:0;background:#000a;z-index:50;align-items:center;justify-content:center;padding:2rem;backdrop-filter:blur(2px)}
 #modal.open{display:flex}
 #modalbox{background:#161b22;border:1px solid #30363d;border-radius:10px;max-width:860px;width:100%;max-height:84vh;display:flex;flex-direction:column;box-shadow:0 10px 44px #000c}
 #modalhead{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.65rem 1rem;border-bottom:1px solid #21262d}
 #modalbody{overflow:auto;padding:1rem;white-space:pre-wrap;font-size:.72rem;line-height:1.5}
 input{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:.4rem;border-radius:6px;width:340px;max-width:100%}
 select{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:.4rem;border-radius:6px;max-width:100%}
 button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:.4rem 1rem;border-radius:6px;cursor:pointer}
 .tag{background:#1f6feb33;color:#79c0ff;border-radius:4px;padding:0 .35rem;font-size:.7rem}
 #disputes{display:none;background:#f8514922;border:1px solid #f8514966;color:#ffa198;border-radius:6px;padding:.6rem 1rem;margin-top:1rem;font-size:.8rem}
 #governance{display:none;background:#d2992222;border:1px solid #d2992266;color:#e3b341;border-radius:6px;padding:.6rem 1rem;margin-top:1rem;font-size:.8rem}
 .hero{background:linear-gradient(180deg,#111826 0%,#0d1117 100%);border:1px solid #21262d;border-radius:12px;padding:1.4rem 1.6rem 1.2rem;margin-bottom:1.4rem}
 .herohead{display:flex;align-items:baseline;gap:1rem;flex-wrap:wrap}
 .hero h1{font-size:1.5rem;margin:0}
 .herosub{font-size:.78rem}
 .tiles{display:flex;gap:.7rem;flex-wrap:wrap;margin:.9rem 0 .2rem}
 .tile{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.55rem .95rem;min-width:104px}
 .tile .num{font-size:1.45rem;color:#e6edf3;line-height:1.15}
 .tile .lbl{font-size:.6rem;color:#8b949e;text-transform:uppercase;letter-spacing:.07em}
 .tile.blue .num{color:#79c0ff}.tile.gold .num{color:#e3b341}.tile.red .num{color:#ffa198}
 #nsFilterBox{position:absolute;top:10px;left:10px;z-index:3;display:flex;align-items:center;gap:.4rem;
  background:#0d1117cc;border:1px solid #21262d;border-radius:8px;padding:.35rem .45rem;backdrop-filter:blur(3px)}
 #nsFilterBox select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;
  padding:.3rem .45rem;font-size:.76rem;max-width:46vw}
 #nsFilterBox .tagline{font-size:.7rem;color:#8b949e}
 #nsLegend{position:absolute;top:10px;right:10px;max-width:48%;display:flex;gap:.4rem;flex-wrap:wrap;justify-content:flex-end;pointer-events:none;z-index:3;background:#0d1117aa;border:1px solid #21262d;border-radius:8px;padding:.45rem;backdrop-filter:blur(3px)}
 #nsLegend .chip{pointer-events:auto}
 .chip{background:#161b22;border:1px solid #30363d;border-radius:99px;padding:.16rem .6rem;font-size:.7rem;cursor:pointer}
 .chip:hover{border-color:#58a6ff}
 .chip .dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.35rem;vertical-align:middle}
 .bar{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin-bottom:.4rem}
 .tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
 @media (max-width:640px){
  body{padding:.8rem}
  .hero{padding:.9rem .75rem;border-radius:9px}
  .hero h1{font-size:1.15rem}
  .herosub{font-size:.68rem}
  input{width:100%}
  .tile{min-width:82px;padding:.45rem .6rem}
  .tile .num{font-size:1.1rem}
  .tile .lbl{font-size:.55rem}
  #nsLegend{max-width:70%}
  #nsFilterBox{top:6px;left:6px;padding:.25rem .35rem}
  #nsFilterBox .tagline{display:none}
  #nsFilterBox select{max-width:52vw}
 }
</style></head><body>
<div id="ecosphere" class="hero">
 <div class="herohead">
  <h1>DATU Ledger Explorer <span class="tag">self-verifying mirror</span></h1>
  <div class="muted herosub">every author strand a bubble · every prev/ref a link · many lineages, one ecosystem, no consensus</div>
  <button id="laytoggle" onclick="toggleLayout()" style="margin-left:auto">layered view</button>
 </div>
 <div id="heroStats" class="tiles"></div>
 <div id="insights" class="muted" style="font-size:.74rem;margin:.15rem 0 .8rem"></div>
 <div id="graphwrap" style="position:relative;display:inline-block;width:100%">
  <canvas id="graph" width="960" height="560" style="width:100%;border:1px solid #21262d;border-radius:10px;cursor:grab;display:block;touch-action:none"></canvas>
  <div id="nsFilterBox"><span class="tagline">namespace</span>
   <select id="nsFilter" onchange="applyNsFilter(this.value)"><option value="">all</option></select></div>
  <div id="nsLegend" class="legend"></div>
  <div id="callout" style="display:none;position:absolute;background:#161b22;border:1px solid #58a6ff66;border-radius:6px;padding:.5rem .6rem;font-size:.72rem;max-width:270px;box-shadow:0 4px 14px #0009;pointer-events:auto;z-index:5"></div>
 </div>
 <div id="ecostats" class="muted" style="margin:.6rem 0 0;font-size:.78rem"></div>
</div>
<div class="bar"><input id="q" placeholder="entry id (64 hex) or author (64 hex)"><button onclick="search()">load</button>
<button onclick="loadEntries()">recent</button> <button onclick="loadWitnesses()">witnesses</button> <button onclick="loadAttestations()">attestations</button> <button onclick="loadConflicts()">disputes</button> <button onclick="loadEcosystem();window.scrollTo({top:0,behavior:'smooth'})">ecosphere</button> <button id="neuralbtn" onclick="toggleNeural()">signals: on</button> <button id="peersbtn" onclick="togglePeers()">peers: on</button></div>
<div id="disputes"></div>
<div id="governance"></div>
<div class="tablewrap"><table id="rows"><tr><th>id</th><th>author</th><th>namespace</th><th>seq</th><th>payload</th></tr></table></div>
<div id="modal" onclick="if(event.target===this)closeModal()">
 <div id="modalbox">
  <div id="modalhead"><b id="modaltitle" style="font-size:.85rem">record</b><button onclick="closeModal()">close ✕</button></div>
  <div id="modalbody"></div>
 </div>
</div>
<script src="/blake3.js"></script>
<script src="/coverage.js"></script>
<script>
async function j(u){const r=await fetch(u);return r.json()}
function short(h){return h?h.slice(0,8)+'…':''}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function hideEco(){document.getElementById('ecosphere').style.display='none';document.getElementById('callout').style.display='none'}
// ── ecosphere: every entry a node, every prev/ref a link in the mesh ─────
const GENESIS_ID='37616bce5bfb8b773f7c99a9e52bcd7aa43294301ab074a908fbc9a334315d63';
const REDUCED_MOTION=(typeof matchMedia==='function')&&matchMedia('(prefers-reduced-motion: reduce)').matches;
let NET={nodes:[],byId:new Map(),links:[],clusters:[],alpha:0,mode:'mesh',pan:{x:0,y:0},zoom:1,drag:null,pinch:null,tapN:null,hover:null,sel:null,moved:0,wired:false,focusNs:null,pinNs:null,raf:0,sub:'bubbles',strand:null,camT:null,neural:true,sprites:new Map(),pulses:[],ripples:[],lastT:0,lastAmbient:0,peers:[],showPeers:true,selfKey:null,peerViews:null,peerSig:null,peerHover:null};
function fitCanvas(){const cv=document.getElementById('graph');if(!cv)return;
 // portrait phones get a taller canvas so the mesh has room; landscape and
 // desktop keep the wide hero
 if(window.innerWidth<640){cv.width=640;
  cv.height=Math.min(920,Math.max(560,Math.round(640*window.innerHeight/Math.max(1,window.innerWidth))))}}
function hue(s){let h=0;for(const c of s)h=(h*31+c.charCodeAt(0))%360;return h}
function buildMesh(entries,cap){
 NET.nodes=[];NET.byId=new Map();NET.links=[];
 const use=entries.slice(0,cap);
 for(const e of use){const n={id:e.id,ns:e.namespace||'x',seq:e.seq,
  nseq:e.ns_seq!==undefined?e.ns_seq:e.seq,
  author:e.author,ts:e.timestamp_ms,
  prev:e.payload_preview||'',h:hue(e.namespace||'x'),root:e.id===GENESIS_ID,deg:0,x:0,y:0,vx:0,vy:0,
  fs:e.first_seen||null};
  NET.nodes.push(n);NET.byId.set(n.id,n)}
 for(const e of use){const n=NET.byId.get(e.id);if(!n)continue;
  const targets=[e.prev].concat(e.refs||[]);
  for(const t of targets){if(!t)continue;const m=NET.byId.get(t);if(!m||m===n)continue;
   NET.links.push({a:n,b:m});n.deg++;m.deg++}}
 // deterministic start: ring by namespace hue, jitter by entry id, so the
 // same ledger settles into the same shape on every visit
 for(const n of NET.nodes){let j=0;for(let i=0;i<8;i++)j=(j*33+(parseInt(n.id.substr(i*2,2),16)||0))%9973;
  const a=(n.h/360)*Math.PI*2+(j%64-32)*.02, r=110+(j%150);
  n.x=Math.cos(a)*r;n.y=Math.sin(a)*r}
 const root=NET.byId.get(GENESIS_ID);if(root){root.x=0;root.y=0}
 NET.alpha=1;return entries.length>use.length}
function simStep(){
 const a=NET.alpha;const S=(NET.mode==='bubbles'&&NET.sub==='strand')?NET.strand:null;
 if(NET.mode==='mesh'){
  const cell=64,grid=new Map();
  for(const n of NET.nodes){const k=Math.floor(n.x/cell)+':'+Math.floor(n.y/cell);
   let b=grid.get(k);if(!b){b=[];grid.set(k,b)}b.push(n)}
  // repulsion: each node pushes back only against grid neighbors
  for(const n of NET.nodes){const gx=Math.floor(n.x/cell),gy=Math.floor(n.y/cell);
   for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){const b=grid.get((gx+dx)+':'+(gy+dy));if(!b)continue;
    for(const m of b){if(m===n)continue;
     let ddx=n.x-m.x,ddy=n.y-m.y,d2=ddx*ddx+ddy*ddy;
     if(d2<1){ddx=.5;ddy=(n.x<m.x?-.5:.5);d2=.5}
     if(d2>cell*cell*4)continue;
     const d=Math.sqrt(d2),f=2400*a/(d2+40);
     n.vx+=ddx/d*f;n.vy+=ddy/d*f}}}
  // springs: every link pulls its two ends toward rest length
  for(const l of NET.links){const dx=l.b.x-l.a.x,dy=l.b.y-l.a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
   const f=(d-52)*.06*a;l.a.vx+=dx/d*f;l.a.vy+=dy/d*f;l.b.vx-=dx/d*f;l.b.vy-=dy/d*f}}
 if(S){
  // strand view: the focused strand's records drift freely inside the
  // viewport, mesh physics scoped to the strand alone (grid repulsion +
  // chain springs + wander + a soft recall at the frame's edge); the
  // other bubbles park where they were, so exiting re-coils in place
  const cell=48,grid=new Map();
  for(const n of S.nodes){const k=Math.floor(n.x/cell)+':'+Math.floor(n.y/cell);
   let b=grid.get(k);if(!b){b=[];grid.set(k,b)}b.push(n)}
  for(const n of S.nodes){const gx=Math.floor(n.x/cell),gy=Math.floor(n.y/cell);
   for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){const b=grid.get((gx+dx)+':'+(gy+dy));if(!b)continue;
    for(const m of b){if(m===n)continue;
     let ddx=n.x-m.x,ddy=n.y-m.y,d2=ddx*ddx+ddy*ddy;
     if(d2<1){ddx=.5;ddy=(n.x<m.x?-.5:.5);d2=.5}
     if(d2>cell*cell*4)continue;
     const d=Math.sqrt(d2),f=Math.min(.3,(900+2200*a)/(d2+40));
     n.vx+=ddx/d*f;n.vy+=ddy/d*f}}}
  // the strand's own prev/ref links stay live springs, so the records
  // wander but never stop being chained
  for(const l of NET.links){if(l.a.c!==S||l.b.c!==S)continue;
   const dx=l.b.x-l.a.x,dy=l.b.y-l.a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
   const f=Math.max(-.3,Math.min(.3,(d-56)*(.012+.025*a)));
   l.a.vx+=dx/d*f;l.a.vy+=dy/d*f;l.b.vx-=dx/d*f;l.b.vy-=dy/d*f}
  // soft containment: free to roam the whole frame, called back gently
  const cv=document.getElementById('graph');
  const lim=Math.max(60,(Math.min(cv.width,cv.height)/2)/NET.zoom-30);
  for(const n of S.nodes){const dx=n.x-S.cx,dy=n.y-S.cy,d=Math.hypot(dx,dy);
   if(d>lim){const f=Math.min(.3,(d-lim)*.004);n.vx-=dx/d*f;n.vy-=dy/d*f}}}
 if(NET.mode==='bubbles'&&NET.clusters){
  // bubble field: inside every bubble the strand's records are slow
  // ricocheting balls - constant cruise on straight lines, elastic
  // bounces off each other and off their bubble's ring, a whisper of
  // randomness on every carom so the pattern never loops. They never
  // rest, and they never leave the sphere.
  for(const c of NET.clusters){if(c===S)continue;const ns=c.nodes;
   const cell=28,grid=new Map();
   for(const n of ns){const k=Math.floor(n.x/cell)+':'+Math.floor(n.y/cell);
    let b=grid.get(k);if(!b){b=[];grid.set(k,b)}b.push(n)}
   for(const n of ns){const gx=Math.floor(n.x/cell),gy=Math.floor(n.y/cell);
    for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){const b=grid.get((gx+dx)+':'+(gy+dy));if(!b)continue;
     for(const m of b){if(m===n||m.id<n.id)continue;
      const ddx=n.x-m.x,ddy=n.y-m.y,d=Math.hypot(ddx,ddy);
      if(d>14||d<1e-6)continue;
      // separate the pair, then swap their normal components: an
      // equal-mass elastic carom, with a tiny random skew so no two
      // bounces repeat
      const nx=ddx/d,ny=ddy/d,ov=(14-d)/2;
      n.x+=nx*ov;n.y+=ny*ov;m.x-=nx*ov;m.y-=ny*ov;
      const rvn=(n.vx-m.vx)*nx+(n.vy-m.vy)*ny;
      if(rvn<0){n.vx-=rvn*nx;n.vy-=rvn*ny;m.vx+=rvn*nx;m.vy+=rvn*ny;
       const sk=(Math.random()-.5)*.12,ca=Math.cos(sk),sa=Math.sin(sk);
       let tx=n.vx*ca-n.vy*sa,ty=n.vx*sa+n.vy*ca;n.vx=tx;n.vy=ty;
       tx=m.vx*ca-m.vy*sa;ty=m.vx*sa+m.vy*ca;m.vx=tx;m.vy=ty}}}}
   // a record caught outside its sphere (say, fresh out of strand view)
   // steers home, then the ring takes over again
   const rim=c.R-5;
   for(const n of ns){const dx=n.x-c.cx,dy=n.y-c.cy,d=Math.hypot(dx,dy);
    if(d>rim+2){n.vx=n.vx*.9+(-dx/d*.22)*.1;n.vy=n.vy*.9+(-dy/d*.22)*.1}}}}
 if(NET.mode==='bubbles'&&NET.clusters){
  // bubbles: clusters repel, cross-cluster citations pull their bubbles
  // together; the rooted (genesis) bubble is nailed to the exact center -
  // no force ever displaces it - so the author bubbles always ring it
  // (the focused strand's center is pinned too, so its free drift stays
  // framed and its bubble reforms in place on the way out)
  const cs=NET.clusters;
  const free=c=>c!==S&&!c.rooted;
  // pairwise repulsion: bubbles jostle each other, and the genesis core
  // pushes back hardest so the author organisms keep a respectful orbit
  for(let i=0;i<cs.length;i++)for(let k=i+1;k<cs.length;k++){const A=cs[i],B=cs[k];
   let dx=A.cx-B.cx,dy=A.cy-B.cy,d=Math.sqrt(dx*dx+dy*dy);
   const minD=A.R+B.R+((A.rooted||B.rooted)?74:48);
   if(d<1){dx=1;dy=0;d=1}
   if(d<minD){const f=(minD-d)/d*(A.rooted||B.rooted?.6:.42)*a;
    if(free(A)){A.vx+=dx/d*f;A.vy+=dy/d*f}if(free(B)){B.vx-=dx/d*f;B.vy-=dy/d*f}}}
  for(const l of NET.links){const A=l.a.c,B=l.b.c;if(!A||!B||A===B)continue;
   const dx=B.cx-A.cx,dy=B.cy-A.cy,d=Math.sqrt(dx*dx+dy*dy)||1;
   const rest=A.R+B.R+52,f=Math.max(-2,Math.min(2,(d-rest)*.02*a));
   if(free(A)){A.vx+=dx/d*f;A.vy+=dy/d*f}if(free(B)){B.vx-=dx/d*f;B.vy-=dy/d*f}}
  // gentle recentering: the field as a whole has no gravity, so left
  // alone it drifts; past a dead zone the centroid is pulled back toward
  // the frame. Weak enough that bubbles still wander, strong enough that
  // the organism never sails out of view.
  let ccx=0,ccy=0,cn=0;
  for(const c of cs){if(c.rooted)continue;ccx+=c.cx;ccy+=c.cy;cn++}
  if(cn>0){ccx/=cn;ccy/=cn;const cd=Math.hypot(ccx,ccy);
   if(cd>160){const f=Math.min(.08,(cd-160)*.0008);
    for(const c of cs){if(c.rooted)continue;c.vx-=ccx/cd*f;c.vy-=ccy/cd*f}}}
  // every bubble is an organism: it keeps its generation ring (which
  // breathes), wanders on its own slow random compass, damps, and is
  // speed-capped so the whole field swells instead of shaking
  const nowC=performance.now();
  for(const c of cs){if(c===S)continue;
   if(c.rooted){c.cx=0;c.cy=0;c.vx=0;c.vy=0;continue}
   const ring=95+(c.dep||1)*100+Math.sin(nowC/2400+(c.ph||0))*7;
   const d=Math.hypot(c.cx,c.cy)||1;
   c.vx+=(c.cx/d*ring-c.cx)*.005;c.vy+=(c.cy/d*ring-c.cy)*.005;
   // orbital drift: a slow slide along the ring, direction per bubble
   const tx=-c.cy/d,ty=c.cx/d;
   c.vx+=tx*c.orb;c.vy+=ty*c.orb;
   c.wa=(c.wa===undefined?(c.ph||0):c.wa)+(Math.random()-.5)*.06;
   c.vx+=Math.cos(c.wa)*.012;c.vy+=Math.sin(c.wa)*.012;
   c.vx*=.95;c.vy*=.95;
   const sp=Math.hypot(c.vx,c.vy);if(sp>.35){c.vx*=.35/sp;c.vy*=.35/sp}
   c.cx+=c.vx;c.cy+=c.vy;
   // the sphere carries its records: interior physics stays in the
   // bubble's own frame while the bubble itself glides
   if(c.vx||c.vy)for(const n of c.nodes){n.x+=c.vx;n.y+=c.vy}}}
 // integration: the mesh centers softly, the layered view anchors each
 // node to its stratum, bubble records roam free inside their sphere; a
 // dragged node is pinned to the pointer, every strand wanders a little
 // so the mesh never looks dead, and bubble motion is speed-capped to
 // stay slow and glassy
 for(const n of NET.nodes){
  if(NET.mode==='layers'){n.vx+=(n.lx-n.x)*.05;n.vy+=(n.ly-n.y)*.05}
  else if(S&&n.c===S){/* free drift: chained and contained above */}
  else if(NET.mode==='bubbles'&&n.c){/* a ricocheting ball inside its
   sphere: cruising straight, caroming off peers and ring */}
  else{n.vx-=n.x*.003*a;n.vy-=n.y*.003*a;
   if(n.root){n.vx-=n.x*.004;n.vy-=n.y*.004}}
  if(!n.root){const sl=S&&n.c===S,fl=NET.mode==='bubbles'&&n.c&&n.c!==S;
   // strand view drifts glassy-slow, field balls fly near-straight with
   // only a whisper of curve, the mesh keeps its livelier wander
   n.wa=(n.wa===undefined?Math.random()*6.283:n.wa)+(Math.random()-.5)*(sl?.06:fl?.03:.22);
   const wv=sl?.011:fl?.008:.035;
   n.vx+=Math.cos(n.wa)*wv;n.vy+=Math.sin(n.wa)*wv}
  if(NET.drag&&NET.drag.n===n){n.x=NET.drag.x;n.y=NET.drag.y;n.vx=0;n.vy=0;continue}
  n.vx*=.82;n.vy*=.82;
  if(NET.mode==='bubbles'){const sp=Math.hypot(n.vx,n.vy)||1e-9;
   // bounce: a field record never rests - it cruises at a steady slow
   // pace on a slowly turning course (forces only steer it); one caught
   // outside its sphere (say, fresh out of strand view) hurries back at
   // up to twice cruise before settling into the cruise again
   if(n.c&&n.c!==S&&!n.root){const c=n.c,rim=c.R-5;
    const d=Math.hypot(n.x-c.cx,n.y-c.cy);
    if(d>rim+6){if(sp>.6){n.vx*=.6/sp;n.vy*=.6/sp}}
    else{const g=.22/sp;n.vx*=g;n.vy*=g;
     // every ball carries its own gentle curl - a slight permanent curve
     // unique in sign and strength - so no two paths repeat and no ball
     // can lock into a loop or park anywhere
     if(n.curl===undefined)n.curl=(Math.random()<.5?-1:1)*(.003+Math.random()*.004);
     const ca=Math.cos(n.curl),sa=Math.sin(n.curl);
     const tx=n.vx*ca-n.vy*sa,ty=n.vx*sa+n.vy*ca;n.vx=tx;n.vy=ty}}
   else if(sp>.3){n.vx*=.3/sp;n.vy*=.3/sp}}
  n.x+=n.vx;n.y+=n.vy;
  // the ring itself: the rim throws a crossing record back elastically -
  // the outward component flips, the bounce always carries it back into
  // the sphere, and a small skew keeps every carom a little different
  if(NET.mode==='bubbles'&&n.c&&n.c!==S){const c=n.c,rim=c.R-5;
   const dx=n.x-c.cx,dy=n.y-c.cy,d=Math.hypot(dx,dy);
   if(d>rim){const s=rim/d;n.x=c.cx+dx*s;n.y=c.cy+dy*s;
    const vr=(n.vx*dx+n.vy*dy)/d;
    if(vr>0){n.vx-=1.9*vr*dx/d;n.vy-=1.9*vr*dy/d;
     const vi=(n.vx*dx+n.vy*dy)/d;
     if(vi>-.12){n.vx+=(-.12-vi)*dx/d;n.vy+=(-.12-vi)*dy/d}
     const sk=(Math.random()-.5)*.18,ca=Math.cos(sk),sa=Math.sin(sk);
     const tx=n.vx*ca-n.vy*sa,ty=n.vx*sa+n.vy*ca;n.vx=tx;n.vy=ty}}}}
 NET.alpha=Math.max(a*.992,.07);return true}
function worldToScreen(n,cv){return[n.x*NET.zoom+cv.width/2+NET.pan.x,n.y*NET.zoom+cv.height/2+NET.pan.y]}
function screenToWorld(px,py,cv){return[(px-cv.width/2-NET.pan.x)/NET.zoom,(py-cv.height/2-NET.pan.y)/NET.zoom]}
function zclamp(z){return Math.min(6,Math.max(NET.sub==='strand'?.5:.35,z))}
// zooming all the way into a bubble opens it into a full strand view (no
// border, its records drift freely in frame, chained by their links);
// zooming all the way out closes it back into the bubble field
function zoomCross(){
 if(NET.mode!=='bubbles'||!NET.clusters.length)return;
 if(NET.sub!=='strand'&&NET.zoom>=5.6){
  const cv=document.getElementById('graph');let best=null,bd=1e18;
  for(const c of NET.clusters){const[sx,sy]=worldToScreen({x:c.cx,y:c.cy},cv);
   const d=(sx-cv.width/2)**2+(sy-cv.height/2)**2;if(d<bd){bd=d;best=c}}
  if(best){NET.sub='strand';NET.strand=best;NET.pinch=null;NET.camT=null;
   NET.sel=null;document.getElementById('callout').style.display='none';
   const z=Math.min(6,Math.max(1.4,Math.min(cv.width,cv.height)/(2*(best.R+56))));
   NET.camT={fx:NET.pan.x,fy:NET.pan.y,fz:NET.zoom,tx:-best.cx*z,ty:-best.cy*z,tz:z,t:0};
   NET.alpha=.32;wake()}}
 else if(NET.sub==='strand'&&NET.zoom<=.55){NET.sub='bubbles';NET.strand=null;NET.camT=null;wake()}}
// ── neural layer: glowing neurons, curved synapses, traveling signals ────
// A sprite cache keeps per-frame cost flat: one 64px radial gradient per
// hue bucket, scaled per node, instead of a gradient object per node.
// Deterministic per-peer personality: phase, speed and home angle from the
// address itself, so the field looks the same on every visit.
function ensurePeerViews(){
 const sig=NET.peers.map(p=>p.addr).sort().join('|');
 if(NET.peerSig===sig&&NET.peerViews)return;
 NET.peerSig=sig;
 NET.peerViews=NET.peers.map((p,i)=>{
  let hsh=0;for(const ch of String(p.addr))hsh=(hsh*31+ch.charCodeAt(0))%100003;
  return {
   addr:p.addr,
   last:p.last_success_ms||0,
   home:(i/Math.max(1,NET.peers.length))*Math.PI*2-Math.PI/2+0.42,
   ph:(hsh%628)/100,
   spd:0.75+((hsh>>3)%60)/100,
   ox:0,oy:0,vx:0,vy:0,   // manual displacement, springs back to the orbit
  }});
}
function glowSprite(h){
 const key=Math.round(h/12)*12%360;
 if(NET.sprites.has(key))return NET.sprites.get(key);
 let c=null;
 try{
  c=document.createElement('canvas');c.width=64;c.height=64;
  const g=c.getContext('2d');
  const rg=g.createRadialGradient(32,32,1,32,32,32);
  rg.addColorStop(0,'hsla('+key+',85%,72%,.95)');
  rg.addColorStop(.35,'hsla('+key+',80%,60%,.35)');
  rg.addColorStop(1,'hsla('+key+',80%,55%,0)');
  g.fillStyle=rg;g.fillRect(0,0,64,64);
 }catch(_){c=null} // headless harnesses and odd embedders: fall back to plain dots
 NET.sprites.set(key,c);
 return c}
// A link becomes a gentle synapse instead of a straight wire: the control
// point sits a deterministic distance off the midpoint, so the same ledger
// always draws the same arcs.
function synapsePath(link,now){
 const ax=link.a.x,ay=link.a.y,bx=link.b.x,by=link.b.y;
 const dx=bx-ax,dy=by-ay,len=Math.hypot(dx,dy)||1;
 let seed=((link.a.seq||0)*37+(link.b.seq||0)*61+((link.a.id||'').charCodeAt(2)||0))%19;
 const bow=(seed-9)/9*.16*len;
 const mx=(ax+bx)/2-dy/len*bow,my=(ay+by)/2+dx/len*bow;
 return {ax,ay,mx,my,bx,by,len}
}
function synapsePoint(p,t){
 const it=1-t;
 return [it*it*p.ax+2*it*t*p.mx+t*t*p.bx, it*it*p.ay+2*it*t*p.my+t*t*p.by]
}
function spawnPulse(link,hot){
 if(!NET.neural||NET.mode!=='bubbles'||NET.sub==='strand')return;
 if(REDUCED_MOTION)return;
 if(NET.pulses.length>140)return;
 NET.pulses.push({l:link,t:0,speed:.006+Math.random()*.008,hot:!!hot,h:(link.a.h||200)})
}
function spawnBurst(node){
 if(!node)return;let n=0;
 for(const l of NET.links){if(l.a!==node&&l.b!==node)continue;
  spawnPulse(l,true);if(++n>=12)break}
}
function stepSignals(now){
 if(!NET.neural){NET.pulses.length=0;NET.ripples.length=0;NET.lastT=now;return}
 const dt=Math.min(64,now-(NET.lastT||now));NET.lastT=now;
 // ambient activity: a slow drip of signals along random links keeps the
 // field feeling alive without turning into a firework
 if(now-(NET.lastAmbient||0)>420&&NET.links.length){
  NET.lastAmbient=now;
  for(let i=0;i<2;i++)spawnPulse(NET.links[(Math.random()*NET.links.length)|0]);
 }
 const keep=[];
 for(const pl of NET.pulses){
  pl.t+=pl.speed*(dt/16.7);
  if(pl.t>=1){const b=pl.l.b;
   NET.ripples.push({x:b.x,y:b.y,h:pl.h,t:0});
   if(NET.ripples.length>60)NET.ripples.shift();
   continue}
  keep.push(pl)}
 NET.pulses=keep;
 const rk=[];
 for(const r of NET.ripples){r.t+=dt/420;if(r.t<1)rk.push(r)}
 NET.ripples=rk;
}
function drawMesh(){const cv=document.getElementById('graph');if(!cv)return;const ctx=cv.getContext('2d');
 const strandMode=NET.mode==='bubbles'&&NET.sub==='strand'&&NET.strand;
 const now=performance.now();
 stepSignals(now);
 const W=cv.width,H=cv.height;ctx.clearRect(0,0,W,H);
 const g=ctx.createRadialGradient(W/2,H/2,60,W/2,H/2,Math.max(W,H)*.7);
 g.addColorStop(0,'#141c2b');g.addColorStop(1,'#0d1117');ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
 ctx.save();ctx.translate(W/2+NET.pan.x,H/2+NET.pan.y);ctx.scale(NET.zoom,NET.zoom);
 if(NET.mode==='bubbles'&&NET.clusters&&!strandMode){
  // the DAG drawn radially: faint generation rings around the genesis
  // core, one per causal depth, so the field reads as a directed tree
  // of lineages even before you look at a single arrow
  let maxDep=0;for(const c of NET.clusters)if(!c.rooted&&c.dep>maxDep)maxDep=c.dep;
  ctx.setLineDash([4/NET.zoom,8/NET.zoom]);ctx.lineWidth=1/NET.zoom;
  ctx.font=(10/NET.zoom)+'px ui-monospace,Menlo,monospace';ctx.textAlign='center';
  for(let g=1;g<=maxDep;g++){const ring=95+g*100;
   ctx.strokeStyle='rgba(139,148,158,.06)';
   ctx.beginPath();ctx.arc(0,0,ring,0,7);ctx.stroke();
   ctx.fillStyle='rgba(139,148,158,.3)';
   ctx.fillText('gen '+g,0,-ring-8/NET.zoom)}
  ctx.setLineDash([]);ctx.textAlign='left'}
 if(NET.mode==='bubbles'&&NET.clusters&&!strandMode){
  for(const c of NET.clusters){
   const dim=NET.focusNs&&!c.nodes.some(n=>n.ns===NET.focusNs);
   ctx.globalAlpha=dim?.12:1;const gold=c.h<0;
   // heartbeat: each bubble breathes on its own clock (phase from the
   // author hash) so the field never pulses in lockstep
   const beat=Math.sin(now/700+c.ph);
   ctx.fillStyle=gold?`rgba(227,179,65,${.07+.03*beat})`:`hsla(${c.h},60%,50%,${.05+.02*beat})`;
   ctx.strokeStyle=gold?'rgba(227,179,65,.4)':`hsla(${c.h},60%,60%,.4)`;
   ctx.lineWidth=(1.5+.5*beat)/NET.zoom;
   ctx.beginPath();ctx.arc(c.cx,c.cy,c.R,0,7);ctx.fill();ctx.stroke();
   // the breath ring: a faint halo swelling out and sinking back
   ctx.strokeStyle=gold?`rgba(227,179,65,${.10+.10*(beat*.5+.5)})`:`hsla(${c.h},60%,65%,${.08+.10*(beat*.5+.5)})`;
   ctx.lineWidth=1/NET.zoom;
   ctx.beginPath();ctx.arc(c.cx,c.cy,c.R+3.5+2*beat,0,7);ctx.stroke()}
  ctx.globalAlpha=1}
 const neural=NET.neural&&NET.mode==='bubbles'&&!strandMode;
 for(const l of NET.links){if(strandMode&&l.a.c!==NET.strand&&l.b.c!==NET.strand)continue;
  const hot=NET.sel&&(l.a===NET.sel||l.b===NET.sel);
  ctx.globalAlpha=(NET.focusNs&&l.a.ns!==NET.focusNs&&l.b.ns!==NET.focusNs&&!hot)?.1:1;
  if(neural){
   // synapses: faint curved axons; brightness rides the record's freshness
   const path=synapsePath(l,now);
   ctx.strokeStyle=hot?'#7cc0ff':('hsla('+l.a.h+',70%,62%,'+(l.a.c&&l.b.c&&l.a.c!==l.b.c?.34:.2)+')');
   ctx.lineWidth=(hot?1.5:.7)/NET.zoom;
   ctx.beginPath();ctx.moveTo(path.ax,path.ay);ctx.quadraticCurveTo(path.mx,path.my,path.bx,path.by);ctx.stroke();
  }else{
  ctx.strokeStyle=hot?'#58a6ff':((NET.mode==='bubbles'&&l.a.c&&l.b.c&&l.a.c!==l.b.c)?'#58a6ff3d':(NET.mode==='bubbles'?'#58a6ff4a':'#58a6ff26'));ctx.lineWidth=(hot?1.6:.8)/NET.zoom;
  ctx.beginPath();ctx.moveTo(l.a.x,l.a.y);ctx.lineTo(l.b.x,l.b.y);ctx.stroke()}
  // subtle arrowhead at the cited end: a child (a) points at its parent (b)
  const adx=l.b.x-l.a.x,ady=l.b.y-l.a.y,alen=Math.hypot(adx,ady)||1;
  if(alen*NET.zoom>16){const rb=(l.b.root?10:3+Math.min(l.b.deg,6)*.6)+4;
   const tx=l.b.x-adx/alen*rb,ty=l.b.y-ady/alen*rb,px=-ady/alen,py=adx/alen;
   ctx.fillStyle=hot?'#58a6ff':'#58a6ff55';
   ctx.beginPath();ctx.moveTo(tx,ty);
   ctx.lineTo(tx-adx/alen*5+px*3,ty-ady/alen*5+py*3);
   ctx.lineTo(tx-adx/alen*5-px*3,ty-ady/alen*5-py*3);
   ctx.closePath();ctx.fill()}
  // cross-author citations carry a traveling spark: a pulse of light
  // flowing from the citing record to the cited one - proof in motion
  if(!neural&&NET.mode==='bubbles'&&!strandMode&&l.a.c&&l.b.c&&l.a.c!==l.b.c&&alen*NET.zoom>26){
   const prog=(now/2600+((l.a.seq*7+l.b.seq*13)%97)/97)%1;
   const sxp=l.a.x+adx*prog,syp=l.a.y+ady*prog,r2=2/NET.zoom;
   ctx.fillStyle='rgba(140,192,255,.28)';
   ctx.beginPath();ctx.arc(sxp,syp,r2*3,0,7);ctx.fill();
   ctx.fillStyle='rgba(140,192,255,.9)';
   ctx.beginPath();ctx.arc(sxp,syp,r2,0,7);ctx.fill()}}
 ctx.globalAlpha=1;
 const neuralNodes=NET.neural&&NET.mode==='bubbles'&&!strandMode;
 // peers: the validators and mirrors this node talks to. Each satellite
 // drifts on its own slow, smooth compass (sum of sines, no jitter), and is
 // wired to the bubbles it actually delivered records from: the link means
 // "these records arrived from this peer", read from this node's local
 // first_seen notes. Peers that delivered nothing known keep a faint tether
 // to the bubbles whose provenance is unknown, never a false certainty.
 if(NET.showPeers&&NET.peers.length){
  ensurePeerViews();
  let baseR=120;
  if(NET.mode==='bubbles'&&NET.clusters){
   let ext=0;for(const c of NET.clusters)ext=Math.max(ext,Math.hypot(c.cx,c.cy)+c.R);
   baseR=ext+90}
  else{baseR=Math.max(...NET.nodes.map(n=>Math.hypot(n.x,n.y)),120)+90}
  // the field drifts after the camera fitted once. Ease the camera out
  // instead of shrinking the ring: satellites stay outside the organisms
  // and inside the frame. Manual zoom still wins (userZoomed).
  // Only the overview is eased: deep zoom (opening a strand at 5.6) and a
  // running camera animation must never be dragged back by the peer ring.
  if(!NET.userZoomed&&!NET.camT&&NET.zoom<=1.1){
   const need=(Math.min(W,H)/2-86)/baseR;
   if(NET.zoom>need)NET.zoom=Math.max(0.28,NET.zoom*0.94+need*0.06);
  }

  // provenance map: peer -> the bubbles it fed, plus which bubbles remain
  // unknown (rows older than the provenance column)
  const norm=a=>String(a||'').replace(/^[a-z]+:\/\//i,'').replace(/\/+$/,'').toLowerCase();
  const fed=new Map();
  if(NET.mode==='bubbles'&&NET.clusters){
   NET.clusters.forEach((c,ci)=>{
    for(const n of c.nodes){if(!n.fs)continue;
     const k=norm(n.fs);
     if(!fed.has(k))fed.set(k,new Set());
     fed.get(k).add(ci)}})}

  const nowMs=Date.now();
  const t=now;
  NET.peerViews.forEach((v,idx)=>{
   // slow, smooth wander: two sines at incommensurate rates per peer
   const ang=v.home
     +0.20*Math.sin(t*0.000115*v.spd+v.ph)
     +0.07*Math.sin(t*0.000067*v.spd+v.ph*2.3);
   const rad=baseR*(0.94+0.06*Math.sin(t*0.00009*v.spd+v.ph*1.7));
   // dragged offset springs home: pull toward zero, damped, so a released
   // peer drifts back into its own orbit instead of snapping
   v.vx-=v.ox*0.035;v.vy-=v.oy*0.035;v.vx*=0.86;v.vy*=0.86;
   v.ox+=v.vx;v.oy+=v.vy;
   const bx=Math.cos(ang)*rad, by=Math.sin(ang)*rad;
   const px=bx+v.ox, py=by+v.oy;
   v.bx=bx;v.by=by;v.x=px;v.y=py;v.ang=ang;
   const hovered=NET.peerHover===v;
   const age=nowMs-(v.last||0);
   const fresh=v.last&&age<90000;
   const stale=v.last&&!fresh;
   const col=fresh?'#4cd6c8':(stale?'#e3b341':'#5f6f85');

   // broken lines to every bubble: a peer is a syncing source for this
   // node's whole view. Weight carries the evidence - a bubble whose
   // records actually arrived from this peer (local first_seen) is drawn
   // strong in the peer's colour; the rest stay faint and neutral, reading
   // as "syncing, origin unconfirmed" rather than a claim.
   const targets=fed.get(norm(v.addr))||new Set();
   ctx.setLineDash([3/NET.zoom,5/NET.zoom]);
   ctx.lineDashOffset=-(t/45+v.ph*10)/NET.zoom;
   if(NET.mode==='bubbles'&&NET.clusters){
    NET.clusters.forEach((c,ci)=>{
     const confirmed=targets.has(ci);
     const mx=(px+c.cx)/2,my=(py+c.cy)/2;
     const dx=c.cx-px,dy=c.cy-py,len=Math.hypot(dx,dy)||1;
     const bow=((v.ph%2)-1)*len*0.12;
     const cx2=mx-dy/len*bow, cy2=my+dx/len*bow;
     if(confirmed){
      ctx.strokeStyle=col;ctx.globalAlpha=hovered?.7:.45;ctx.lineWidth=(hovered?1.4:.9)/NET.zoom;
     }else{
      // same peer colour, lower weight: the peer is syncing this bubble's
      // records; which of them it delivered first is not (yet) confirmed
      ctx.strokeStyle=col;ctx.globalAlpha=hovered?.34:.17;ctx.lineWidth=(hovered?1:.7)/NET.zoom;
     }
     ctx.beginPath();ctx.moveTo(px,py);ctx.quadraticCurveTo(cx2,cy2,c.cx,c.cy);ctx.stroke();
    });
   }else{
    // mesh and layered views have no bubbles, so the syncing web is drawn
    // peer to peer: every satellite links to every other one, the same
    // broken dashes as the bubble links, because they are syncing the same
    // ledger with each other and with this node. O(n^2) with n small; the
    // guard keeps an absurd peer table from melting the frame.
    const peers=NET.peerViews;
    if(peers.length<=24){
     peers.forEach(other=>{
      if(other===v)return;
      const oi=peers.indexOf(other);if(oi<idx)return; // one line per pair
      const freshPair=fresh||(other.last&&nowMs-other.last<90000);
      // bow each pair differently so 15 lines between 6 nodes stay legible
      const dx=other.x-px,dy=other.y-py,len=Math.hypot(dx,dy)||1;
      const bow=(((v.ph+other.ph)%2)-1)*len*0.10;
      const mx=(px+other.x)/2-dy/len*bow, my=(py+other.y)/2+dx/len*bow;
      ctx.strokeStyle=freshPair?'#4cd6c8':'rgba(120,150,190,1)';
      ctx.globalAlpha=hovered?.38:.20;ctx.lineWidth=(hovered?1.1:.75)/NET.zoom;
      ctx.beginPath();ctx.moveTo(px,py);ctx.quadraticCurveTo(mx,my,other.x,other.y);ctx.stroke();
     });
    }
    // and the tether to the core, same language
    ctx.globalAlpha=hovered?.32:.15;
    ctx.beginPath();ctx.moveTo(px,py);ctx.lineTo(0,0);ctx.stroke();
   }
   ctx.setLineDash([]);ctx.globalAlpha=1;
   // the peer itself: a small ring, not a neuron - nodes are not records
   ctx.strokeStyle=col;ctx.lineWidth=(hovered?1.8:1.2)/NET.zoom;
   ctx.beginPath();ctx.arc(px,py,(hovered?6:4.5)/NET.zoom,0,7);ctx.stroke();
   ctx.fillStyle=col;ctx.globalAlpha=.85;
   ctx.beginPath();ctx.arc(px,py,1.6/NET.zoom,0,7);ctx.fill();ctx.globalAlpha=1;
   // its name, always: anchored toward the field so it cannot leave the
   // frame, brighter and more detailed under the pointer
   const label=String(v.addr).replace(/^[a-z]+:\/\//i,'');
   // labels point away from the field: bubbles already own the inside
   const side=px>=0?1:-1;
   ctx.font=(hovered?10.5:9)/NET.zoom+'px ui-monospace,Menlo,monospace';
   ctx.textAlign=side>0?'left':'right';
   const lx=px+side*(9/NET.zoom);
   // the name appears only under the pointer (mesh AND bubble views: this
   // layer is shared); the bottom-left HUD still names everyone at a glance
   if(hovered){
    const ageTxt=v.last?((Math.round((nowMs-v.last)/1000))+'s ago'):'never synced';
    const text=label+'  '+ageTxt;
    const tw=ctx.measureText(text).width+8/NET.zoom;
    ctx.fillStyle='rgba(5,8,13,.78)';
    ctx.fillRect(side>0?lx:lx-tw,py-7.5/NET.zoom,tw,14/NET.zoom);
    ctx.fillStyle='#e8eef7';ctx.fillText(text,lx,py+3.5/NET.zoom);
   }
   ctx.textAlign='left';
  });
 }
 for(const n of NET.nodes){if(strandMode&&n.c!==NET.strand)continue;
  const fresh=NET.mode==='bubbles'&&n.c?(n.seq||0)/Math.max(1,n.c.maxSeq||1):0;
  if(n.root){const pu=Math.sin(now/700)*1.4;
   if(neuralNodes){const spr=glowSprite(46);
    if(spr){ctx.globalAlpha=.9;ctx.drawImage(spr,n.x-20,n.y-20,40,40);ctx.globalAlpha=1}}
   ctx.fillStyle='#e3b341';ctx.beginPath();ctx.arc(n.x,n.y,6,0,7);ctx.fill();
   ctx.strokeStyle='#e3b34155';ctx.lineWidth=2;ctx.beginPath();ctx.arc(n.x,n.y,10+pu,0,7);ctx.stroke()}
  else{ctx.globalAlpha=(NET.focusNs&&n.ns!==NET.focusNs)?.15:1;
   // newest records glow brightest, so time's direction reads inside
   // every bouncing strand: dim old core, bright fresh rim
   const r=3+Math.min(n.deg,6)*.6+fresh*1.3;
   if(neuralNodes){
    // neuron: soft halo (sprite), saturated synapse core, bright nucleus
    const halo=glowSprite(n.h);
    const hs=(NET.nodes.length>1400?r*2.2:r*3.2);
    if(halo){ctx.globalAlpha=(NET.focusNs&&n.ns!==NET.focusNs)?.06:.55;
     ctx.drawImage(halo,n.x-hs,n.y-hs,hs*2,hs*2)}
    ctx.globalAlpha=(NET.focusNs&&n.ns!==NET.focusNs)?.15:1;
    ctx.fillStyle='hsl('+n.h+',72%,'+(56+fresh*10)+'%)';
    ctx.beginPath();ctx.arc(n.x,n.y,r*.85,0,7);ctx.fill();
    ctx.fillStyle='rgba(240,248,255,'+(.5+fresh*.35)+')';
    ctx.beginPath();ctx.arc(n.x,n.y,Math.max(1,r*.3),0,7);ctx.fill();
   }else{
   ctx.fillStyle=`hsl(${n.h} 70% ${58+fresh*16}%)`;
   ctx.beginPath();ctx.arc(n.x,n.y,r,0,7);ctx.fill()}
   ctx.globalAlpha=1}}
 // firing ripples: a neuron that just received a signal lights a ring
 if(neuralNodes){for(const rp of NET.ripples){const a=1-rp.t;
   ctx.globalAlpha=a*.55;ctx.strokeStyle='hsla('+rp.h+',85%,72%,1)';
   ctx.lineWidth=1.2/NET.zoom;ctx.beginPath();ctx.arc(rp.x,rp.y,4+rp.t*14,0,7);ctx.stroke()}
  ctx.globalAlpha=1}
 // traveling signals: a bright bead on the axon, with a trailing glow
 if(neuralNodes){for(const pl of NET.pulses){
   const path=synapsePath(pl.l,now);
   const pt=synapsePoint(path,pl.t);
   ctx.globalAlpha=.22;ctx.fillStyle='hsla('+pl.h+',90%,75%,1)';
   ctx.beginPath();ctx.arc(pt[0],pt[1],4.5/NET.zoom,0,7);ctx.fill();
   ctx.globalAlpha=.95;ctx.fillStyle='#f2f8ff';
   ctx.beginPath();ctx.arc(pt[0],pt[1],1.5/NET.zoom,0,7);ctx.fill()}
  ctx.globalAlpha=1}
 ctx.restore();
 if(NET.mode==='bubbles'&&NET.zoom<2.2&&NET.clusters&&!strandMode){
  ctx.font='10px ui-monospace,Menlo,monospace';ctx.textAlign='center';
  for(const c of NET.clusters){
   if(NET.focusNs&&!c.nodes.some(n=>n.ns===NET.focusNs))continue;
   const[sx,sy]=worldToScreen({x:c.cx,y:c.cy},cv);
   ctx.fillStyle=c.h<0?'#e3b341':`hsl(${c.h} 70% 72%)`;
   ctx.fillText(short(c.author)+' · '+c.nodes.length,sx,sy-c.R*NET.zoom-6)}
  ctx.textAlign='left'}
 // peer HUD: who feeds this node, in plain text that never clips. The
 // satellites show where they sit; this says who they are and how fresh.
 if(NET.showPeers&&NET.peers.length){
  const list=[...NET.peers].sort((x,y)=>(y.last_success_ms||0)-(x.last_success_ms||0));
  const lineH=13, x0=14, y0=H-16-lineH*Math.min(list.length,6);
  ctx.font='10px ui-monospace,Menlo,monospace';ctx.textAlign='left';
  list.slice(0,6).forEach((p,i)=>{
   const age=Date.now()-(p.last_success_ms||0);
   const fresh=p.last_success_ms&&age<90000;
   const stale=p.last_success_ms&&!fresh;
   const col=fresh?'#4cd6c8':(stale?'#e3b341':'#5f6f85');
   const y=y0+i*lineH;
   ctx.fillStyle=col;ctx.beginPath();ctx.arc(x0+3,y-3,2.4,0,7);ctx.fill();
   ctx.fillStyle='rgba(201,209,217,.85)';
   const ageText=p.last_success_ms?(fresh?'now':Math.round(age/60000)+'m ago'):'never';
   ctx.fillText(String(p.addr).replace(/^[a-z]+:\/\//,'')+'  '+ageText,x0+12,y);
  });
 }
 for(const n of [NET.hover,NET.sel]){if(!n)continue;const[sx,sy]=worldToScreen(n,cv);
  ctx.strokeStyle='#c9d1d9';ctx.lineWidth=1.4;ctx.beginPath();ctx.arc(sx,sy,8,0,7);ctx.stroke();
  ctx.fillStyle=n.root?'#e3b341':'#c9d1d9';ctx.font='11px ui-monospace,Menlo,monospace';
  ctx.fillText(n.root?'genesis':n.ns+' #'+(n.nseq??n.seq),sx+11,sy-9)}
 if(NET.sel){const[sx,sy]=worldToScreen(NET.sel,cv);
  const co=document.getElementById('callout'),wr=document.getElementById('graphwrap');
  co.style.left=Math.min(Math.max(sx+16,4),Math.max(wr.clientWidth-280,4))+'px';
  co.style.top=Math.min(Math.max(sy-16,4),Math.max(wr.clientHeight-150,4))+'px'}}
function meshLoop(){if(NET.camT){const t=NET.camT;const e=Math.min(1,t.t+.045);t.t=e;
  const s=1-Math.pow(1-e,3);
  NET.pan.x=t.fx+(t.tx-t.fx)*s;NET.pan.y=t.fy+(t.ty-t.fy)*s;NET.zoom=t.fz+(t.tz-t.fz)*s;
  if(e>=1)NET.camT=null}
 simStep();drawMesh();NET.raf=requestAnimationFrame(meshLoop)}
function wake(){if(!NET.raf)NET.raf=requestAnimationFrame(meshLoop)}
function togglePeers(){NET.showPeers=!NET.showPeers;
 const b=document.getElementById('peersbtn');
 if(b)b.textContent='peers: '+(NET.showPeers?'on':'off');wake()}
function toggleNeural(){NET.neural=!NET.neural;
 const b=document.getElementById('neuralbtn');
 if(b)b.textContent='signals: '+(NET.neural?'on':'off');
 if(NET.neural)seedSignals();wake()}
// Seed the field: a handful of signals along the newest records so the
// first frame already reads as a living graph, not a static diagram.
function seedSignals(){if(!NET.links.length)return;
 const newest=[...NET.links].sort((x,y)=>((y.a.seq||0)+(y.b.seq||0))-((x.a.seq||0)+(x.b.seq||0)));
 for(const l of newest.slice(0,14))spawnPulse(l)}
function nodeAt(ev){const cv=document.getElementById('graph');const r=cv.getBoundingClientRect();
 const px=(ev.clientX-r.left)*(cv.width/r.width),py=(ev.clientY-r.top)*(cv.height/r.height);
 let best=null,bd=Math.max(7,12/Math.sqrt(NET.zoom));
 for(const n of NET.nodes){if(NET.sub==='strand'&&NET.strand&&n.c!==NET.strand)continue;
  const[sx,sy]=worldToScreen(n,cv);
  const d=Math.hypot(sx-px,sy-py);if(d<bd){bd=d;best=n}}return best}
// A peer satellite is grabbable and hoverable like a bubble.
function peerAt(ev){const cv=document.getElementById('graph');
 if(!NET.showPeers||!NET.peerViews||!NET.peerViews.length)return null;
 const r=cv.getBoundingClientRect();
 const px=(ev.clientX-r.left)*(cv.width/r.width),py=(ev.clientY-r.top)*(cv.height/r.height);
 let best=null,bd=Math.max(10,16/Math.sqrt(NET.zoom));
 for(const v of NET.peerViews){
  const[sx,sy]=worldToScreen({x:v.x,y:v.y},cv);
  const d=Math.hypot(sx-px,sy-py);if(d<bd){bd=d;best=v}}
 return best}
// The bubble itself is grabbable: dragging one pulls it out of the field,
// and its generation-ring spring carries it slowly home on release.
function bubbleAt(ev){const cv=document.getElementById('graph');
 if(NET.mode!=='bubbles'||NET.sub==='strand'||!NET.clusters)return null;
 const r=cv.getBoundingClientRect();
 const px=(ev.clientX-r.left)*(cv.width/r.width),py=(ev.clientY-r.top)*(cv.height/r.height);
 const w=screenToWorld(px,py,cv);let best=null,bd=1e9;
 for(const c of NET.clusters){if(c.rooted)continue;
  const d=Math.hypot(w[0]-c.cx,w[1]-c.cy);
  if(d<=c.R+6&&d<bd){bd=d;best=c}}
 return best}
function calloutFor(p){const co=document.getElementById('callout');
 co.style.display='block';
 co.innerHTML=`<div><b style="color:hsl(${p.h} 70% 70%)">${esc(p.ns)}</b> <span class="muted">#${p.nseq??p.seq}</span>${p.root?' <span class="tag" style="background:#d2992233;color:#e3b341">lineage mark</span>':''}</div>`+
  `<div class="muted">${short(p.id)} · by ${short(p.author)}</div>`+
  `<div class="muted">${new Date(p.ts).toLocaleString()} · ${p.deg} link(s) · feed #${p.seq}</div>`+
  `<div class="muted">first seen from <b>${esc(p.fs||'unknown (older row)')}</b> <span class="dim">· this node's note, not signed</span></div>`+
  `<div style="margin-top:.3rem;word-break:break-all">${esc(p.prev.slice(0,90))}</div>`+
  `<div style="margin-top:.4rem"><a href="#" onclick="show('${p.id}');return false">open full record →</a></div>`;
 co.onclick=e=>{if(e.target===co){co.style.display='none';NET.sel=null}}}
function wireGraph(){if(NET.wired){wake();return}NET.wired=true;const cv=document.getElementById('graph');
 cv.onmousedown=ev=>{NET.moved=0;const pp=peerAt(ev);
  if(pp){NET.drag={p:pp}}
  else{const n=nodeAt(ev);
   if(n){NET.drag={n,x:n.x,y:n.y};NET.alpha=Math.max(NET.alpha,.35)}
   else{const b=bubbleAt(ev);
   if(b)NET.drag={c:b};
   else NET.drag={pan:{x:NET.pan.x,y:NET.pan.y,mx:ev.clientX,my:ev.clientY}}}}
  cv.style.cursor=NET.drag.n||NET.drag.c||NET.drag.p?'grabbing':'move';wake()};
 window.addEventListener('mouseup',()=>{if(NET.drag){const d=NET.drag;NET.drag=null;
  if(d.c){d.c.vx=0;d.c.vy=0} // elastic: the ring spring takes it home
  cv.style.cursor='grab'}});
 cv.onmousemove=ev=>{if(NET.drag){NET.moved++;const d=NET.drag;
   const r=cv.getBoundingClientRect();
   const px=(ev.clientX-r.left)*(cv.width/r.width),py=(ev.clientY-r.top)*(cv.height/r.height);
   if(d.n){const w=screenToWorld(px,py,cv);d.x=w[0];d.y=w[1]}
   else if(d.p){const w=screenToWorld(px,py,cv);
    d.p.ox=w[0]-d.p.bx;d.p.oy=w[1]-d.p.by;d.p.vx=0;d.p.vy=0}
   else if(d.c){const w=screenToWorld(px,py,cv);
    const dx=w[0]-d.c.cx,dy=w[1]-d.c.cy;d.c.cx=w[0];d.c.cy=w[1];d.c.vx=0;d.c.vy=0;
    for(const n of d.c.nodes){n.x+=dx;n.y+=dy}}
   else{NET.pan.x=d.pan.x+(ev.clientX-d.pan.mx);NET.pan.y=d.pan.y+(ev.clientY-d.pan.my)}
   wake();return}
  NET.hover=nodeAt(ev);NET.peerHover=peerAt(ev);
  cv.style.cursor=(NET.hover||NET.peerHover)?'pointer':'grab';wake()};
 cv.onmouseleave=()=>{NET.hover=null;NET.peerHover=null;wake()};
 cv.onclick=ev=>{if(NET.moved>4)return;const n=nodeAt(ev);
  if(n){NET.sel=n;calloutFor(n);spawnBurst(n);wake()}else{NET.sel=null;document.getElementById('callout').style.display='none'}};
 cv.onwheel=ev=>{if(!ev.ctrlKey)return;ev.preventDefault();NET.userZoomed=true;const r=cv.getBoundingClientRect();
  const px=(ev.clientX-r.left)*(cv.width/r.width),py=(ev.clientY-r.top)*(cv.height/r.height);
  const z2=zclamp(NET.zoom*Math.exp(-ev.deltaY*.0012));
  NET.pan.x=px-cv.width/2-(px-cv.width/2-NET.pan.x)*z2/NET.zoom;
  NET.pan.y=py-cv.height/2-(py-cv.height/2-NET.pan.y)*z2/NET.zoom;
  NET.zoom=z2;zoomCross();drawMesh()};
 // touch: one finger drags a node or pans, two fingers pinch-zoom, a short
 // tap selects (the touch equivalent of hover+click in one gesture)
 const tpos=t=>{const r=cv.getBoundingClientRect();
  return[(t.clientX-r.left)*(cv.width/r.width),(t.clientY-r.top)*(cv.height/r.height)]};
 const tdist=ev=>Math.hypot(ev.touches[0].clientX-ev.touches[1].clientX,ev.touches[0].clientY-ev.touches[1].clientY);
 cv.addEventListener('touchstart',ev=>{ev.preventDefault();
  if(ev.touches.length===2){NET.drag=null;NET.pinch={d:tdist(ev),z:NET.zoom};return}
  const t=ev.touches[0];NET.moved=0;NET.tapN=nodeAt(t);
  const tp=peerAt(t);
  if(tp){NET.drag={p:tp}}
  else if(NET.tapN){NET.drag={n:NET.tapN,x:NET.tapN.x,y:NET.tapN.y};NET.alpha=Math.max(NET.alpha,.35)}
  else{const b=bubbleAt(t);
   if(b)NET.drag={c:b};
   else NET.drag={pan:{x:NET.pan.x,y:NET.pan.y,mx:t.clientX,my:t.clientY}}}
  wake()},{passive:false});
 cv.addEventListener('touchmove',ev=>{ev.preventDefault();
  if(NET.pinch&&ev.touches.length===2){NET.userZoomed=true;NET.zoom=zclamp(NET.pinch.z*tdist(ev)/NET.pinch.d);zoomCross();drawMesh();return}
  if(NET.drag&&ev.touches.length===1){NET.moved++;const t=ev.touches[0];const d=NET.drag;
   if(d.n||d.c||d.p){const p=tpos(t);const w=screenToWorld(p[0],p[1],cv);
    if(d.n){d.x=w[0];d.y=w[1]}
    else if(d.p){d.p.ox=w[0]-d.p.bx;d.p.oy=w[1]-d.p.by;d.p.vx=0;d.p.vy=0}
    else{const dx=w[0]-d.c.cx,dy=w[1]-d.c.cy;
     d.c.cx=w[0];d.c.cy=w[1];d.c.vx=0;d.c.vy=0;
     for(const n of d.c.nodes){n.x+=dx;n.y+=dy}}}
   else{NET.pan.x=d.pan.x+(t.clientX-d.pan.mx);NET.pan.y=d.pan.y+(t.clientY-d.pan.my)}
   wake()}},{passive:false});
 cv.addEventListener('touchend',ev=>{if(!ev.touches.length){NET.pinch=null;
  if(NET.drag){const d=NET.drag;NET.drag=null;
   if(d.c){d.c.vx=0;d.c.vy=0}
   if(NET.moved<=4){const n=NET.tapN;
    if(n){NET.sel=n;calloutFor(n);spawnBurst(n);wake()}
    else{NET.sel=null;document.getElementById('callout').style.display='none'}}}}});
 window.addEventListener('resize',()=>{fitCanvas();drawMesh()});
 wake()}
// causal depth from the roots (Kahn's order over the citation edges):
// the shared DAG spine both views read from - the layered view stacks
// it into strata, the bubble field wraps it into generation rings
function computeDepths(){
 const kids=new Map(),indeg=new Map();
 for(const n of NET.nodes){kids.set(n.id,[]);indeg.set(n.id,0)}
 for(const l of NET.links){kids.get(l.b.id).push(l.a);indeg.set(l.a.id,indeg.get(l.a.id)+1)}
 const q=[];for(const n of NET.nodes)if(indeg.get(n.id)===0){n.depth=0;q.push(n)}
 for(let qi=0;qi<q.length;qi++){const n=q[qi];
  for(const c of kids.get(n.id)){c.depth=Math.max(c.depth||0,n.depth+1);
   indeg.set(c.id,indeg.get(c.id)-1);if(indeg.get(c.id)===0)q.push(c)}}
 for(const n of NET.nodes)if(n.depth===undefined)n.depth=0}
function layoutLayers(){
 computeDepths();
 let maxD=0;for(const n of NET.nodes)if(n.depth>maxD)maxD=n.depth;
 // strata run top (roots) to bottom (newest); siblings grouped by author
 // so each lineage reads as a stable column
 const cols=new Map();
 for(const n of NET.nodes){if(!cols.has(n.depth))cols.set(n.depth,[]);cols.get(n.depth).push(n)}
 for(const col of cols.values()){
  col.sort((x,y)=>x.author<y.author?-1:x.author>y.author?1:x.seq-y.seq);
  const gap=Math.min(34,880/Math.max(1,col.length));
  col.forEach((n,i)=>{n.lx=(i-(col.length-1)/2)*gap;n.ly=(n.depth-maxD/2)*74})}
 const root=NET.byId.get(GENESIS_ID);if(root)root.ly-=10}
function buildClusters(){
 // every author strand coils into its own bubble; each bubble also
 // learns its causal generation (depth from the roots), so the field
 // can sit the strand on its DAG ring around the genesis core
 computeDepths();
 NET.clusters=[];const byAuth=new Map();
 for(const n of NET.nodes){let c=byAuth.get(n.author);
  if(!c){c={author:n.author,nodes:[],cx:0,cy:0,R:0,h:0,rooted:false,dep:1,maxSeq:0};
   byAuth.set(n.author,c);NET.clusters.push(c)}
  c.nodes.push(n);n.c=c}
 for(const c of NET.clusters){
  const nsCount=new Map();let dom='',dc=0;
  for(const n of c.nodes){const k=n.ns;nsCount.set(k,(nsCount.get(k)||0)+1);
   if(nsCount.get(k)>dc){dc=nsCount.get(k);dom=k}
   if(n.seq>c.maxSeq)c.maxSeq=n.seq}
  c.h=hue(dom);c.R=26+Math.sqrt(c.nodes.length)*7;c.vx=0;c.vy=0;
  let dep=1e9;for(const n of c.nodes)if((n.depth||0)<dep)dep=n.depth||0;
  c.dep=dep===1e9?1:dep;
  let j=0;for(let i=0;i<8;i++)j=(j*33+(parseInt(c.author.substr(i*2,2),16)||0))%9973;
  c.ph=j%628/100;
  // each bubble also slides around its ring on its own slow orbit,
  // some clockwise some not, so the field visibly circulates
  c.orb=((j%2)?1:-1)*(.004+(j%7)*.001);
  const ang=(j%360)*Math.PI/180,r=130+(j%170);
  c.cx=Math.cos(ang)*r;c.cy=Math.sin(ang)*r}
 const root=NET.byId.get(GENESIS_ID);
 if(root&&root.c){root.c.rooted=true;root.c.cx=0;root.c.cy=0;root.c.h=-1}
 for(const c of NET.clusters){
  c.nodes.sort((x,y)=>x.seq-y.seq).forEach((n,i)=>{
   const ang=i*2.399963,rad=c.R*.72*Math.sqrt((i+.5)/c.nodes.length);
   n.ox=Math.cos(ang)*rad;n.oy=Math.sin(ang)*rad})}}
// Views are deep-linkable: #mesh, #layers, #bubbles. Handy for sharing a
// view and for screenshots and tests that must not click through modes.
// Fit the camera so the bubbles AND their peer satellites are framed. Runs
// once per load; wheel/pinch still override it afterwards.
function fitView(){
 const cv=document.getElementById('graph');if(!cv)return;
 if(NET.userZoomed)return;
 let ext=0;
 if(NET.mode==='bubbles'&&NET.clusters){for(const c of NET.clusters)ext=Math.max(ext,Math.hypot(c.cx,c.cy)+c.R)}
 else{for(const n of NET.nodes)ext=Math.max(ext,Math.hypot(n.x,n.y))}
 if(!ext)return;
 // the peer ring sits at ext+90 with labels beyond; frame it whole
 const needed=NET.showPeers?ext+90+80:ext+40;
 const fit=((Math.min(cv.width,cv.height)/2)-10)/needed;
 NET.zoom=Math.max(.3,Math.min(1,fit));
}
function applyHashView(){
 const h=((typeof location!=='undefined'&&location.hash)||'').replace('#','').toLowerCase();
 const btn=document.getElementById('laytoggle');
 if(h==='mesh'&&NET.mode!=='mesh'){NET.mode='mesh';if(btn)btn.textContent='layered view';NET.alpha=1;NET.sub='bubbles';NET.strand=null;wake()}
 else if(h==='layers'&&NET.mode!=='layers'){NET.mode='layers';layoutLayers();if(btn)btn.textContent='bubbles view';NET.alpha=.6;NET.sub='bubbles';NET.strand=null;wake()}
 else if(h==='bubbles'&&NET.mode!=='bubbles'){NET.mode='bubbles';buildClusters();if(btn)btn.textContent='mesh view';NET.alpha=.6;NET.sub='bubbles';NET.strand=null;wake()}
}
function toggleLayout(){NET.userZoomed=false;const btn=document.getElementById('laytoggle');
 const next={mesh:'layers',layers:'bubbles',bubbles:'mesh'}[NET.mode];
 if(next==='mesh'){NET.mode='mesh';btn.textContent='layered view';NET.alpha=1}
 else if(next==='layers'){NET.mode='layers';layoutLayers();btn.textContent='bubbles view';NET.alpha=.6}
 else{NET.mode='bubbles';buildClusters();btn.textContent='mesh view';NET.alpha=.6}
 NET.sub='bubbles';NET.strand=null;NET.camT=null;
 NET.sel=null;document.getElementById('callout').style.display='none';wake()}
// Namespace-driven view: rebuild the ecosphere from just one namespace, so
// each namespace can be read as its own small DAG (one bubble per author
// that wrote in it). The selector lists namespaces with their entry counts.
function applyNsFilter(ns){NET.nsFilter=ns||null;
 const all=NET.entriesAll||[];
 const use=NET.nsFilter?all.filter(e=>e.namespace===NET.nsFilter):all;
 buildMesh(use,2500);
 if(NET.mode==='layers')layoutLayers();else if(NET.mode==='bubbles')buildClusters();
 NET.sel=null;NET.hover=null;document.getElementById('callout').style.display='none';
 wake()}
async function loadEcosystem(){
 document.getElementById('ecosphere').style.display='block';
 fitCanvas();
 // EVERY transaction: page through the whole store until the last page.
 const entries=[];const page=500;let offset=0,capped=false;
 for(;;){const d=await j('/v1/entries?limit='+page+'&offset='+offset);
  const batch=d.entries||[];entries.push(...batch);
  if(batch.length<page||entries.length>=20000){if(entries.length>=20000)capped=true;break}
  offset+=page}
 const [ps,st]=await Promise.all([j('/v1/peers'),j('/v1/status')]);
 NET.peers=(ps&&ps.peers)||[];
 NET.peerSig=null; // rebuild views so ages and addresses follow the refresh
 NET.selfKey=st&&st.identity?st.identity:null;
 NET.entriesAll=entries;
 const sel=document.getElementById('nsFilter');
 if(sel){const counts=new Map();
  for(const e of entries){const k=e.namespace||'x';counts.set(k,(counts.get(k)||0)+1)}
  sel.innerHTML='<option value="">all namespaces</option>'+
   [...counts.entries()].sort((a,b)=>b[1]-a[1]).map(([ns,n])=>`<option value="${esc(ns)}"${ns===NET.nsFilter?' selected':''}>${esc(ns)} · ${n}</option>`).join('')}
 const use=NET.nsFilter?entries.filter(e=>e.namespace===NET.nsFilter):entries;
 const meshCapped=buildMesh(use,2500);
 seedSignals();
 NET.userZoomed=false;
 applyHashView();
 fitView();
 if(NET.mode==='layers')layoutLayers();else if(NET.mode==='bubbles')buildClusters();
 NET.sel=null;NET.hover=null;NET.pan={x:0,y:0};NET.zoom=1;NET.sub='bubbles';NET.strand=null;NET.camT=null;document.getElementById('callout').style.display='none';wireGraph();
 const known=(ps.known||[]);
 const mode=(st.policy&&st.policy.mode)||'open-observer';
 const mesh=(ps.network&&ps.network.network_id)||'';
 document.getElementById('ecostats').textContent=
  `${entries.length} entr${entries.length===1?'y':'ies'} as nodes · ${NET.links.length} link(s) between them${(capped||meshCapped)?' (drawing capped - the rest live in recent)':''} · `+
  `${(st.checkpoints!=null?st.checkpoints:0)} witness checkpoint(s) · `+
  `this node: ${mode}${mesh?' @ mesh '+mesh:' · open network'} · `+
  `${known.length} node address(es) known, ${known.filter(k=>k.last_success_ms>0).length} synced`;
 // hero data: count-up tiles, one-line insights, namespace spotlight chips
 const nsCount=new Map();entries.forEach(e=>{const k=e.namespace||'x';nsCount.set(k,(nsCount.get(k)||0)+1)});
 const authors=new Set(entries.map(e=>e.author)).size;
 const synced=known.filter(k=>k.last_success_ms>0).length;
 const conflicts=(st.conflicts!=null?st.conflicts:0);
 const tiles=document.getElementById('heroStats');tiles.innerHTML='';
 const specs=[[entries.length,'entries','blue'],[NET.links.length,'links',''],[authors,'lineages','gold'],[nsCount.size,'namespaces',''],
  [(st.checkpoints!=null?st.checkpoints:0),'witness checkpoints',''],[known.length?synced+' / '+known.length:'0 / 0','peers synced',''],[conflicts,'disputes',conflicts>0?'red':'']];
 for(const[v,l,cls]of specs){const d=document.createElement('div');d.className='tile '+(cls||'');
  d.innerHTML='<div class="num">0</div><div class="lbl">'+l+'</div>';tiles.appendChild(d);
  const num=d.querySelector('.num');
  if(typeof v==='number')countUp(num,v);else num.textContent=v}
 const byAuth=new Map();entries.forEach(e=>byAuth.set(e.author,(byAuth.get(e.author)||0)+1));
 let topA='',topAc=0;byAuth.forEach((c,a)=>{if(c>topAc){topA=a;topAc=c}});
 let hub=null;for(const n of NET.nodes)if(!hub||n.deg>hub.deg)hub=n;
 document.getElementById('insights').innerHTML=
  (topA?'largest lineage: <b>'+short(topA)+'</b> · '+topAc+' entries · ':'')+
  (hub&&hub.deg?'most connected record: <a href="#" onclick="show(\''+hub.id+'\');return false">'+short(hub.id)+'</a> · '+hub.deg+' links · ':'')+
  'the gold core is the founder\'s genesis - every ledger descends from it';
 const lg=document.getElementById('nsLegend');lg.innerHTML='';
 [...nsCount.entries()].sort((a,b)=>b[1]-a[1]).forEach(([ns,c])=>{
  const chip=document.createElement('span');chip.className='chip';chip.title='hover to spotlight, click to pin';
  chip.innerHTML='<span class="dot" style="background:hsl('+hue(ns)+' 70% 64%)"></span>'+esc(ns)+' <span class="muted">'+c+'</span>';
  chip.onmouseenter=()=>{if(!NET.pinNs){NET.focusNs=ns;drawMesh()}};
  chip.onmouseleave=()=>{if(!NET.pinNs){NET.focusNs=null;drawMesh()}};
  chip.onclick=()=>{NET.pinNs=NET.pinNs===ns?null:ns;NET.focusNs=NET.pinNs;drawMesh()};
  lg.appendChild(chip)});
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>peer address</th><th>node</th><th>mesh</th><th>source</th><th>last sync</th><th>state</th></tr>';
 known.forEach(k=>{const tr=document.createElement('tr');
  const ago=k.last_success_ms?timeAgo(k.last_success_ms):'never';
  const ok=k.last_success_ms>0&&(!k.last_error);
  tr.innerHTML=`<td>${esc(k.addr)}</td><td>${short(k.node_key)}</td><td>${esc(k.network_id||'open')}</td><td><span class="tag">${esc(k.source)}</span></td><td>${ago}</td>`+
   `<td>${ok?'<span class="tag" style="background:#23863633;color:#7ee787">synced</span>':k.last_error?'<span class="tag" style="background:#f8514933;color:#ffa198" title="'+esc(k.last_error)+'">'+esc(k.last_error.slice(0,28))+'</span>':'<span class="tag">unverified</span>'}</td>`;
  rows.appendChild(tr)});
 if(!known.length){const tr=document.createElement('tr');tr.innerHTML='<td colspan="6" class="muted">no peers yet - add one with `datu node --seed host:port` and it will grow by peer exchange</td>';rows.appendChild(tr)}}
function timeAgo(ms){const s=Math.max(1,Math.round((Date.now()-ms)/1000));
 if(s<60)return s+'s ago';if(s<3600)return Math.round(s/60)+'m ago';if(s<86400)return Math.round(s/3600)+'h ago';return Math.round(s/86400)+'d ago'}
function countUp(el,val){const t0=performance.now(),dur=700;
 const f=t=>{const k=Math.min(1,(t-t0)/dur);
  el.textContent=Math.round(val*(1-Math.pow(1-k,3))).toLocaleString();
  if(k<1)requestAnimationFrame(f)};
 requestAnimationFrame(f)}
// Landing: the ecosphere is the explorer's front page. Never let the
// browser restore a scroll position on a lower table - every load starts
// at the top, on the ecosystem view.
if(typeof history!=='undefined'&&'scrollRestoration' in history)history.scrollRestoration='manual';
if(typeof window!=='undefined'&&window.scrollTo)window.scrollTo(0,0);
loadEcosystem();
async function loadEntries(){hideEco();
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>id</th><th>author</th><th>namespace</th><th>seq</th><th>first seen from</th><th>payload</th></tr>';
 const d=await j('/v1/entries?limit=50');
 (d.entries||[]).forEach(e=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td><a href="#" onclick="show('${e.id}');return false">${short(e.id)}</a></td><td>${short(e.author)}</td><td>${esc(e.namespace)}</td><td>${e.seq}</td><td class="dim">${esc(e.first_seen||'unknown')}</td><td>${esc(e.payload_preview.slice(0,80))}</td>`;
  rows.appendChild(tr)})}
async function show(id){let e=await j('/v1/entry/'+id);if(e.error)e=await j('/v1/conflict/'+id);
 document.getElementById('modaltitle').textContent='record '+short(id)+(e.namespace?' · '+e.namespace:'');
 const d=document.getElementById('modalbody');
 const p=atob(e.payload_base64||'');d.textContent=JSON.stringify(e,null,2)+'\n\npayload:\n'+p;
 // Ledger facts worth surfacing next to any record: who witnessed it (and
 // as of when), and whether it declares a contract (the pending view).
 const facts=[];
 try{
  const c=await j('/v1/coverage/'+id);
  if(c.witnesses&&c.witnesses.length){
   facts.push('witnessed by '+c.witnesses.length+' node(s):');
   for(const w of c.witnesses){
    let verdict='NOT CHECKED';
    try{
     const check=await datuCoverage.verifyWitness(id,w);
     verdict=check.ok
      ?(check.signature==='ok'?'verified locally (merkle path + Ed25519)':'path verified locally; signature checked by the node (no WebCrypto Ed25519 here)')
      :('NOT VERIFIED: '+check.reason);
    }catch(e){verdict='NOT VERIFIED: '+e.message}
    facts.push('  '+short(w.signer)+' as of '+new Date(w.timestamp_ms).toISOString()+' (height '+w.height+') - '+verdict);
   }
  }else{
   facts.push('witness coverage: none fresh on this node yet');
  }
 }catch(_){}
 try{
  const o=await j('/v1/contract/status/'+id);
  if(o&&!o.error){
   facts.push('contract '+(o.contract_id||'').slice(0,12)+'... '+(o.ready?'READY':'OUTSTANDING')+' - awaits a \''+o.admits+'\' document');
   (o.reasons||[]).forEach(r=>facts.push('  reason: '+r));
  }
 }catch(_){}
 // Identity chain for the author: who vouches, with what claims, cosigned by
 // whom, revoked or not. Plain ledger statements; the reader's policy decides
 // their weight, so the card never prints a bare "verified".
 try{
  const ch=await j('/v1/identity/'+e.author);
  if(ch&&ch.attestations){
   facts.push('identity: '+short(e.author)+(ch.counts.revoked?' - revoked':''));
   if(!ch.attestations.length&&!ch.revoked_by_key) facts.push('  no attestation on this ledger; signed in, unattested');
   for(const a of ch.attestations){
    const claims=Object.entries(a.claims||{}).map(kv=>kv[0]+'='+JSON.stringify(kv[1])).join(', ');
    const cs=a.cosigners&&a.cosigners.length?(' | cosigned by '+a.cosigners.length+': '+a.cosigners.map(short).join(', ')):'';
    facts.push('  attested by '+short(a.by)+(a.label?(' as '+a.label):'')+' - '+(claims||'(no claims)')+cs);
    if(a.revoked&&a.revoked_by) facts.push('    REVOKED by '+short(a.revoked_by.by)+(a.revoked_by.reason?(' - '+a.revoked_by.reason):''));
   }
   if(ch.revoked_by_key&&ch.revoked_by_key.by)
    facts.push('  key revoked directly by '+short(ch.revoked_by_key.by)+(ch.revoked_by_key.reason?(' - '+ch.revoked_by_key.reason):''));
  }
 }catch(_){}
 if(facts.length) d.textContent+=String.fromCharCode(10,10)+facts.join(String.fromCharCode(10));
 document.getElementById('modal').classList.add('open')}
function closeModal(){document.getElementById('modal').classList.remove('open')}
window.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});
async function search(){const q=document.getElementById('q').value.trim();
 if(/^[0-9a-fA-F]{64}$/.test(q)){show(q)}
 else if(/^[0-9a-fA-F]{63,}$/.test(q)){const d=await j('/v1/feed/'+q);showFeed(d)}
 else alert('enter 64-hex entry id or author id')}
async function showFeed(d){hideEco();
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>seq</th><th>id</th><th>namespace</th><th>payload</th></tr>';
 (d.entries||[]).forEach(e=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td>${e.seq}</td><td><a href="#" onclick="show('${e.id}');return false">${short(e.id)}</a></td><td>${esc(e.namespace)}</td><td>${esc(e.payload_preview.slice(0,80))}</td>`;
  rows.appendChild(tr)})}
async function loadAttestations(){hideEco();
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>attestation</th><th>attestor</th><th>subject</th><th>label</th><th>status</th></tr>';
 // Revocations first: a trusted statement names the attestation it kills.
 const revokes=await j('/v1/entries?ns=identity.revoke&limit=200');
 const revoked={};
 for(const item of revokes.entries||[]){
  try{
   const full=await j('/v1/entry/'+item.id);
   const body=JSON.parse(atob(full.payload_base64||''));
   if(typeof body.attestation==='string') revoked[body.attestation]=full.author||item.author;
  }catch(_){}
 }
 const list=await j('/v1/entries?ns=identity.attest&limit=100');
 for(const item of list.entries||[]){
  let body={};
  try{const full=await j('/v1/entry/'+item.id); body=JSON.parse(atob(full.payload_base64||''));}catch(_){}
  const by=revoked[item.id];
  const tr=document.createElement('tr');
  tr.innerHTML=`<td><a href="#" onclick="show('${item.id}');return false">${short(item.id)}</a></td><td>${short(item.author)}</td><td>${short(body.subject||'')}</td><td>${esc(body.label||'')}</td><td>${by?'<span class="tag" style="background:#f8514933;color:#ffa198">REVOKED by '+short(by)+'</span>':'<span class="tag">standing</span>'}</td>`;
  rows.appendChild(tr);
 }
}
async function loadWitnesses(){hideEco();const d=await j('/v1/checkpoints');
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>witness</th><th>height</th><th>entries</th><th>merkle root</th></tr>';
 (d.witnesses||[]).forEach(w=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td>${short(w.signer)}</td><td>${w.height}</td><td>${w.entries_count}</td><td>${esc(w.entry_ids_root)}</td>`;
  rows.appendChild(tr)})}
async function checkDisputes(){const d=await j('/v1/conflicts');
 const el=document.getElementById('disputes');
 if(!d.count){el.style.display='none';return}
 el.style.display='block';
 el.textContent='⚠ '+d.count+' disputed feed record(s) - conflicting signed history preserved as evidence (disputes view lists them)'}
async function loadConflicts(){hideEco();const d=await j('/v1/conflicts');
 const el=document.getElementById('disputes');
 if(!d.count){el.style.display='none';el.textContent='';return}
 el.style.display='block';
 el.textContent='⚠ '+d.count+' disputed feed record(s) - conflicting signed history preserved as evidence';
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>disputed author</th><th>seq</th><th>stored id</th><th>conflicting id</th><th>namespace</th></tr>';
 (d.conflicts||[]).forEach(c=>{const tr=document.createElement('tr');
  const res=(c.resolutions||[]).length?(' <span class="tag">resolved</span>'):' <span class="tag" style="background:#f8514933;color:#ffa198">open</span>';
  tr.innerHTML=`<td>${short(c.author)}</td><td>${c.seq}</td><td><a href="#" onclick="show('${c.stored_id}');return false">${short(c.stored_id)}</a></td><td><a href="#" onclick="show('${c.id}');return false">${short(c.id)}</a></td><td>${esc(c.namespace)}${res}</td>`;
  rows.appendChild(tr)});
 (d.conflicts||[]).forEach(c=>{(c.resolutions||[]).forEach(r=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td colspan="4" class="muted">↳ resolved by <a href="#" onclick="show('${r.id}');return false">${short(r.id)}</a> in ${esc(r.namespace)}</td><td>${esc(r.resolution_preview)}</td>`;
  rows.appendChild(tr)})})}
async function checkGovernance(){const s=await j('/v1/status');const g=s.manifest;const el=document.getElementById('governance');
 if(!g||g.freshness==='current'){el.style.display='none';return}
 el.style.display='block';
 el.textContent='⚠ governance '+g.freshness+' - '+g.reason}
checkDisputes();
checkGovernance();
</script></body></html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody, CHECKPOINT_VERSION};
    use datu_wallet::wire::entry_full_json;

    fn signed(seq: u64, prev: Option<[u8; 32]>, payload: &[u8]) -> Entry {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pq = datu_core::pq::keypair().unwrap().1;
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "gov.records".into(),
            seq,
            prev,
            refs: vec![],
            timestamp_ms: 1,
            payload: payload.to_vec(),
        };
        Entry::sign(body, &ed, &pq).unwrap()
    }

    fn resolution(refs: Vec<[u8; 32]>, payload: &[u8]) -> Entry {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pq = datu_core::pq::keypair().unwrap().1;
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "gov.dispute.title".into(),
            seq: 0,
            prev: None,
            refs,
            timestamp_ms: 2,
            payload: payload.to_vec(),
        };
        Entry::sign(body, &ed, &pq).unwrap()
    }

    fn http(port: u16, method: &str, path: &str, body: &str) -> (String, String) {
        use std::io::Read;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let mut parts = raw.splitn(2, "\r\n");
        let status = parts.next().unwrap_or("").to_string();
        let rest = parts.next().unwrap_or("").to_string();
        let body = rest.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    #[test]
    fn peer_limiter_sliding_window() {
        let limiter = PeerLimiter::new(2);
        assert_eq!(limiter.check("a", 1_000), None);
        assert_eq!(limiter.check("a", 2_000), None);
        assert!(
            limiter.check("a", 3_000).is_some(),
            "third hit in window denied"
        );
        assert_eq!(limiter.check("b", 3_000), None, "budget is per peer");
        assert_eq!(limiter.check("a", 61_500), None, "window has slid");
        let off = PeerLimiter::new(0);
        for _ in 0..10 {
            assert_eq!(off.check("a", 1), None, "0 = unlimited");
        }
    }

    #[test]
    fn http_conflict_evidence_and_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let data = dir.path().to_path_buf();
        let original = signed(0, None, b"original");
        let rewrite = signed(0, None, b"rewritten");
        // A resolution record (design §A) already references the disputed
        // side: resolutions are ordinary gov.dispute.* entries, and the
        // conflict listing links them at read time - ordering never matters.
        let resolution_id = {
            let store = Store::open(&data.join("node.db")).unwrap();
            let r = resolution(
                vec![rewrite.id().unwrap()],
                b"{\"verdict\":\"stored history stands\"}",
            );
            store.insert_entry(&r).unwrap();
            hex::encode(r.id().unwrap())
        };
        std::thread::spawn(move || {
            let _ = serve(&data, &format!("127.0.0.1:{port}"), None, 5, 5, None);
        });
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                drop(s);
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready, "serve did not come up");

        let submit = serde_json::to_string(&entry_full_json(&original).unwrap()).unwrap();
        let (status, _) = http(port, "POST", "/v1/entries", &submit);
        assert!(status.contains("201"), "first insert: {status}");
        let (status, _) = http(port, "POST", "/v1/entries", &submit);
        assert!(status.contains("200"), "idempotent duplicate: {status}");

        let conflicting = serde_json::to_string(&entry_full_json(&rewrite).unwrap()).unwrap();
        let (status, body) = http(port, "POST", "/v1/entries", &conflicting);
        assert!(status.contains("409"), "conflict rejected: {status}");
        assert!(
            body.contains("evidence_recorded"),
            "409 body names the evidence"
        );

        let (status, body) = http(port, "GET", "/v1/conflicts", "");
        assert!(status.contains("200"));
        let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(listing["count"].as_u64(), Some(1));
        let conflict_id = listing["conflicts"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(
            listing["conflicts"][0]["stored_id"]
                .as_str()
                .map(str::to_string),
            Some(hex::encode(original.id().unwrap()))
        );
        assert_eq!(
            listing["conflicts"][0]["resolutions"][0]["id"].as_str(),
            Some(resolution_id.as_str()),
            "the gov.dispute.* entry refs the conflicting side, so it is surfaced as a resolution"
        );

        let (status, body) = http(port, "GET", &format!("/v1/conflict/{conflict_id}"), "");
        assert!(status.contains("200"), "status: {status}");
        assert!(
            body.contains(&rewrite.body.author),
            "recorded evidence names the author"
        );

        let (status, body) = http(port, "GET", "/v1/status", "");
        assert!(status.contains("200"));
        assert!(body.contains("\"conflicts\": 1"));

        for i in 0..4 {
            let (status, body) = http(port, "POST", "/v1/entries", &submit);
            if i < 2 {
                assert!(status.contains("200"), "within budget: {status}");
            } else {
                assert!(status.contains("429"), "over budget must 429: {status}");
                assert!(body.contains("retry_after_s"));
            }
        }

        // The sync route carries its own per-peer budget: every page walks
        // the store, so an unthrottled client would be CPU amplification.
        let bloom = serde_json::json!({
            "m": 64, "k": 3,
            "bits_b64": B64.encode([0u8; 8]),
        })
        .to_string();
        let mut saw_429 = false;
        for _ in 0..6 {
            let (status, body) = http(port, "POST", "/v1/sync/haves", &bloom);
            if status.contains("429") {
                assert!(
                    body.contains("sync rate limit"),
                    "429 body names the sync budget: {body}"
                );
                saw_429 = true;
                break;
            }
            assert!(status.contains("200"), "within the haves budget: {status}");
        }
        assert!(
            saw_429,
            "the haves budget (5/min here) must bite within six requests"
        );
    }
    /// The explorer's entry view keeps pointing at the ledger-fact routes;
    /// a rename there must not silently drop the panels of evidence.
    #[test]
    fn explorer_surfaces_coverage_and_contracts() {
        assert!(EXPLORER_HTML.contains("/v1/coverage/"));
        assert!(EXPLORER_HTML.contains("/v1/contract/status/"));
        assert!(EXPLORER_HTML.contains("/v1/checkpoints"));
        // The entry view verifies served witnesses locally, not just display.
        assert!(EXPLORER_HTML.contains("/blake3.js"));
        assert!(EXPLORER_HTML.contains("datuCoverage.verifyWitness"));
        // Attestations view marks revoked statements.
        assert!(EXPLORER_HTML.contains("loadAttestations"));
        assert!(EXPLORER_HTML.contains("identity.attest"));
    }

    /// The coverage-proof endpoint serves the same offline-verifiable
    /// artifact `datu witness prove` writes: checkpoint + Merkle path.
    #[test]
    fn http_coverage_proof_endpoint() {
        use borsh::BorshDeserialize;

        let dir = tempfile::tempdir().unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let data = dir.path().to_path_buf();
        // One entry, then a witness checkpoint over everything seen.
        let entry_id = {
            let store = Store::open(&data.join("node.db")).unwrap();
            let entry = signed(0, None, b"record");
            store.insert_entry(&entry).unwrap();
            let ids = store.entry_ids().unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
            let pq = datu_core::pq::keypair().unwrap().1;
            let body = CheckpointBody {
                version: CHECKPOINT_VERSION,
                signer: String::new(),
                signer_pq: String::new(),
                pq_alg: String::new(),
                height: 0,
                prev: None,
                timestamp_ms: 777,
                entries_count: ids.len() as u64,
                entry_ids_root: datu_core::merkle::merkle_root(&ids),
            };
            store
                .append_checkpoint(&Checkpoint::sign(body, &key, &pq).unwrap())
                .unwrap();
            hex::encode(entry.id().unwrap())
        };
        std::thread::spawn(move || {
            let _ = serve(&data, &format!("127.0.0.1:{port}"), None, 5, 5, None);
        });
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                drop(s);
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready, "serve did not come up");

        let (status, body) = http(port, "GET", &format!("/v1/coverage/{entry_id}"), "");
        assert!(status.contains("200"), "{status} {body}");
        let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
        let witnesses = listing["witnesses"].as_array().unwrap();
        assert_eq!(witnesses.len(), 1);
        let witness = &witnesses[0];
        assert_eq!(witness["timestamp_ms"].as_u64(), Some(777));
        // The locally-verifiable fields a browser needs.
        assert_eq!(witness["entries_count"], witness["proof"]["count"]);
        assert_eq!(witness["entry_ids_root"].as_str().map(str::len), Some(64));
        assert!(witness["body_b64"].as_str().is_some_and(|b| !b.is_empty()));
        assert_eq!(witness["signature"].as_str().map(str::len), Some(128));

        // Verify the served artifact offline, exactly like a browser would:
        // decode the checkpoint, verify both signatures, walk the path.
        let checkpoint_bytes = B64
            .decode(witness["checkpoint_b64"].as_str().unwrap())
            .unwrap();
        let checkpoint = Checkpoint::try_from_slice(&checkpoint_bytes).unwrap();
        checkpoint.verify().unwrap();
        let proof: datu_core::checkpoint::CoverageProof =
            serde_json::from_value(witness["proof"].clone()).unwrap();
        proof.verify(&checkpoint).unwrap();

        // The checkpoint id pins the same witness.
        let (status, body) = http(
            port,
            "GET",
            &format!(
                "/v1/coverage/{entry_id}/{}",
                witness["checkpoint_id"].as_str().unwrap()
            ),
            "",
        );
        assert!(status.contains("200"), "{status} {body}");

        // The browser verifiers are served by the node itself.
        let (status, js) = http(port, "GET", "/blake3.js", "");
        assert!(status.contains("200"), "{status}");
        assert!(js.contains("datuBlake3"), "blake3 served");
        let (status, js) = http(port, "GET", "/coverage.js", "");
        assert!(status.contains("200"), "{status}");
        assert!(js.contains("datuCoverage"), "coverage verifier served");

        // An id no fresh witness covered is explained, not fabricated.
        let (status, body) = http(
            port,
            "GET",
            &format!("/v1/coverage/{}", hex::encode([6u8; 32])),
            "",
        );
        assert!(status.contains("409"), "{status} {body}");
        assert!(body.contains("stale"), "{body}");
    }

    /// The peer table over HTTP: the exchange subset for nodes, the full
    /// listing for the explorer, and the asker's announce recorded.
    #[test]
    fn peers_endpoint_shares_and_records_announce() {
        let dir = tempfile::tempdir().unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let data = dir.path().to_path_buf();
        let table = Arc::new(datu_p2p::PeerTable::new());
        table.upsert("10.0.0.41:7476", "abcd41", "", "mdns");
        table.record_success("10.0.0.41:7476", "abcd41", "");
        table.merge_pex(
            &[datu_p2p::PeerWire {
                addr: "10.0.0.42:7476".into(),
                node_key: String::new(),
                network_id: String::new(),
                last_success_ms: 5, // hearsay: must not be shared
            }],
            "",
        );
        let shared_table = table.clone();
        std::thread::spawn(move || {
            let _ = serve(
                &data,
                &format!("127.0.0.1:{port}"),
                None,
                5,
                5,
                Some(shared_table),
            );
        });
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                drop(s);
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready, "serve did not come up");

        // A node asking for exchange: verified peers shared, hearsay not.
        let (status, body) = http(port, "GET", "/v1/peers?network=", "");
        assert!(status.contains("200"), "{status} {body}");
        let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
        let shared = listing["peers"].as_array().unwrap();
        assert_eq!(shared.len(), 1, "only the verified address: {body}");
        assert_eq!(shared[0]["addr"], "10.0.0.41:7476");
        // The explorer sees the whole table, hearsay included.
        let known = listing["known"].as_array().unwrap();
        assert_eq!(known.len(), 2, "explorer listing includes unverified");

        // Announce ourselves; the table grows and the answer reflects it.
        let (status, body) = http(
            port,
            "GET",
            "/v1/peers?announce=10.0.0.43:7476&key=ef44&network=",
            "",
        );
        assert!(status.contains("200"), "{status} {body}");
        let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(listing["known"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["addr"] == "10.0.0.43:7476" && k["node_key"] == "ef44"));

        // A cross-mesh ask is answered politely, but empty.
        let (status, body) = http(port, "GET", "/v1/peers?network=other-mesh", "");
        assert!(status.contains("200"), "{status} {body}");
        let listing: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(listing["peers"].as_array().unwrap().is_empty());
    }
}

#[cfg(test)]
mod request_limit_tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    /// Send `raw` from a client and parse it as one request on the server
    /// side. Returns what read_request made of it.
    fn parse(raw: Vec<u8>) -> Option<(String, String, Vec<u8>)> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let _ = c.write_all(&raw);
            let _ = c.shutdown(std::net::Shutdown::Write);
            // hold the socket open so the server side can finish reading
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let (stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let parsed = read_request(&stream);
        client.join().unwrap();
        parsed
    }

    #[test]
    fn a_well_formed_request_parses() {
        let (m, p, b) = parse(b"GET /v1/status HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()).unwrap();
        assert_eq!((m.as_str(), p.as_str()), ("GET", "/v1/status"));
        assert!(b.is_empty());
    }

    #[test]
    fn oversized_header_line_is_refused() {
        let mut raw = b"GET / HTTP/1.1\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES));
        raw.extend_from_slice(b"\r\n\r\n");
        assert!(parse(raw).is_none(), "header line beyond budget is dropped");
    }

    #[test]
    fn too_many_headers_are_refused() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADER_COUNT + 2) {
            raw.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        assert!(
            parse(raw).is_none(),
            "header count beyond budget is dropped"
        );
    }

    #[test]
    fn oversized_body_is_refused_without_allocating() {
        let raw = format!(
            "POST /v1/entries HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(parse(raw.into_bytes()).is_none());
    }

    #[test]
    fn explorer_ships_the_neural_bubble_layer() {
        // The ecosphere page is a string constant; these hooks are what a
        // static page cannot prove and a reviewer cannot easily grep for
        // once the file grows. Keep the neural rendering and its off-switch
        // pinned.
        for needle in [
            "function stepSignals(",
            "function synapsePoint(",
            "function glowSprite(",
            "function spawnPulse(",
            "function toggleNeural(",
            "#mesh, #layers, #bubbles",
        ] {
            assert!(
                EXPLORER_HTML.contains(needle),
                "explorer page lost: {needle}"
            );
        }
    }

    #[test]
    fn partial_request_times_out_instead_of_hanging() {
        // Client sends a request line but never finishes the headers; the
        // server-side read timeout must end the read, not block forever.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"GET /v1/status HTTP/1.1\r\nHost: x\r\n")
                .unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
        });
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let parsed = read_request(&stream);
        assert!(parsed.is_none(), "stalled request is not accepted");
        client.join().unwrap();
    }

    /// Seeded xorshift for the parser fuzz below; fixed seed so any failure
    /// reproduces exactly.
    struct FuzzRng(u64);
    impl FuzzRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            let len = (self.next() as usize) % max;
            (0..len).map(|_| self.next() as u8).collect()
        }
        fn ascii(&mut self, max: usize) -> String {
            String::from_utf8_lossy(&self.bytes(max))
                .chars()
                .filter(|c| !c.is_control() || *c == '\r' || *c == '\n' || *c == '\t')
                .collect()
        }
    }

    #[test]
    fn http_parser_survives_seeded_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let data = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = serve(&data, &format!("127.0.0.1:{port}"), None, 5, 5, None);
        });
        let mut ready = false;
        for _ in 0..200 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                drop(s);
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(ready, "serve did not come up");

        // Pure parsers first: cursors and list queries are attacker-
        // controlled strings; they must clamp or reject, never panic.
        let mut rng = FuzzRng(0x5eed_c11a);
        for _ in 0..3000 {
            let raw = rng.ascii(64);
            let _ = decode_cursor(&raw);
            let (ns, author, limit, offset) = parse_list_query(&raw);
            assert!(limit <= 500 && offset <= 1_000_000);
            if let Some(ns) = &ns {
                assert!(!ns.is_empty());
            }
            if let Some(author) = &author {
                assert!(!author.is_empty());
            }
        }

        // Live sockets: random shapes at the request reader. Whatever the
        // server answers (status line, empty reply, or hard close) is fine;
        // a panic or a wedged listener is not. Streams are always dropped
        // so stalled reads end via EOF, not the 10 s deadline.
        use std::io::Read;
        for round in 0..120 {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut payload: Vec<u8> = match round % 5 {
                0 => rng.bytes(512),
                1 => format!("{} {} HTTP/1.1\r\n", rng.ascii(16), rng.ascii(64)).into_bytes(),
                2 => format!(
                    "GET /v1/entries?{} HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                    rng.ascii(48),
                    rng.next() % 4096
                )
                .into_bytes(),
                3 => {
                    // long request line, way past any sane method or path
                    let mut long = b"GET /".to_vec();
                    long.extend(std::iter::repeat_n(b'x', 8 * 1024));
                    long
                }
                _ => {
                    let mut cut =
                        b"POST /v1/entries HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
                            .to_vec();
                    cut.extend(rng.bytes(16));
                    cut
                }
            };
            if rng.next().is_multiple_of(2) {
                // write only a prefix, then drop: mid-request disconnect
                let cut = (rng.next() as usize) % (payload.len() + 1);
                payload.truncate(cut);
            }
            let _ = stream.write_all(&payload);
            // Half-close: the shapes above often promise more bytes than
            // they send, and without EOF the server rightly waits for its
            // deadline. Signaling write-EOF lets it answer or drop now,
            // which keeps this test seconds, not minutes.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
        }

        // The server must still answer an honest request after the abuse.
        let mut probe = TcpStream::connect(("127.0.0.1", port)).unwrap();
        probe
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut raw = String::new();
        probe.read_to_string(&mut raw).unwrap();
        assert!(
            raw.starts_with("HTTP/1.1 200"),
            "server wedged after fuzz rounds: {}",
            raw.split("\r\n").next().unwrap_or("")
        );
    }
}

#[cfg(test)]
mod identity_chain_tests {
    use super::*;
    use datu_core::attest::{AttestationDoc, CosignDoc, RevokeDoc};
    use datu_core::{Entry, EntryBody};

    fn entry_with(
        key_seed: u8,
        seq: u64,
        namespace: &str,
        payload: serde_json::Value,
        refs: Vec<[u8; 32]>,
        prev: Option<[u8; 32]>,
    ) -> Entry {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[key_seed; 32]);
        let pq = datu_core::pq::keypair().unwrap().1;
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: namespace.into(),
            seq,
            prev,
            refs,
            timestamp_ms: 1,
            payload: serde_json::to_vec(&payload).unwrap(),
        };
        Entry::sign(body, &ed, &pq).unwrap()
    }

    #[test]
    fn chain_reports_attestation_cosignature_and_revocation() {
        let store = Store::open_in_memory().unwrap();
        // Subject key we will attest; author keys 3 and 4 are the root and a cosigner.
        let subject = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let att = entry_with(
            3,
            0,
            datu_core::attest::NS_ATTEST,
            serde_json::to_value(AttestationDoc {
                subject: subject.clone(),
                label: Some("Acme Registry".into()),
                claims: serde_json::json!({"role":"clerk","legal_name":"Acme Ltd"}),
            })
            .unwrap(),
            vec![],
            None,
        );
        let att_id = att.id().unwrap();
        store.insert_entry(&att).unwrap();
        let cosign = entry_with(
            4,
            0,
            datu_core::attest::NS_COSIGN,
            serde_json::to_value(CosignDoc {
                attestation: hex::encode(att_id),
            })
            .unwrap(),
            vec![att_id],
            None,
        );
        store.insert_entry(&cosign).unwrap();

        let chain = identity_chain_json(&store, &subject).unwrap();
        assert_eq!(chain["counts"]["attestations"], 1);
        assert_eq!(chain["counts"]["distinct_cosigners"], 1);
        assert_eq!(chain["attestations"][0]["label"], "Acme Registry");
        assert_eq!(chain["attestations"][0]["revoked"], false);
        assert_eq!(
            chain["attestations"][0]["cosigners"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(chain["note"].as_str().unwrap().contains("not a verdict"));

        // revoke the attestation by id: the attestation stays, flagged, with
        // the revoker named
        let rev = entry_with(
            3,
            1,
            datu_core::attest::NS_REVOKE,
            serde_json::to_value(RevokeDoc {
                attestation: Some(hex::encode(att_id)),
                subject: None,
                reason: Some("left the registry".into()),
            })
            .unwrap(),
            vec![],
            Some(att_id),
        );
        let rev_id = rev.id().unwrap();
        store.insert_entry(&rev).unwrap();
        let chain = identity_chain_json(&store, &subject).unwrap();
        assert_eq!(chain["counts"]["revoked"], 1);
        assert_eq!(chain["attestations"][0]["revoked"], true);
        assert_eq!(
            chain["attestations"][0]["revoked_by"]["reason"],
            "left the registry"
        );

        // key-level ejection: a revoke naming the subject directly
        let keyrev = entry_with(
            3,
            2,
            datu_core::attest::NS_REVOKE,
            serde_json::to_value(RevokeDoc {
                attestation: None,
                subject: Some(subject.clone()),
                reason: Some("key compromised".into()),
            })
            .unwrap(),
            vec![],
            Some(rev_id),
        );
        store.insert_entry(&keyrev).unwrap();
        let chain = identity_chain_json(&store, &subject).unwrap();
        assert_eq!(chain["revoked_by_key"]["reason"], "key compromised");

        // an unattested key is an empty chain, not an error
        let nobody = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let chain = identity_chain_json(&store, &nobody).unwrap();
        assert_eq!(chain["counts"]["attestations"], 0);
    }
}
