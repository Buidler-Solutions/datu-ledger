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
//!   POST /v1/entries           submit a signed entry (JSON, base64 payload)
//!   POST /v1/sync/haves        set-reconciliation: send a Bloom filter of
//!                              the ids you have, receive what you lack

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use datu_core::bloom::BloomFilter;
use datu_core::{Checkpoint, CheckpointBody, Entry};
use datu_p2p::NetworkPolicy;
use datu_store::{Store, StoreError, WritePolicy};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

pub use datu_wallet::wire::{entry_from_submission, entry_full_json};

/// Hard cap on an HTTP request body (a single entry JSON is ≤ ~350 KB).
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

pub fn serve(data_dir: &Path, addr: &str, policy: Option<WritePolicy>) -> Result<(), String> {
    // Fail fast if there is no node to serve.
    let store = Store::open_with_policy(&data_dir.join("node.db"), policy.clone())
        .map_err(|e| e.to_string())?;
    drop(store);
    let network = crate::read_network(data_dir)?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    println!("datu node serving http://{addr}");
    match &network {
        None => println!("  network:   open (permissionless - any node may join and sync)"),
        Some(n) if n.is_permissioned() => println!(
            "  network:   permissioned mesh '{}' ({} member(s), {} attestation root(s))",
            if n.network_id.is_empty() { "(unnamed)" } else { &n.network_id },
            n.members.len(),
            n.roots.len()
        ),
        Some(n) if !n.network_id.is_empty() => {
            println!("  network:   walled mesh '{}' (permissionless mirror)", n.network_id)
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
    println!("  explorer:  http://{addr}/");
    println!("  submit:    POST http://{addr}/v1/entries   (signed entry JSON)");
    println!("  feed head: GET  http://{addr}/v1/feed/{{author}}");
    println!("ctrl-c to stop");
    let dir = data_dir.to_path_buf();
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let dir = dir.clone();
        let policy = policy.clone();
        let network = network.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &dir, policy, network);
        });
    }
    Ok(())
}

fn handle(
    stream: TcpStream,
    data_dir: &PathBuf,
    policy: Option<WritePolicy>,
    network: Option<NetworkPolicy>,
) -> Result<(), String> {
    let mut stream = stream;
    if let Err(e) = handle_inner(&mut stream, data_dir, policy, network) {
        let _ = respond_json(&mut stream, "400 Bad Request", &serde_json::json!({ "error": e }));
    }
    Ok(())
}

fn handle_inner(
    stream: &mut TcpStream,
    data_dir: &PathBuf,
    policy: Option<WritePolicy>,
    network: Option<NetworkPolicy>,
) -> Result<(), String> {
    let request = match read_request(stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let (method, path, body) = request;
    let route = path.split('?').next().unwrap_or("/").to_string();
    let query = path.splitn(2, '?').nth(1).unwrap_or("").to_string();

    if method == "OPTIONS" {
        respond(stream, "204 No Content", "text/plain", "")?;
        return Ok(());
    }

    let store = Store::open_with_policy(&data_dir.join("node.db"), policy)
        .map_err(|e| e.to_string())?;

    match (method.as_str(), route.as_str()) {
        ("GET", "/") => respond(stream, "200 OK", "text/html; charset=utf-8", EXPLORER_HTML),
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
                "policy": policy,
                "network": network,
            });
            respond_json(stream, "200 OK", &json)
        }
        ("GET", "/v1/entries") => {
            let (ns, author, limit) = parse_list_query(&query);
            let entries = store
                .list(ns.as_deref(), author.as_deref(), limit)
                .map_err(|e| e.to_string())?;
            let items: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| entry_summary_json(e).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            respond_json(stream, "200 OK", &serde_json::json!({ "entries": items }))
        }
        ("GET", "/v1/entry") | ("GET", "/v1/entry/") => {
            respond_json(stream, "400 Bad Request", &serde_json::json!({"error":"missing entry id"}))
        }
        ("GET", e) if e.starts_with("/v1/entry/") => {
            let id_hex = &e["/v1/entry/".len()..];
            match hex::decode(id_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            {
                Some(id) => match store.get_entry(&id).map_err(|e| e.to_string())? {
                    Some(entry) => respond_json(stream, "200 OK", &entry_full_json(&entry)?),
                    None => respond_json(stream, "404 Not Found", &serde_json::json!({"error":"entry not found"})),
                },
                None => respond_json(stream, "400 Bad Request", &serde_json::json!({"error":"bad entry id"})),
            }
        }
        ("GET", f) if f.starts_with("/v1/feed/") => {
            let author = &f["/v1/feed/".len()..];
            let feed = store.feed(author).map_err(|e| e.to_string())?;
            let head = feed.last().map(|e| {
                Ok::<_, String>(serde_json::json!({
                    "seq": e.body.seq,
                    "id": hex::encode(e.id().map_err(|e| e.to_string())?),
                }))
            }).transpose()?.unwrap_or(serde_json::Value::Null);
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
                .map(|e| entry_summary_json(e).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            respond_json(stream, "200 OK", &serde_json::json!({
                "author": author, "head": head, "next": next, "entries": items,
            }))
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
        ("POST", "/v1/entries") => {
            let submission: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| format!("bad JSON: {e}"))?;
            let entry = entry_from_submission(&submission)?;
            match store.insert_entry(&entry) {
                Ok(true) => {
                    let id = entry.id().map_err(|e| e.to_string())?;
                    respond_json(stream, "201 Created", &serde_json::json!({
                        "ok": true, "id": hex::encode(id), "seq": entry.body.seq,
                    }))
                }
                Ok(false) => respond_json(stream, "200 OK", &serde_json::json!({
                    "ok": true, "duplicate": true,
                })),
                Err(StoreError::Denied(m)) => respond_json(
                    stream,
                    "403 Forbidden",
                    &serde_json::json!({ "ok": false, "denied": m }),
                ),
                Err(e) => respond_json(stream, "409 Conflict", &serde_json::json!({
                    "ok": false, "rejected": e.to_string(),
                })),
            }
        }
        ("POST", "/v1/sync/haves") => {
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
                    return respond_json(stream, "400 Bad Request", &serde_json::json!({
                        "error": "malformed bloom filter (m, k, bits_b64)"
                    }))
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
            respond_json(stream, "200 OK", &serde_json::json!({
                "entries": items,
                "cursor": next_cursor,
                "more": more,
                "checkpoints": checkpoints,
            }))
        }
        (m, _) => respond_json(
            stream,
            "404 Not Found",
            &serde_json::json!({"error": format!("no route for {m} {route}")}),
        ),
    }
}

fn parse_list_query(query: &str) -> (Option<String>, Option<String>, usize) {
    let mut ns = None;
    let mut author = None;
    let mut limit = 50usize;
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
            _ => {}
        }
    }
    (ns, author, limit)
}

fn payload_preview(entry: &Entry) -> String {
    String::from_utf8_lossy(&entry.body.payload).chars().take(120).collect()
}

fn entry_summary_json(entry: &Entry) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "id": hex::encode(entry.id().map_err(|e| e.to_string())?),
        "author": entry.body.author,
        "namespace": entry.body.namespace,
        "seq": entry.body.seq,
        "timestamp_ms": entry.body.timestamp_ms,
        "refs": entry.body.refs.iter().map(hex::encode).collect::<Vec<_>>(),
        "payload_preview": payload_preview(entry),
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
            signer: value["signer"].as_str().ok_or("missing signer")?.to_string(),
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
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
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

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn respond_json(stream: &mut TcpStream, status: &str, value: &serde_json::Value) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    respond(stream, status, "application/json; charset=utf-8", &body)
}

const EXPLORER_HTML: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"><title>DATU Ledger Explorer</title>
<style>
 body{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}
 h1{font-size:1.2rem} a{color:#58a6ff;text-decoration:none} .muted{color:#8b949e}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 td,th{border-bottom:1px solid #21262d;padding:.45rem .6rem;text-align:left;font-size:.8rem}
 th{color:#8b949e;text-transform:uppercase;font-size:.7rem}
 #detail{margin-top:2rem;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1rem;white-space:pre-wrap;font-size:.75rem;display:none}
 input{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:.4rem;border-radius:6px;width:340px}
 button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:.4rem 1rem;border-radius:6px;cursor:pointer}
 .tag{background:#1f6feb33;color:#79c0ff;border-radius:4px;padding:0 .35rem;font-size:.7rem}
</style></head><body>
<h1>DATU Ledger Explorer <span class="tag">self-verifying mirror</span></h1>
<div><input id="q" placeholder="entry id (64 hex) or author (64 hex)"><button onclick="search()">load</button>
<button onclick="loadEntries()">recent</button> <button onclick="loadWitnesses()">witnesses</button></div>
<table id="rows"><tr><th>id</th><th>author</th><th>namespace</th><th>seq</th><th>payload</th></tr></table>
<div id="detail"></div>
<script>
async function j(u){const r=await fetch(u);return r.json()}
function short(h){return h?h.slice(0,8)+'…':''}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
async function loadEntries(){
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>id</th><th>author</th><th>namespace</th><th>seq</th><th>payload</th></tr>';
 const d=await j('/v1/entries?limit=50');
 (d.entries||[]).forEach(e=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td><a href="#" onclick="show('${e.id}');return false">${short(e.id)}</a></td><td>${short(e.author)}</td><td>${esc(e.namespace)}</td><td>${e.seq}</td><td>${esc(e.payload_preview.slice(0,80))}</td>`;
  rows.appendChild(tr)})}
async function show(id){const e=await j('/v1/entry/'+id);
 const d=document.getElementById('detail');d.style.display='block';
 const p=atob(e.payload_base64||'');d.textContent=JSON.stringify(e,null,2)+'\n\npayload:\n'+p}
async function search(){const q=document.getElementById('q').value.trim();
 if(/^[0-9a-fA-F]{64}$/.test(q)){show(q)}
 else if(/^[0-9a-fA-F]{63,}$/.test(q)){const d=await j('/v1/feed/'+q);showFeed(d)}
 else alert('enter 64-hex entry id or author id')}
async function showFeed(d){
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>seq</th><th>id</th><th>namespace</th><th>payload</th></tr>';
 (d.entries||[]).forEach(e=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td>${e.seq}</td><td><a href="#" onclick="show('${e.id}');return false">${short(e.id)}</a></td><td>${esc(e.namespace)}</td><td>${esc(e.payload_preview.slice(0,80))}</td>`;
  rows.appendChild(tr)})}
async function loadWitnesses(){const d=await j('/v1/checkpoints');
 const rows=document.getElementById('rows');
 rows.innerHTML='<tr><th>witness</th><th>height</th><th>entries</th><th>merkle root</th></tr>';
 (d.witnesses||[]).forEach(w=>{const tr=document.createElement('tr');
  tr.innerHTML=`<td>${short(w.signer)}</td><td>${w.height}</td><td>${w.entries_count}</td><td>${esc(w.entry_ids_root)}</td>`;
  rows.appendChild(tr)})}
loadEntries();
</script></body></html>
"##;
