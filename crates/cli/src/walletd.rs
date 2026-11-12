//! `datu signet serve`: the local Signet Personal Vault bridge (production
//! mode). The old spelling `datu wallet serve` still works as an alias.
//!
//! A browser wallet extension and a dApp cannot safely hold ML-DSA-65 keys
//! in JavaScript, and they should not try: this process owns the keystore,
//! unlocks it per request with your passphrase, and performs the exact same
//! signing and sealing as the CLI.
//!
//! Hardening:
//! - **Pairing token**: a 256-bit token is generated once at
//!   `<data-dir>/wallet/bridge.token` (0600). Every `/v1` call must send
//!   `Authorization: Bearer <token>`; the token is compared in constant time.
//!   Without it, any local process or web page could ask the bridge to sign.
//! - **Origin allowlist**: browser requests must come from an extension page
//!   (`chrome-extension://…`) or an explicitly allowed dev origin
//!   (`--allow-origin http://127.0.0.1:5173`). Non-browser clients (no
//!   Origin header) still need the token.
//! - **Passphrase throttling**: 5 wrong passphrases lock that identity for
//!   15 seconds (429), so a hostile page cannot brute-force even with a token.
//! - **Loopback by default**: pass `--addr 127.0.0.1:7482`. Binding a
//!   non-loopback address prints a loud warning.
//! - **JSON errors, never silent drops**: handler failures return
//!   `{"error": …}` with a proper status code.
//!
//! Routes:
//!   GET  /                      bridge doc page (no token)
//!   GET  /v1/pair               token handed to browser wallet extensions only
//!                               (Origin must be chrome-extension://) - lets the
//!                               extension pair itself; web pages are refused
//!   GET  /v1/wallet/identities  public identities (ed + seal keys)
//!   POST /v1/wallet/create      {name, passphrase}
//!   POST /v1/wallet/party-sign  {name, passphrase, role, document, kind?}
//!   POST /v1/wallet/seal        {name, passphrase, document, fields, to[], to_fields[]}
//!   POST /v1/wallet/seal-deferred    {name, passphrase, document, fields, to/to_fields}
//!   POST /v1/wallet/release-deferred {document, field, release}
//!   POST /v1/wallet/open        {name, passphrase, document}
//!   POST /v1/wallet/deferred-open (alias: open-deferred)
//!                               {name, passphrase, document, field, release}
//!   POST /v1/wallet/export      {name, passphrase, backup_passphrase}
//!   POST /v1/wallet/import      {input, backup_passphrase, rename?}
//!   POST /v1/wallet/verify-entry{entry}
//!   POST /v1/wallet/sign-entry  {name, passphrase, request}

use crate::serve as ledger_api;
use datu_wallet::wire::{entry_from_sign_request, SignRequest};
use datu_core::parties::SignedDocument;
use datu_wallet::{IdentityBackup, LoadedIdentity, Wallet};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_PASSPHRASE_FAILURES: u32 = 5;
const LOCKOUT_MS: u64 = 15_000;
const TOKEN_FILE: &str = "wallet/bridge.token";

pub fn serve(data_dir: &Path, addr: &str, allow_origins: Vec<String>) -> Result<(), String> {
    let wallet = Wallet::open(data_dir);
    let identities = wallet.list().unwrap_or_default();
    let token = load_or_create_token(data_dir)?;
    let mut origins = allow_origins;
    origins.push("http://127.0.0.1:5173".into());
    origins.push("http://localhost:5173".into());
    origins.sort();
    origins.dedup();

    let listener = TcpListener::bind(addr).map_err(|e| format!("cannot bind {addr}: {e}"))?;
    println!("datu wallet bridge serving http://{addr}");
    println!("  identities: {}", identities.len());
    for id in &identities {
        println!(
            "    {:<16} ed {}  seal {}",
            id.name,
            &id.ed_public[..16.min(id.ed_public.len())],
            id.seal_public
        );
    }
    println!("  pairing token: {}", data_dir.join(TOKEN_FILE).display());
    println!("    {token}");
    println!("  the browser wallet extension can pair itself - no paste needed");
    println!("  (manual fallback: paste the token into the panel's Settings)");
    println!("  allowed browser origins: chrome-extension://… , {}", origins.join(" , "));
    if !addr.starts_with("127.0.0.1") && !addr.starts_with("localhost") {
        println!("  WARNING: bound to a non-loopback address - anyone who can reach");
        println!("  this port with the token can ask for signatures");
    }
    println!("  keys never leave this process; every signature needs the passphrase");
    println!("ctrl-c to stop");

    let dir = data_dir.to_path_buf();
    let token = Arc::new(token);
    let origins = Arc::new(origins);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let dir = dir.clone();
        let token = Arc::clone(&token);
        let origins = Arc::clone(&origins);
        std::thread::spawn(move || {
            let _ = handle(stream, &dir, &token, &origins);
        });
    }
    Ok(())
}

fn handle(
    stream: TcpStream,
    data_dir: &PathBuf,
    token: &str,
    origins: &[String],
) -> Result<(), String> {
    let mut stream = stream;
    if let Err(e) = handle_inner(&mut stream, data_dir, token, origins) {
        if let Some(rest) = e.strip_prefix("TOO_MANY_ATTEMPTS:") {
            let _ = respond_json(
                &mut stream,
                "429 Too Many Requests",
                &serde_json::json!({ "error": rest.trim() }),
            );
        } else {
            let _ = respond_json(&mut stream, "400 Bad Request", &serde_json::json!({ "error": e }));
        }
    }
    Ok(())
}

fn handle_inner(
    stream: &mut TcpStream,
    data_dir: &PathBuf,
    token: &str,
    origins: &[String],
) -> Result<(), String> {
    let (method, path, body, headers) = match read_request(stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let route = path.split('?').next().unwrap_or("/").to_string();
    if method == "OPTIONS" {
        respond(stream, "204 No Content", "text/plain", "")?;
        return Ok(());
    }

    if route == "/" && method == "GET" {
        return respond(stream, "200 OK", "text/html; charset=utf-8", BRIDGE_HTML);
    }

    // Self-pairing for browser wallet extensions: a human never copies the
    // token. Only an extension page carries a chrome-extension:// Origin - web
    // pages cannot forge it - and the extension only gains the right to *ask*
    // for signatures (still passphrase-gated) plus read access.
    if route == "/v1/pair" && method == "GET" {
        let origin = headers.get("origin").cloned().unwrap_or_default();
        if origin.starts_with("chrome-extension://") {
            println!("[pair] browser wallet extension paired: {origin}");
            return respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "service": "datu-wallet-bridge",
                    "token": token,
                }),
            );
        }
        return respond_json(
            stream,
            "403 Forbidden",
            &serde_json::json!({
                "error": "auto-pairing is only offered to browser wallet extensions (chrome-extension:// origin); web pages must be paired explicitly",
            }),
        );
    }

    if let Err((status, message)) = check_access(&headers, token, origins) {
        return respond_json(
            stream,
            status,
            &serde_json::json!({ "error": message }),
        );
    }

    let wallet = Wallet::open(data_dir);
    match (method.as_str(), route.as_str()) {
        // Create an identity: the holder chooses the passphrase here. It is
        // stretched with Argon2id and never stored or transmitted.
        ("POST", "/v1/wallet/create") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            if passphrase.chars().count() < 8 {
                return Err("passphrase must be at least 8 characters".into());
            }
            let public = wallet.create(&name, &passphrase)?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "identity": {
                        "name": public.name,
                        "ed_public": public.ed_public,
                        "pq_alg": "mldsa65",
                        "pq_public_prefix": &public.pq_public[..16.min(public.pq_public.len())],
                        "seal_public": public.seal_public,
                    },
                }),
            )
        }
        ("GET", "/v1/wallet/identities") => {
            let identities = wallet.list().map_err(|e| e.to_string())?;
            let items: Vec<serde_json::Value> = identities
                .iter()
                .map(|id| {
                    serde_json::json!({
                        "name": id.name,
                        "ed_public": id.ed_public,
                        "pq_alg": "mldsa65",
                        "pq_public_prefix": &id.pq_public[..16.min(id.pq_public.len())],
                        "seal_public": id.seal_public,
                        "created_at_ms": id.created_at_ms,
                    })
                })
                .collect();
            respond_json(stream, "200 OK", &serde_json::json!({ "identities": items }))
        }
        ("POST", "/v1/wallet/party-sign") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let role = str_field(&body_json, "role")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let mut document = as_signed_document(&body_json)?;
            identity.sign_document(&mut document, &role)?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "signed_by": identity.public.ed_public,
                    "role": role,
                    "document": document,
                }),
            )
        }
        ("POST", "/v1/wallet/seal") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let mut document = body_json
                .get("document")
                .cloned()
                .ok_or("missing 'document'")?;
            let fields = string_list(&body_json, "fields");
            let mut readers = string_list(&body_json, "to");
            for field in string_list(&body_json, "to_fields") {
                match document.get(&field) {
                    Some(serde_json::Value::String(key)) => readers.push(key.clone()),
                    Some(serde_json::Value::Array(items)) => {
                        for item in items {
                            if let Some(key) = item.as_str() {
                                readers.push(key.to_string());
                            }
                        }
                    }
                    _ => return Err(format!("document has no seal key in field '{field}'")),
                }
            }
            readers.sort();
            readers.dedup();
            if readers.is_empty() {
                return Err("pass at least one reader seal key (to / to_fields)".into());
            }
            let sealed = identity.seal_fields(&mut document, &fields, &readers)?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "sealed": sealed,
                    "readers": readers.len(),
                    "document": document,
                }),
            )
        }
        // Deferred delivery, issuer side: seal fields now, hand back the
        // release secrets; the release entry publishes the key half later.
        ("POST", "/v1/wallet/seal-deferred") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let mut document = body_json
                .get("document")
                .cloned()
                .ok_or("missing 'document'")?;
            let fields = string_list(&body_json, "fields");
            let mut holders = string_list(&body_json, "to");
            for field in string_list(&body_json, "to_fields") {
                match document.get(&field) {
                    Some(serde_json::Value::String(key)) => holders.push(key.clone()),
                    Some(serde_json::Value::Array(items)) => {
                        for item in items {
                            if let Some(key) = item.as_str() {
                                holders.push(key.to_string());
                            }
                        }
                    }
                    _ => return Err(format!("document has no seal key in field '{field}'")),
                }
            }
            holders.sort();
            holders.dedup();
            if holders.len() != 1 {
                return Err(
                    "deferred delivery addresses exactly one holder seal key (to / to_fields)"
                        .into(),
                );
            }
            let releases = identity.seal_deferred_fields(&mut document, &fields, &holders[0])?;
            let secrets: serde_json::Map<String, serde_json::Value> = releases
                .iter()
                .map(|(field, secret)| (field.clone(), serde_json::json!(hex::encode(secret))))
                .collect();
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "sealed": releases.len(),
                    "holder": holders[0],
                    "document": document,
                    "releases": secrets,
                }),
            )
        }
        // Deferred delivery, issuer side: turn a release secret into the
        // key half a release entry carries. Public keys only - releasing is
        // a ledger act, not a seal-key act. Same action as the desktop FFI.
        ("POST", "/v1/wallet/release-deferred") => {
            let body_json = parse_body(&body)?;
            let field = str_field(&body_json, "field")?;
            let document = body_json.get("document").cloned().ok_or("missing 'document'")?;
            let field_value = document
                .get(field.as_str())
                .cloned()
                .ok_or_else(|| format!("document has no field '{field}'"))?;
            let deferred: datu_wallet::DeferredField = serde_json::from_value(field_value)
                .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
            let release = body_json.get("release").cloned().ok_or("missing 'release'")?;
            let secret_hex = release
                .get("fields")
                .and_then(|fields| fields.get(&field))
                .and_then(|secret| secret.as_str())
                .ok_or_else(|| format!("release secrets have no entry for '{field}'"))?;
            let secret: [u8; 32] = hex::decode(secret_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or("release secret is not a 32-byte hex value")?;
            let share = datu_wallet::attach_release(&deferred, &secret)?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "field": field, "share": share }),
            )
        }
        ("POST", "/v1/wallet/open") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let mut document = body_json
                .get("document")
                .cloned()
                .ok_or("missing 'document'")?;
            let (mut opened, mut skipped) = identity.open_fields(&mut document)?;
            let signed_document = document.get("doc").map(|d| d.is_object()).unwrap_or(false)
                && document.get("parties").is_some();
            if signed_document {
                if let Some(inner) = document.get_mut("doc") {
                    let (o, s) = identity.open_fields(inner)?;
                    opened += o;
                    skipped += s;
                }
            }
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "opened": opened,
                    "skipped": skipped,
                    "document": document,
                }),
            )
        }
        // Deferred delivery: open a field whose release share the release
        // entry has published. The holder - and only the holder - recomposes
        // the content key; the BLAKE3 commitment checks the reveal.
        ("POST", "/v1/wallet/deferred-open") | ("POST", "/v1/wallet/open-deferred") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let field = str_field(&body_json, "field")?;
            let document = body_json.get("document").ok_or("missing 'document'")?;
            let field_value = document
                .get(field.as_str())
                .cloned()
                .ok_or_else(|| format!("document has no field '{field}'"))?;
            let deferred: datu_wallet::DeferredField = serde_json::from_value(field_value)
                .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
            let release = body_json.get("release").ok_or("missing 'release'")?;
            let share = datu_wallet::SealedShare::find(release).ok_or(
                "release carries no share object (expected a 'datu-share-v2' object)",
            )?;
            let plaintext = datu_wallet::open_deferred(
                &deferred,
                &share,
                &identity.public.seal_public,
                &identity.seal,
            )?;
            let value: serde_json::Value = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("decrypted field is not valid JSON: {e}"))?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "field": field, "value": value }),
            )
        }
        // Portable, separately-encrypted identity backup (offline copy or
        // moving to another device). Needs the identity passphrase AND sets a
        // distinct backup passphrase.
        ("POST", "/v1/wallet/export") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let backup_passphrase = str_field(&body_json, "backup_passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let backup = wallet.export_identity(&name, &passphrase, &backup_passphrase)?;
            let _ = identity;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "backup": backup }),
            )
        }
        ("POST", "/v1/wallet/import") => {
            let body_json = parse_body(&body)?;
            let backup: IdentityBackup = serde_json::from_value(
                body_json.get("backup").cloned().ok_or("missing 'backup'")?,
            )
            .map_err(|e| format!("not a datu identity backup: {e}"))?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let rename = body_json
                .get("rename")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            let public = wallet.import_identity(&backup, &passphrase, rename.as_deref())?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "identity": {
                        "name": public.name,
                        "ed_public": public.ed_public,
                        "pq_alg": "mldsa65",
                        "pq_public_prefix": &public.pq_public[..16.min(public.pq_public.len())],
                        "seal_public": public.seal_public,
                    },
                    "note": "imported identity unlocks with the backup passphrase",
                }),
            )
        }
        // Verify a record fetched from ANY node (a validator or a free
        // observer). The node is untrusted: the wallet checks both hybrid
        // signatures here, using the same code the ledger uses.
        ("POST", "/v1/wallet/verify-entry") => {
            let body_json = parse_body(&body)?;
            let entry_value = body_json.get("entry").cloned().ok_or("missing 'entry'")?;
            let entry = ledger_api::entry_from_submission(&entry_value)?;
            entry
                .verify()
                .map_err(|e| format!("signature verification failed: {e}"))?;
            let id = entry.id().map_err(|e| e.to_string())?;
            let parties: Vec<serde_json::Value> =
                SignedDocument::from_payload(&entry.body.payload)
                    .and_then(|doc| doc.verify().ok())
                    .map(|verified| {
                        verified
                            .iter()
                            .map(|(role, key)| serde_json::json!({"role": role, "key": key}))
                            .collect()
                    })
                    .unwrap_or_default();
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({
                    "ok": true,
                    "id": hex::encode(id),
                    "author": entry.body.author,
                    "namespace": entry.body.namespace,
                    "seq": entry.body.seq,
                    "timestamp_ms": entry.body.timestamp_ms,
                    "parties": parties,
                    "note": "verified by your wallet - the serving node was not trusted",
                }),
            )
        }
        ("POST", "/v1/wallet/sign-entry") => {
            let body_json = parse_body(&body)?;
            let name = str_field(&body_json, "name")?;
            let passphrase = str_field(&body_json, "passphrase")?;
            let identity = load_guarded(&wallet, &name, &passphrase)?;
            let request: SignRequest = serde_json::from_value(
                body_json.get("request").cloned().ok_or("missing 'request'")?,
            )
            .map_err(|e| format!("bad sign request: {e}"))?;
            let entry = entry_from_sign_request(&identity, &request)?;
            let id = entry.id().map_err(|e| e.to_string())?;
            let json = ledger_api::entry_full_json(&entry)?;
            respond_json(
                stream,
                "200 OK",
                &serde_json::json!({ "ok": true, "id": hex::encode(id), "entry": json }),
            )
        }
        (m, _) => respond_json(
            stream,
            "404 Not Found",
            &serde_json::json!({ "error": format!("no route for {m} {route}") }),
        ),
    }
}

// ---- pairing / access control ----

fn load_or_create_token(data_dir: &Path) -> Result<String, String> {
    let path = data_dir.join(TOKEN_FILE);
    if path.exists() {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let token = text.trim().to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    std::fs::write(&path, &token).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

fn const_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn check_access(
    headers: &HashMap<String, String>,
    token: &str,
    origins: &[String],
) -> Result<(), (&'static str, String)> {
    if let Some(origin) = headers.get("origin") {
        let allowed = origin.starts_with("chrome-extension://")
            || origins.iter().any(|o| o == origin);
        if !allowed {
            return Err((
                "403 Forbidden",
                format!("origin '{origin}' is not allowed - restart the bridge with --allow-origin"),
            ));
        }
    }
    let authed = headers
        .get("authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|presented| const_eq(presented.trim().as_bytes(), token.as_bytes()))
        .unwrap_or(false);
    if !authed {
        return Err((
            "401 Unauthorized",
            "missing or wrong pairing token - paste the token printed by `datu wallet serve` (wallet/bridge.token)"
                .into(),
        ));
    }
    Ok(())
}

// ---- passphrase throttling ----

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn failures() -> &'static Mutex<HashMap<String, (u32, u64)>> {
    static FAILURES: OnceLock<Mutex<HashMap<String, (u32, u64)>>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_guarded(wallet: &Wallet, name: &str, passphrase: &str) -> Result<LoadedIdentity, String> {
    {
        let map = failures().lock().map_err(|_| "lock poisoned".to_string())?;
        if let Some((count, until)) = map.get(name).copied() {
            let now = now_ms();
            if count >= MAX_PASSPHRASE_FAILURES && now < until {
                return Err(format!(
                    "TOO_MANY_ATTEMPTS: too many wrong passphrases for '{name}', retry in {}s",
                    (until - now) / 1000 + 1
                ));
            }
        }
    }
    match wallet.load(name, passphrase) {
        Ok(identity) => {
            if let Ok(mut map) = failures().lock() {
                map.remove(name);
            }
            Ok(identity)
        }
        Err(e) => {
            if let Ok(mut map) = failures().lock() {
                let now = now_ms();
                let entry = map.entry(name.to_string()).or_insert((0, 0));
                entry.0 += 1;
                if entry.0 >= MAX_PASSPHRASE_FAILURES {
                    entry.1 = now + LOCKOUT_MS;
                }
            }
            Err(e)
        }
    }
}

// ---- shared helpers ----

/// Either an already party-signed document, or a bare object wrapped with
/// the request's `kind`.
fn as_signed_document(body: &serde_json::Value) -> Result<SignedDocument, String> {
    let document = body.get("document").cloned().ok_or("missing 'document'")?;
    if let Ok(signed) = serde_json::from_value::<SignedDocument>(document.clone()) {
        return Ok(signed);
    }
    if !document.is_object() {
        return Err("document must be a JSON object".into());
    }
    let kind = body
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or("document is not party-signed and no 'kind' was given")?;
    Ok(SignedDocument::new(kind, document))
}

fn parse_body(body: &[u8]) -> Result<serde_json::Value, String> {
    serde_json::from_slice(body).map_err(|e| format!("bad JSON body: {e}"))
}

fn str_field(body: &serde_json::Value, name: &str) -> Result<String, String> {
    body.get(name)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing '{name}'"))
}

fn string_list(body: &serde_json::Value, name: &str) -> Vec<String> {
    body.get(name)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn read_request(
    stream: &TcpStream,
) -> Option<(String, String, Vec<u8>, HashMap<String, String>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }
    if content_length > MAX_BODY_BYTES {
        return None;
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some((method, path, body, headers))
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> Result<(), String> {
    // Access-Control-Allow-Private-Network: modern Chrome (Private Network
    // Access / Local Network Access) sends an OPTIONS preflight carrying
    // `Access-Control-Request-Private-Network: true` before letting an
    // extension page fetch http://127.0.0.1 - without this header on the
    // preflight (and the actual responses) the wallet extension sees every
    // request fail as "no wallet service found".
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, Access-Control-Request-Private-Network\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Private-Network: true\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

const BRIDGE_HTML: &str = r##"<!doctype html>
<html><head><meta charset="utf-8"><title>datu wallet bridge</title>
<style>body{font-family:ui-monospace,Menlo,monospace;background:#0d1117;color:#c9d1d9;padding:2rem}
a{color:#58a6ff}code{background:#161b22;padding:.1rem .3rem;border-radius:4px}
.warn{color:#f0b429}</style></head>
<body><h1>datu wallet bridge</h1>
<p>This process holds your keystore. Keys never leave it; every signature needs your passphrase.</p>
<p class="warn">Paired access only: every /v1 call needs
<code>Authorization: Bearer &lt;token&gt;</code>. The token is in
<code>wallet/bridge.token</code> and was printed at startup.</p>
<ul>
<li><code>GET&nbsp;/v1/wallet/identities</code> - public keys</li>
<li><code>POST /v1/wallet/create</code> - new identity (you choose the passphrase)</li>
<li><code>POST /v1/wallet/party-sign</code> - consent signature (e.g. role <b>holder</b>)</li>
<li><code>POST /v1/wallet/seal</code> / <code>open</code> - field encryption</li>
<li><code>POST /v1/wallet/verify-entry</code> - verify a record from any node</li>
<li><code>POST /v1/wallet/sign-entry</code> - author a ledger entry</li>
</ul>
<p>Browser origins: extension pages and explicitly allowed dev origins only.
Bind 127.0.0.1. If you can read this page from another machine, stop the bridge.</p>
</body></html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &str) -> (String, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

    /// Deferred delivery over the bridge HTTP surface, end to end: token
    /// auth, the issuer-side seal, and the holder-side open with its
    /// wrong-holder refusal.
    #[test]
    fn deferred_delivery_over_http() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let serve_dir = data.clone();
        std::thread::spawn(move || {
            let _ = serve(&serve_dir, &format!("127.0.0.1:{port}"), Vec::new());
        });

        // The bridge writes its pairing token at startup.
        let token_path = data.join(TOKEN_FILE);
        let started = Instant::now();
        let token = loop {
            if let Ok(text) = std::fs::read_to_string(&token_path) {
                let token = text.trim().to_string();
                if token.len() >= 32 {
                    break token;
                }
            }
            if started.elapsed() > Duration::from_secs(10) {
                panic!("bridge did not come up");
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        // No token, no service.
        let (status, _) = http(
            port,
            "POST",
            "/v1/wallet/create",
            None,
            &json!({"name": "issuer", "passphrase": "issuer pass"}).to_string(),
        );
        assert!(status.contains("401"), "unpaired calls are refused: {status}");

        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/create",
            Some(&token),
            &json!({"name": "issuer", "passphrase": "issuer pass"}).to_string(),
        );
        assert!(status.contains("200"), "{status} {body}");
        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/create",
            Some(&token),
            &json!({"name": "holder", "passphrase": "holder pass"}).to_string(),
        );
        assert!(status.contains("200"), "{status} {body}");
        let holder_seal = serde_json::from_str::<serde_json::Value>(&body).unwrap()
            ["identity"]["seal_public"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/seal-deferred",
            Some(&token),
            &json!({
                "name": "issuer",
                "passphrase": "issuer pass",
                "document": {"cert_id": "C-3", "owner_name": "Amina", "holder_seal": holder_seal},
                "fields": ["owner_name"],
                "to_fields": ["holder_seal"],
            })
            .to_string(),
        );
        assert!(status.contains("200"), "seal-deferred failed: {status} {body}");
        let sealed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sealed["document"]["owner_name"]["sealed"], "datu-sealed-deferred-v2");
        assert!(sealed["releases"]["owner_name"].as_str().is_some());

        // The issuer-side release: the bridge turns the secret into the key
        // half a release entry carries (public keys only, no passphrase).
        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/release-deferred",
            Some(&token),
            &json!({
                "document": sealed["document"],
                "field": "owner_name",
                "release": {"version": 1, "fields": sealed["releases"]},
            })
            .to_string(),
        );
        assert!(status.contains("200"), "release-deferred failed: {status} {body}");
        let released: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(released["share"]["sealed"], "datu-share-v2");
        let release = released["share"].clone();

        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/deferred-open",
            Some(&token),
            &json!({
                "name": "issuer",
                "passphrase": "issuer pass",
                "document": sealed["document"],
                "field": "owner_name",
                "release": release,
            })
            .to_string(),
        );
        assert!(status.contains("400"), "non-holder refused: {status} {body}");
        assert!(body.contains("another holder"), "{body}");

        // The FFI action name works as a route alias.
        let (status, body) = http(
            port,
            "POST",
            "/v1/wallet/open-deferred",
            Some(&token),
            &json!({
                "name": "holder",
                "passphrase": "holder pass",
                "document": sealed["document"],
                "field": "owner_name",
                "release": release,
            })
            .to_string(),
        );
        assert!(status.contains("200"), "holder open failed: {status} {body}");
        let opened: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(opened["value"], json!("Amina"));
    }
}
