//! C ABI over the DATU wallet core, for mobile apps (phase 2).
//!
//! The desktop stack signs in a separate bridge process (`datu wallet serve`)
//! because desktops can spawn sidecars; phones cannot. Instead, the exact
//! same wallet code (`datu-wallet`) is linked straight into the app and
//! reached through four C functions:
//!
//! - `datu_wallet_open(data_dir)` → handle bound to a keystore directory
//! - `datu_wallet_request(handle, json)` → JSON in, JSON out; the caller
//!   frees the returned string with `datu_string_free`
//! - `datu_wallet_close(handle)`
//! - `datu_string_free(ptr)`
//!
//! The request grammar mirrors the desktop bridge routes (`{"action":
//! "identities"}`, `create`, `party-sign`, `seal`, `open`, `seal-deferred`,
//! `release-deferred`, `open-deferred`, `export`, `import`, `sign-entry`,
//! `verify-entry`) and returns the same response shapes, so a front end can
//! swap an HTTP bridge for this core without changing screens. Errors come back as `{"error": "…"}` - including
//! passphrase throttling: 5 wrong passphrases lock that identity for 15 s.
//!
//! There is no pairing token and no origin allowlist here: the security
//! boundary is the process itself. The embedding app must never expose
//! `datu_wallet_request` to web content or other apps.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Mutex;

use datu_core::parties::SignedDocument;
use datu_wallet::wire::{self, SignRequest};
use datu_wallet::{DeferredField, IdentityBackup, LoadedIdentity, Wallet};
use serde_json::{json, Value};

const MAX_PASSPHRASE_FAILURES: u32 = 5;
const LOCKOUT_MS: u64 = 15_000;

/// ML-DSA-65 keygen/signing needs several MB of stack in debug builds, and
/// an embedder's calling thread (a Dart VM isolate, a JVM thread) may have
/// far less. Every request runs on a dedicated thread with a stack big
/// enough for the crypto, whatever the host thread's limit is.
const FFI_STACK_BYTES: usize = 16 * 1024 * 1024;

/// One open wallet core: a keystore directory plus per-identity throttle
/// state. Thread-safe; a handle may be shared across threads.
pub struct WalletCore {
    wallet: Wallet,
    failures: Mutex<HashMap<String, (u32, u64)>>,
}

impl WalletCore {
    pub fn new(data_dir: PathBuf) -> WalletCore {
        WalletCore {
            wallet: Wallet::open(&data_dir),
            failures: Mutex::new(HashMap::new()),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Handle one JSON request, return one JSON response. This is the whole
/// protocol; the `extern "C"` layer is only string plumbing around it.
pub fn process(core: &WalletCore, request_json: &str) -> String {
    match process_inner(core, request_json) {
        Ok(value) => value.to_string(),
        Err(message) => json!({ "error": message }).to_string(),
    }
}

fn process_inner(core: &WalletCore, request_json: &str) -> Result<Value, String> {
    let body: Value =
        serde_json::from_str(request_json).map_err(|e| format!("bad JSON request: {e}"))?;
    let action = body
        .get("action")
        .and_then(|a| a.as_str())
        .ok_or("missing 'action'")?
        .to_string();

    match action.as_str() {
        "identities" => {
            let identities = core.wallet.list().map_err(|e| e.to_string())?;
            let items: Vec<Value> = identities
                .iter()
                .map(|id| {
                    json!({
                        "name": id.name,
                        "ed_public": id.ed_public,
                        "pq_alg": "mldsa65",
                        "pq_public_prefix": &id.pq_public[..16.min(id.pq_public.len())],
                        "seal_public": id.seal_public,
                        "created_at_ms": id.created_at_ms,
                    })
                })
                .collect();
            Ok(json!({ "identities": items }))
        }
        "create" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            if passphrase.chars().count() < 8 {
                return Err("passphrase must be at least 8 characters".into());
            }
            let public = core.wallet.create(&name, &passphrase)?;
            Ok(json!({
                "ok": true,
                "identity": {
                    "name": public.name,
                    "ed_public": public.ed_public,
                    "pq_alg": "mldsa65",
                    "pq_public_prefix": &public.pq_public[..16.min(public.pq_public.len())],
                    "seal_public": public.seal_public,
                },
            }))
        }
        "party-sign" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let role = str_field(&body, "role")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let mut document = as_signed_document(&body)?;
            identity.sign_document(&mut document, &role)?;
            Ok(json!({
                "ok": true,
                "signed_by": identity.public.ed_public,
                "role": role,
                "document": document,
            }))
        }
        "seal" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let mut document = body
                .get("document")
                .cloned()
                .ok_or("missing 'document'")?;
            let fields = string_list(&body, "fields");
            let mut readers = string_list(&body, "to");
            for field in string_list(&body, "to_fields") {
                match document.get(&field) {
                    Some(Value::String(key)) => readers.push(key.clone()),
                    Some(Value::Array(items)) => {
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
            Ok(json!({
                "ok": true,
                "sealed": sealed,
                "readers": readers.len(),
                "document": document,
            }))
        }
        "open" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let mut document = body
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
            Ok(json!({
                "ok": true,
                "opened": opened,
                "skipped": skipped,
                "document": document,
            }))
        }
        // Deferred delivery: ciphertext now, the key half only at release.
        "seal-deferred" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let mut document = body
                .get("document")
                .cloned()
                .ok_or("missing 'document'")?;
            let fields = string_list(&body, "fields");
            let mut holders = string_list(&body, "to");
            for field in string_list(&body, "to_fields") {
                match document.get(&field) {
                    Some(Value::String(key)) => holders.push(key.clone()),
                    Some(Value::Array(items)) => {
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
            let releases =
                identity.seal_deferred_fields(&mut document, &fields, &holders[0])?;
            let secrets: serde_json::Map<String, Value> = releases
                .iter()
                .map(|(field, secret)| (field.clone(), json!(hex::encode(secret))))
                .collect();
            Ok(json!({
                "ok": true,
                "sealed": releases.len(),
                "holder": holders[0],
                "document": document,
                "releases": secrets,
            }))
        }
        "release-deferred" => {
            let field = str_field(&body, "field")?;
            let document = body.get("document").cloned().ok_or("missing 'document'")?;
            let field_value = document
                .get(&field)
                .cloned()
                .ok_or_else(|| format!("document has no field '{field}'"))?;
            let deferred: DeferredField = serde_json::from_value(field_value)
                .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
            let release = body.get("release").cloned().ok_or("missing 'release'")?;
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
            Ok(json!({ "ok": true, "field": field, "share": share }))
        }
        "open-deferred" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let field = str_field(&body, "field")?;
            let document = body.get("document").cloned().ok_or("missing 'document'")?;
            let field_value = document
                .get(&field)
                .cloned()
                .ok_or_else(|| format!("document has no field '{field}'"))?;
            let deferred: DeferredField = serde_json::from_value(field_value)
                .map_err(|e| format!("'{field}' is not a deferred-delivery field: {e}"))?;
            let release = body.get("release").cloned().ok_or("missing 'release'")?;
            let share = datu_wallet::SealedShare::find(&release).ok_or(
                "release carries no share object (expected a 'datu-share-v2' object)",
            )?;
            let plaintext = datu_wallet::open_deferred(
                &deferred,
                &share,
                &identity.public.seal_public,
                &identity.seal,
            )?;
            let value: Value = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("decrypted field is not valid JSON: {e}"))?;
            Ok(json!({ "ok": true, "field": field, "value": value }))
        }
        "export" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let backup_passphrase = str_field(&body, "backup_passphrase")?;
            load_guarded(core, &name, &passphrase)?;
            let backup = core
                .wallet
                .export_identity(&name, &passphrase, &backup_passphrase)?;
            Ok(json!({ "ok": true, "backup": backup }))
        }
        "import" => {
            let backup: IdentityBackup = serde_json::from_value(
                body.get("backup").cloned().ok_or("missing 'backup'")?,
            )
            .map_err(|e| format!("not a datu identity backup: {e}"))?;
            let passphrase = str_field(&body, "passphrase")?;
            let rename = body
                .get("rename")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string);
            let public = core
                .wallet
                .import_identity(&backup, &passphrase, rename.as_deref())?;
            Ok(json!({
                "ok": true,
                "identity": {
                    "name": public.name,
                    "ed_public": public.ed_public,
                    "pq_alg": "mldsa65",
                    "pq_public_prefix": &public.pq_public[..16.min(public.pq_public.len())],
                    "seal_public": public.seal_public,
                },
                "note": "imported identity unlocks with the backup passphrase",
            }))
        }
        "verify-entry" => {
            let entry_value = body.get("entry").cloned().ok_or("missing 'entry'")?;
            let entry = wire::entry_from_submission(&entry_value)?;
            entry
                .verify()
                .map_err(|e| format!("signature verification failed: {e}"))?;
            let id = entry.id().map_err(|e| e.to_string())?;
            let parties: Vec<Value> =
                SignedDocument::from_payload(&entry.body.payload)
                    .and_then(|doc| doc.verify().ok())
                    .map(|verified| {
                        verified
                            .iter()
                            .map(|(role, key)| json!({"role": role, "key": key}))
                            .collect()
                    })
                    .unwrap_or_default();
            Ok(json!({
                "ok": true,
                "id": hex_encode(id),
                "author": entry.body.author,
                "namespace": entry.body.namespace,
                "seq": entry.body.seq,
                "timestamp_ms": entry.body.timestamp_ms,
                "parties": parties,
                "note": "verified by your wallet - the serving node was not trusted",
            }))
        }
        "sign-entry" => {
            let name = str_field(&body, "name")?;
            let passphrase = str_field(&body, "passphrase")?;
            let identity = load_guarded(core, &name, &passphrase)?;
            let request: SignRequest = serde_json::from_value(
                body.get("request").cloned().ok_or("missing 'request'")?,
            )
            .map_err(|e| format!("bad sign request: {e}"))?;
            let entry = wire::entry_from_sign_request(&identity, &request)?;
            let id = entry.id().map_err(|e| e.to_string())?;
            let entry_json = wire::entry_full_json(&entry)?;
            Ok(json!({ "ok": true, "id": hex_encode(id), "entry": entry_json }))
        }
        other => Err(format!(
            "unknown action '{other}' - expected identities, create, party-sign, seal, open, seal-deferred, release-deferred, open-deferred, export, import, sign-entry, verify-entry"
        )),
    }
}

fn hex_encode(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Same throttle as the desktop bridge: 5 wrong passphrases per identity
/// lock it for 15 s. The wallet core is in-process, so this is the only
/// brute-force brake a hostile UI thread faces.
fn load_guarded(core: &WalletCore, name: &str, passphrase: &str) -> Result<LoadedIdentity, String> {
    {
        let map = core
            .failures
            .lock()
            .map_err(|_| "lock poisoned".to_string())?;
        if let Some((count, until)) = map.get(name).copied() {
            let now = now_ms();
            if count >= MAX_PASSPHRASE_FAILURES && now < until {
                return Err(format!(
                    "too many wrong passphrases for '{name}', retry in {}s",
                    (until - now) / 1000 + 1
                ));
            }
        }
    }
    match core.wallet.load(name, passphrase) {
        Ok(identity) => {
            if let Ok(mut map) = core.failures.lock() {
                map.remove(name);
            }
            Ok(identity)
        }
        Err(e) => {
            if let Ok(mut map) = core.failures.lock() {
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

fn str_field(body: &Value, name: &str) -> Result<String, String> {
    body.get(name)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing '{name}'"))
}

fn string_list(body: &Value, name: &str) -> Vec<String> {
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

/// Either an already party-signed document, or a bare object wrapped with
/// the request's `kind`.
fn as_signed_document(body: &Value) -> Result<SignedDocument, String> {
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

// ---- C ABI -----------------------------------------------------------------

fn error_string(message: &str) -> *mut c_char {
    // Errors are returned as freeable JSON (not null) so the caller always
    // owns one uniform `datu_string_free`-able pointer.
    let text = json!({ "error": message }).to_string();
    match CString::new(text) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Open a wallet core bound to `data_dir` (created if missing). Returns null
/// on a non-UTF-8 path; the keystore itself is created lazily.
#[no_mangle]
pub unsafe extern "C" fn datu_wallet_open(data_dir: *const c_char) -> *mut WalletCore {
    if data_dir.is_null() {
        return std::ptr::null_mut();
    }
    let dir = match CStr::from_ptr(data_dir).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(WalletCore::new(PathBuf::from(dir))))
}

/// Run one JSON request; the returned string is UTF-8 JSON the caller must
/// free with `datu_string_free`. Never returns null for a valid handle.
#[no_mangle]
pub unsafe extern "C" fn datu_wallet_request(
    core: *mut WalletCore,
    request: *const c_char,
) -> *mut c_char {
    if core.is_null() || request.is_null() {
        return error_string("null handle or request");
    }
    let core = &*core;
    let json = match CStr::from_ptr(request).to_str() {
        Ok(s) => s,
        Err(_) => return error_string("request is not valid UTF-8"),
    };
    let out = run_on_signer_thread(core, json);
    match CString::new(out) {
        Ok(c) => c.into_raw(),
        Err(_) => error_string("response is not valid UTF-8"),
    }
}

/// Do the actual work on a thread with a guaranteed-large stack (see
/// FFI_STACK_BYTES); a panic in the wallet is contained and reported as
/// JSON instead of unwinding across the C boundary.
fn run_on_signer_thread(core: &WalletCore, request_json: &str) -> String {
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .stack_size(FFI_STACK_BYTES)
            .spawn_scoped(scope, || process(core, request_json));
        match spawned {
            Ok(handle) => match handle.join() {
                Ok(text) => text,
                Err(_) => json!({ "error": "wallet core thread panicked" }).to_string(),
            },
            Err(e) => json!({ "error": format!("cannot spawn signer thread: {e}") }).to_string(),
        }
    })
}

/// Close a core opened with `datu_wallet_open`. Null is ignored.
#[no_mangle]
pub unsafe extern "C" fn datu_wallet_close(core: *mut WalletCore) {
    if !core.is_null() {
        drop(Box::from_raw(core));
    }
}

/// Free a string returned by `datu_wallet_request`. Null is ignored.
#[no_mangle]
pub unsafe extern "C" fn datu_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
