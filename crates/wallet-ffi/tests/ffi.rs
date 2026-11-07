//! End-to-end tests for the FFI wallet core: same grammar as the desktop
//! bridge, exercised through the public `process` entry point and the raw
//! C ABI itself.

use datu_wallet_ffi::{self as ffi, WalletCore};
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn request(core: &WalletCore, body: Value) -> Value {
    let out = ffi::process(core, &body.to_string());
    serde_json::from_str(&out).expect("response is JSON")
}

fn temp_core() -> (WalletCore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    (WalletCore::new(dir.path().to_path_buf()), dir)
}

#[test]
fn create_and_list_identities() {
    let (core, _dir) = temp_core();
    let made = request(
        &core,
        json!({"action": "create", "name": "amina", "passphrase": "correct horse battery"}),
    );
    assert_eq!(made["ok"], json!(true), "create failed: {made}");
    assert!(made["identity"]["ed_public"].as_str().unwrap().len() == 64);
    assert_eq!(made["identity"]["pq_alg"], "mldsa65");

    let listed = request(&core, json!({"action": "identities"}));
    let items = listed["identities"].as_array().expect("identities array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "amina");
    assert_eq!(items[0]["ed_public"], made["identity"]["ed_public"]);
    assert!(items[0]["pq_public_prefix"].as_str().unwrap().len() == 16);
    assert_eq!(items[0]["seal_public"], made["identity"]["seal_public"]);
}

#[test]
fn short_passphrase_is_rejected() {
    let (core, _dir) = temp_core();
    let out = request(&core, json!({"action": "create", "name": "x", "passphrase": "short"}));
    assert!(out["error"].as_str().unwrap().contains("at least 8 characters"));
}

#[test]
fn wrong_passphrase_is_an_error_and_throttles() {
    let (core, _dir) = temp_core();
    request(
        &core,
        json!({"action": "create", "name": "amina", "passphrase": "correct horse battery"}),
    );
    for i in 0..5 {
        let out = request(
            &core,
            json!({"action": "party-sign", "name": "amina", "passphrase": "wrong passphrase", "role": "holder", "kind": "land.title.application", "document": {"parcel": "pk-7"}}),
        );
        assert!(out["error"].is_string(), "attempt {i} should fail: {out}");
        assert!(!out["error"].as_str().unwrap().contains("too many"), "attempt {i} must not be locked out yet");
    }
    // Sixth attempt - even with the RIGHT passphrase - is locked out.
    let out = request(
        &core,
        json!({"action": "party-sign", "name": "amina", "passphrase": "correct horse battery", "role": "holder", "kind": "land.title.application", "document": {"parcel": "pk-7"}}),
    );
    let err = out["error"].as_str().expect("lockout error");
    assert!(err.contains("too many wrong passphrases"), "expected lockout, got: {err}");
}

#[test]
fn party_sign_and_verify() {
    let (core, _dir) = temp_core();
    let made = request(
        &core,
        json!({"action": "create", "name": "holder", "passphrase": "correct horse battery"}),
    );
    let signed = request(
        &core,
        json!({"action": "party-sign", "name": "holder", "passphrase": "correct horse battery", "role": "holder", "kind": "land.title.application", "document": {"parcel": "pk-7", "holder_key": made["identity"]["ed_public"]}}),
    );
    assert_eq!(signed["ok"], json!(true), "party-sign failed: {signed}");
    assert_eq!(signed["role"], "holder");
    let document = &signed["document"];
    assert_eq!(document["kind"], "land.title.application");
    let parties = document["parties"].as_array().expect("parties");
    assert_eq!(parties.len(), 1);
    assert_eq!(parties[0]["role"], "holder");
    assert!(parties[0]["pq_signature"].is_string(), "consent must be hybrid-signed");

    // The signed document must verify with the ledger's own verifier.
    let doc: datu_core::parties::SignedDocument =
        serde_json::from_value(document.clone()).expect("deserializes as SignedDocument");
    let verified = doc.verify().expect("signature verifies");
    assert_eq!(verified, vec![("holder".to_string(), made["identity"]["ed_public"].as_str().unwrap().to_string())]);
}

#[test]
fn seal_and_open_roundtrip() {
    let (core, _dir) = temp_core();
    let made = request(
        &core,
        json!({"action": "create", "name": "reader", "passphrase": "correct horse battery"}),
    );
    let seal_key = made["identity"]["seal_public"].as_str().unwrap();
    let sealed = request(
        &core,
        json!({"action": "seal", "name": "reader", "passphrase": "correct horse battery", "document": {"parcel": "pk-7", "holder_name": "Amina Yusuf", "birth_date": "1990-04-12"}, "fields": ["holder_name", "birth_date"], "to": [seal_key]}),
    );
    assert_eq!(sealed["ok"], json!(true), "seal failed: {sealed}");
    assert_eq!(sealed["sealed"], json!(2));
    assert_eq!(sealed["readers"], json!(1));
    assert!(sealed["document"]["holder_name"].is_object(), "field must be replaced by a sealed object");
    assert_eq!(sealed["document"]["parcel"], "pk-7", "unlisted field stays public");

    let opened = request(
        &core,
        json!({"action": "open", "name": "reader", "passphrase": "correct horse battery", "document": sealed["document"].clone()}),
    );
    assert_eq!(opened["ok"], json!(true), "open failed: {opened}");
    assert_eq!(opened["opened"], json!(2));
    assert_eq!(opened["document"]["holder_name"], "Amina Yusuf");
    assert_eq!(opened["document"]["birth_date"], "1990-04-12");
}

#[test]
fn sign_entry_produces_a_node_submittable_envelope() {
    let (core, _dir) = temp_core();
    let made = request(
        &core,
        json!({"action": "create", "name": "author", "passphrase": "correct horse battery"}),
    );
    let signed = request(
        &core,
        json!({"action": "sign-entry", "name": "author", "passphrase": "correct horse battery", "request": {"namespace": "test.ffi", "seq": 0, "payload_json": {"hello": "ffi"}}}),
    );
    assert_eq!(signed["ok"], json!(true), "sign-entry failed: {signed}");
    assert!(signed["id"].as_str().unwrap().len() == 64);
    assert_eq!(signed["entry"]["author"], made["identity"]["ed_public"]);
    assert_eq!(signed["entry"]["namespace"], "test.ffi");

    // The envelope must survive the node's ingestion path unchanged, and
    // verify-entry must accept what sign-entry produced.
    let verified = request(
        &core,
        json!({"action": "verify-entry", "entry": signed["entry"].clone()}),
    );
    assert_eq!(verified["ok"], json!(true), "verify-entry failed: {verified}");
    assert_eq!(verified["id"], signed["id"]);
    assert_eq!(verified["namespace"], "test.ffi");

    // Chained entries (seq > 0) must carry prev - same per-author chain rule
    // the ledger enforces.
    let chained = request(
        &core,
        json!({"action": "sign-entry", "name": "author", "passphrase": "correct horse battery", "request": {"namespace": "test.ffi", "seq": 1, "prev": signed["id"], "payload_json": {"hello": "again"}}}),
    );
    assert_eq!(chained["ok"], json!(true), "chained sign failed: {chained}");
    assert_eq!(chained["entry"]["prev"], signed["id"]);
    let verified = request(
        &core,
        json!({"action": "verify-entry", "entry": chained["entry"].clone()}),
    );
    assert_eq!(verified["ok"], json!(true), "chained verify failed: {verified}");
}

#[test]
fn export_import_roundtrip_across_cores() {
    let (core_a, _dir_a) = temp_core();
    request(
        &core_a,
        json!({"action": "create", "name": "mover", "passphrase": "original passphrase"}),
    );
    let exported = request(
        &core_a,
        json!({"action": "export", "name": "mover", "passphrase": "original passphrase", "backup_passphrase": "travel passphrase"}),
    );
    assert_eq!(exported["ok"], json!(true), "export failed: {exported}");
    assert_eq!(exported["backup"]["format"], "datu-identity-backup");

    let (core_b, _dir_b) = temp_core();
    let imported = request(
        &core_b,
        json!({"action": "import", "backup": exported["backup"].clone(), "passphrase": "travel passphrase"}),
    );
    assert_eq!(imported["ok"], json!(true), "import failed: {imported}");
    assert_eq!(imported["identity"]["name"], "mover");

    // The imported identity signs under the backup passphrase - proof the
    // keys traveled, not just the metadata.
    let signed = request(
        &core_b,
        json!({"action": "sign-entry", "name": "mover", "passphrase": "travel passphrase", "request": {"namespace": "test.move", "seq": 1, "payload_json": {"moved": true}}}),
    );
    assert_eq!(signed["ok"], json!(true), "imported identity cannot sign: {signed}");
    assert_eq!(
        signed["entry"]["author"], imported["identity"]["ed_public"],
        "imported keys must match the backup metadata"
    );
}

#[test]
fn unknown_action_and_missing_fields_are_json_errors() {
    let (core, _dir) = temp_core();
    let out = request(&core, json!({"action": "nope"}));
    assert!(out["error"].as_str().unwrap().contains("unknown action 'nope'"));
    let out = request(&core, json!({"action": "create"}));
    assert_eq!(out["error"], "missing 'name'");
    let out = ffi::process(&core, "not json");
    assert!(out.contains("\"error\""), "bad JSON must be a JSON error: {out}");
}

#[test]
fn raw_c_abi_smoke() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
    let core = unsafe { ffi::datu_wallet_open(c_dir.as_ptr()) };
    assert!(!core.is_null(), "open must return a handle");

    let ask = |core: *mut ffi::WalletCore, body: &str| -> String {
        let c_body = CString::new(body).unwrap();
        let raw = unsafe { ffi::datu_wallet_request(core, c_body.as_ptr()) };
        assert!(!raw.is_null(), "request must return a string");
        let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        unsafe { ffi::datu_string_free(raw) };
        text
    };

    let made = ask(core, r#"{"action":"create","name":"ffi","passphrase":"correct horse battery"}"#);
    assert!(made.contains("\"ok\":true"), "create via ABI failed: {made}");
    let listed = ask(core, r#"{"action":"identities"}"#);
    assert!(listed.contains("\"name\":\"ffi\""), "list via ABI failed: {listed}");

    unsafe { ffi::datu_wallet_close(core) };

    // Null arguments must not crash, and still answer JSON.
    let raw: *mut c_char = unsafe { ffi::datu_wallet_request(std::ptr::null_mut(), std::ptr::null()) };
    assert!(!raw.is_null());
    let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    unsafe { ffi::datu_string_free(raw) };
    assert!(text.contains("null handle"), "unexpected: {text}");
}
