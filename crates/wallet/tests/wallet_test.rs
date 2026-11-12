use base64::Engine;
use datu_core::{EntryBody, ENTRY_VERSION};
use datu_wallet::{LoadedIdentity, Wallet};
use serde_json::json;

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn keystore_create_load_roundtrip() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    let public = wallet.create("alice", "correct horse").unwrap();
    assert_eq!(public.name, "alice");
    assert_eq!(wallet.list().unwrap().len(), 1);

    let loaded = wallet.load("alice", "correct horse").unwrap();
    assert_eq!(loaded.public.ed_public, public.ed_public);

    assert!(wallet.load("alice", "wrong pass").is_err());
    assert!(wallet.load("nobody", "x").is_err());
    assert!(wallet.create("alice", "x").is_err(), "duplicate refused");
}

#[test]
fn signed_entry_from_wallet_verifies() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("alice", "pw").unwrap();
    let alice = wallet.load("alice", "pw").unwrap();

    let body = EntryBody {
        version: ENTRY_VERSION,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "gov.forms".into(),
        seq: 0,
        prev: None,
        refs: vec![],
        timestamp_ms: 1,
        payload: br#"{"form":"procurement-bid"}"#.to_vec(),
    };
    let entry = alice.sign_entry(body).unwrap();
    entry.verify().unwrap();
    assert_eq!(entry.body.author, alice.public.ed_public);
}

#[test]
fn seal_and_open_roundtrip() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("bidder", "pw1").unwrap();
    wallet.create("ministry", "pw2").unwrap();
    let bidder = wallet.load("bidder", "pw1").unwrap();
    let ministry = wallet.load("ministry", "pw2").unwrap();

    let mut doc = json!({
        "tender_id": "T-2026-041",
        "bidder_name": "Acme Corp",
        "bid_amount": 1250000,
        "tax_id": "12-3456789"
    });
    let sealed_count = bidder
        .seal_fields(
            &mut doc,
            &["bid_amount".to_string(), "tax_id".to_string()],
            std::slice::from_ref(&ministry.public.seal_public),
        )
        .unwrap();
    assert_eq!(sealed_count, 2);

    // Public fields remain readable; sealed fields carry only ciphertext + commitment.
    assert_eq!(doc["tender_id"], json!("T-2026-041"));
    assert!(doc["bid_amount"].is_object());
    assert!(doc["bid_amount"]["sealed"].is_string());

    // The wrong reader cannot decrypt (skipped, left sealed).
    let mut wrong_copy = doc.clone();
    let (opened, skipped) = bidder.open_fields(&mut wrong_copy).unwrap();
    assert_eq!(opened, 0);
    assert_eq!(skipped, 2);

    // The intended reader decrypts and gets exact original values.
    let mut reader_copy = doc.clone();
    let (opened, skipped) = ministry.open_fields(&mut reader_copy).unwrap();
    assert_eq!(opened, 2);
    assert_eq!(skipped, 0);
    assert_eq!(reader_copy["bid_amount"], json!(1250000));
    assert_eq!(reader_copy["tax_id"], json!("12-3456789"));
}

#[test]
fn sealed_field_tamper_detected() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("a", "p").unwrap();
    wallet.create("b", "p").unwrap();
    let a = wallet.load("a", "p").unwrap();
    let b = wallet.load("b", "p").unwrap();

    let mut doc = json!({ "secret": "attack at dawn" });
    a.seal_fields(
        &mut doc,
        &["secret".to_string()],
        std::slice::from_ref(&b.public.seal_public),
    )
    .unwrap();

    // Flip a byte in the first recipient's ciphertext.
    let ct_b64 = doc["secret"]["recipients"][0]["ct"]
        .as_str()
        .unwrap()
        .to_string();
    let mut ct = base64::engine::general_purpose::STANDARD
        .decode(&ct_b64)
        .unwrap();
    let len = ct.len();
    ct[len - 1] ^= 0xFF;
    doc["secret"]["recipients"][0]["ct"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&ct));
    assert!(b.open_fields(&mut doc).is_err() || doc["secret"]["sealed"].is_string());
}

#[test]
fn wallet_helper_types_compile() {
    // Ensures the public API surface stays exported for the CLI.
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    let _public = wallet.create("x", "p").unwrap();
    let loaded: LoadedIdentity = wallet.load("x", "p").unwrap();
    let _ = &loaded.seal;
}

#[test]
fn multi_reader_sealing() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("writer", "p").unwrap();
    wallet.create("ministry", "p").unwrap();
    wallet.create("auditor", "p").unwrap();
    wallet.create("outsider", "p").unwrap();
    let writer = wallet.load("writer", "p").unwrap();
    let ministry = wallet.load("ministry", "p").unwrap();
    let auditor = wallet.load("auditor", "p").unwrap();
    let outsider = wallet.load("outsider", "p").unwrap();

    let mut doc = json!({ "tender": "T-1", "amount": 42, "note": "public" });
    let sealed = writer
        .seal_fields(
            &mut doc,
            &["amount".to_string()],
            &[
                ministry.public.seal_public.clone(),
                auditor.public.seal_public.clone(),
            ],
        )
        .unwrap();
    assert_eq!(sealed, 1);
    assert_eq!(doc["amount"]["recipients"].as_array().unwrap().len(), 2);
    // One shared commitment at field level, not per recipient.
    assert!(doc["amount"]["commitment"].is_string());
    assert!(doc["amount"]["recipients"][0].get("commitment").is_none());

    for reader in [ministry, auditor] {
        let mut copy = doc.clone();
        let (opened, skipped) = reader.open_fields(&mut copy).unwrap();
        assert_eq!((opened, skipped), (1, 0));
        assert_eq!(copy["amount"], json!(42));
    }
    let mut copy = doc.clone();
    let (opened, skipped) = outsider.open_fields(&mut copy).unwrap();
    assert_eq!((opened, skipped), (0, 1));
    assert!(copy["amount"]["sealed"].is_string());
}

#[test]
fn export_import_moves_identity_to_another_wallet() {
    let source = Wallet::open(tmpdir().path().to_owned().as_path());
    let dir_a = tmpdir();
    let dir_b = tmpdir();
    let a = Wallet::open(dir_a.path());
    let created = a.create("alice", "alice-pass").unwrap();

    let backup = a
        .export_identity("alice", "alice-pass", "backup-pass")
        .unwrap();
    assert_eq!(backup.format, "datu-identity-backup");
    assert_eq!(backup.ed_public, created.ed_public);

    // Import on the second device: it unlocks with the *backup* passphrase.
    let b = Wallet::open(dir_b.path());
    let imported = b.import_identity(&backup, "backup-pass", None).unwrap();
    assert_eq!(imported.ed_public, created.ed_public);
    assert_eq!(imported.seal_public, created.seal_public);
    let loaded = b.load("alice", "backup-pass").unwrap();
    assert_eq!(loaded.public.name, "alice");

    // Same keys => same signatures over the same bytes.
    let body = EntryBody {
        version: ENTRY_VERSION,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "gov.records".into(),
        seq: 0,
        prev: None,
        refs: vec![],
        timestamp_ms: 1,
        payload: b"same bytes".to_vec(),
    };
    let from_a = a
        .load("alice", "alice-pass")
        .unwrap()
        .sign_entry(body.clone())
        .unwrap();
    let from_b = b
        .load("alice", "backup-pass")
        .unwrap()
        .sign_entry(body)
        .unwrap();
    assert_eq!(from_a.signature, from_b.signature);

    let _ = source;
}

#[test]
fn backup_needs_both_the_identity_and_backup_passphrases() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("bob", "bob-pass-1").unwrap();

    // Wrong identity passphrase: no backup is produced.
    assert!(wallet
        .export_identity("bob", "wrong-pass", "backup-pass")
        .is_err());

    let backup = wallet
        .export_identity("bob", "bob-pass-1", "backup-pass")
        .unwrap();

    // Wrong backup passphrase: import refuses.
    let target = tmpdir();
    let other = Wallet::open(target.path());
    assert!(other
        .import_identity(&backup, "not-the-pass", None)
        .is_err());

    // Tampered public metadata no longer matches the restored keys.
    let mut tampered = backup.clone();
    tampered.ed_public = "00".repeat(32);
    assert!(other
        .import_identity(&tampered, "backup-pass", None)
        .is_err());

    // The clean import works, a second identical one collides, rename fixes it.
    let first = other.import_identity(&backup, "backup-pass", None).unwrap();
    assert_eq!(first.name, "bob");
    assert!(other.import_identity(&backup, "backup-pass", None).is_err());
    let renamed = other
        .import_identity(&backup, "backup-pass", Some("bob-2"))
        .unwrap();
    assert_eq!(renamed.name, "bob-2");
    assert_eq!(renamed.ed_public, backup.ed_public);
}

#[test]
fn deferred_delivery_withholds_the_key_until_release() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("issuer", "pw1").unwrap();
    wallet.create("holder", "pw2").unwrap();
    wallet.create("outsider", "pw3").unwrap();
    let issuer = wallet.load("issuer", "pw1").unwrap();
    let holder = wallet.load("holder", "pw2").unwrap();
    let outsider = wallet.load("outsider", "pw3").unwrap();

    let mut doc = json!({
        "cert_id": "C-9",
        "owner_name": "Amina Yusuf",
        "issued": true,
    });
    let releases = issuer
        .seal_deferred_fields(
            &mut doc,
            &["owner_name".to_string()],
            &holder.public.seal_public,
        )
        .unwrap();
    assert_eq!(releases.len(), 1);

    // On-ledger shape: ciphertext from day one, the nominated holder, and
    // only the harmless public share of the content key.
    let field: datu_wallet::DeferredField =
        serde_json::from_value(doc["owner_name"].clone()).unwrap();
    assert_eq!(field.sealed, datu_wallet::DEFERRED_MARK);
    assert_eq!(field.release_to, holder.public.seal_public);
    assert!(
        datu_core::contract::is_sealed(&doc["owner_name"]),
        "seal demands accept the deferred mark"
    );

    // Before the release, opening finds nothing to open: the field is
    // skipped, exactly like a sealed field for another reader.
    let (opened, skipped) = holder.open_fields(&mut doc.clone()).unwrap();
    assert_eq!((opened, skipped), (0, 1));

    // The release publishes the other half, sealed to the nominated holder.
    let share = datu_wallet::attach_release(&field, &releases[0].1).unwrap();

    // Even holding the release object, the wrong identity stays locked out.
    assert!(datu_wallet::open_deferred(
        &field,
        &share,
        &outsider.public.seal_public,
        &outsider.seal
    )
    .is_err());

    // The holder opens it, and the reveal matches the signed commitment.
    let plaintext =
        datu_wallet::open_deferred(&field, &share, &holder.public.seal_public, &holder.seal)
            .unwrap();
    let restored: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(restored, json!("Amina Yusuf"));

    // Tampering with the public share breaks the key recomposition.
    let mut tampered = field.clone();
    tampered.share = "00".repeat(32);
    assert!(datu_wallet::open_deferred(
        &tampered,
        &share,
        &holder.public.seal_public,
        &holder.seal
    )
    .is_err());
}

#[test]
fn release_share_finder_accepts_bare_and_nested_objects() {
    let share = json!({
        "sealed": "datu-share-v2",
        "recipient": {
            "to": "ab".repeat(32),
            "eph": "cd".repeat(32),
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "AAAA",
        },
    });

    // A bare share object.
    assert!(datu_wallet::SealedShare::find(&share).is_some());
    // Any document containing one (e.g. a release entry payload).
    let nested = json!({"doc": {"released_key": share}, "kind": "datu.cert.release"});
    assert!(datu_wallet::SealedShare::find(&nested).is_some());
    // Nothing to find.
    assert!(datu_wallet::SealedShare::find(&json!({"sealed": "datu-sealed-v2"})).is_none());
}

#[test]
fn a_lost_secrets_file_is_recoverable_by_the_issuer() {
    let dir = tmpdir();
    let wallet = Wallet::open(dir.path());
    wallet.create("issuer", "pw1").unwrap();
    wallet.create("holder", "pw2").unwrap();
    let issuer = wallet.load("issuer", "pw1").unwrap();
    let holder = wallet.load("holder", "pw2").unwrap();

    let mut doc = json!({ "owner_name": "Amina" });
    // The returned secrets are deliberately ignored: the file is "lost".
    let _releases = issuer
        .seal_deferred_fields(
            &mut doc,
            &["owner_name".to_string()],
            &holder.public.seal_public,
        )
        .unwrap();
    let field: datu_wallet::DeferredField =
        serde_json::from_value(doc["owner_name"].clone()).unwrap();
    assert!(field.recovery.is_some(), "custody copy rides in the field");

    // The issuer recovers the release half from its own sealed copy and the
    // deferred loop still closes.
    let secret =
        datu_wallet::recover_release_secret(&field, &issuer.public.seal_public, &issuer.seal)
            .unwrap();
    let share = datu_wallet::attach_release(&field, &secret).unwrap();
    let plaintext =
        datu_wallet::open_deferred(&field, &share, &holder.public.seal_public, &holder.seal)
            .unwrap();
    let restored: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(restored, json!("Amina"));

    // The holder cannot open the issuer's custody copy, and fields sealed
    // before custody copies existed say so instead of failing weirdly.
    assert!(
        datu_wallet::recover_release_secret(&field, &holder.public.seal_public, &holder.seal)
            .is_err()
    );
    let mut legacy = field.clone();
    legacy.recovery = None;
    let err =
        datu_wallet::recover_release_secret(&legacy, &issuer.public.seal_public, &issuer.seal)
            .unwrap_err();
    assert!(err.contains("no recovery copy"));
}
