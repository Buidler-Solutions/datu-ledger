use datu_core::parties::SignedDocument;
use datu_core::pq;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn holder_doc() -> SignedDocument {
    SignedDocument::new(
        "land.title.application",
        json!({
            "parcel": "TIT-0042-17",
            "holder_name": "Amina Yusuf",
            "area_m2": 612
        }),
    )
}

#[test]
fn two_party_sign_and_verify() {
    let mut doc = holder_doc();
    let registrar = SigningKey::from_bytes(&[7u8; 32]);
    let (holder_ed, holder_pq) = (SigningKey::from_bytes(&[9u8; 32]), pq::keypair().unwrap());

    doc.sign("registrar", &registrar, None).unwrap();
    doc.sign("holder", &holder_ed, Some(&holder_pq.1)).unwrap();

    let verified = doc.verify().unwrap();
    assert_eq!(verified.len(), 2);
    assert!(verified.iter().any(|(r, _)| r == "holder"));
    assert!(verified.iter().any(|(r, _)| r == "registrar"));
    assert!(doc.has_verified_role("holder"));
    assert!(!doc.has_verified_role("surveyor"));
}

#[test]
fn payload_roundtrip() {
    let mut doc = holder_doc();
    let holder = SigningKey::from_bytes(&[3u8; 32]);
    doc.sign("holder", &holder, None).unwrap();
    let bytes = doc.payload_bytes().unwrap();
    let parsed = SignedDocument::from_payload(&bytes).unwrap();
    assert_eq!(parsed, doc);
    assert!(parsed.has_verified_role("holder"));
    assert!(SignedDocument::from_payload(b"not json").is_none());
}

#[test]
fn tampered_document_fails() {
    let mut doc = holder_doc();
    let holder = SigningKey::from_bytes(&[5u8; 32]);
    doc.sign("holder", &holder, None).unwrap();
    // Mutate the document after signing.
    doc.doc["parcel"] = json!("TIT-9999-00");
    assert!(doc.verify().is_err());
    assert!(!doc.has_verified_role("holder"));
}

#[test]
fn wrong_key_fails() {
    let mut doc = holder_doc();
    let signer = SigningKey::from_bytes(&[11u8; 32]);
    doc.sign("holder", &signer, None).unwrap();
    // Swap in a different party key: the digest binds the key, so the
    // signature must stop verifying.
    doc.parties[0].key = hex::encode([13u8; 32]);
    assert!(doc.verify().is_err());
}

#[test]
fn role_swap_fails() {
    let mut doc = holder_doc();
    let signer = SigningKey::from_bytes(&[15u8; 32]);
    doc.sign("holder", &signer, None).unwrap();
    doc.parties[0].role = "registrar".into();
    assert!(doc.verify().is_err());
    assert!(!doc.has_verified_role("registrar"));
}
