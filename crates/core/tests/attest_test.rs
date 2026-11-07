use datu_core::attest::{
    attestations_for, cosigners_for, parse_attestation, AttestationDoc, CosignDoc, NS_ATTEST,
    NS_COSIGN,
};
use datu_core::pq::PqPrivateKey;
use datu_core::{Entry, EntryBody};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

struct Keys {
    ed: SigningKey,
    pq: PqPrivateKey,
}

fn keys() -> Keys {
    Keys {
        ed: SigningKey::generate(&mut OsRng),
        pq: datu_core::pq::keypair().unwrap().1,
    }
}

fn signed(keys: &Keys, namespace: &str, seq: u64, refs: Vec<[u8; 32]>, payload: Vec<u8>) -> Entry {
    let body = EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: namespace.into(),
        seq,
        prev: None,
        refs,
        timestamp_ms: 1,
        payload,
    };
    Entry::sign(body, &keys.ed, &keys.pq).unwrap()
}

fn attest_entry(keys: &Keys, seq: u64, subject: &str, label: Option<&str>) -> Entry {
    let doc = AttestationDoc {
        subject: subject.to_string(),
        label: label.map(|s| s.to_string()),
        claims: serde_json::json!({"legal_name": "Acme Ltd", "role": "bidder"}),
    };
    signed(keys, NS_ATTEST, seq, vec![], doc.payload_bytes().unwrap())
}

#[test]
fn attestation_roundtrip_and_lookup() {
    let ministry = keys();
    let other = keys();
    let subject = hex::encode(other.ed.verifying_key().as_bytes());

    let a1 = attest_entry(&ministry, 0, &subject, Some("Acme Ltd"));
    let a1_id = a1.id().unwrap();
    let unrelated = attest_entry(&other, 0, &"ff".repeat(32), None);

    assert!(parse_attestation(&a1).is_some());
    assert!(parse_attestation(&unrelated).is_some());
    // A random signed entry is not an attestation.
    assert!(parse_attestation(&signed(&other, "general", 0, vec![], b"{}".to_vec())).is_none());

    let all = vec![&a1, &unrelated];
    let found = attestations_for(all.iter().copied(), &subject);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0.id().unwrap(), a1_id);
    assert_eq!(found[0].1.label.as_deref(), Some("Acme Ltd"));
    assert_eq!(found[0].1.claims["role"], "bidder");
}

#[test]
fn cosigners_count_distinct_authors_only() {
    let ministry = keys();
    let ngo = keys();
    let press = keys();
    let subject = hex::encode(press.ed.verifying_key().as_bytes());

    let attestation = attest_entry(&ministry, 0, &subject, None);
    let id = attestation.id().unwrap();
    let id_hex = hex::encode(id);

    let cosign = |k: &Keys, seq: u64| {
        let doc = CosignDoc {
            attestation: id_hex.clone(),
        };
        signed(
            k,
            NS_COSIGN,
            seq,
            vec![id],
            serde_json::to_vec(&doc).unwrap(),
        )
    };
    let c1 = cosign(&ngo, 0);
    let c2 = cosign(&press, 0);
    // Same author cosigning twice must not double-count.
    let c3 = cosign(&ngo, 1);
    // An entry that references the attestation but is not a cosign doc.
    let bystander = signed(&press, NS_COSIGN, 1, vec![id], b"{}".to_vec());

    let all = vec![&attestation, &c1, &c2, &c3, &bystander];
    let cosigners = cosigners_for(all.iter().copied(), &id);
    assert_eq!(cosigners.len(), 2, "one entry per distinct author");

    // Wrong id yields nothing.
    assert!(cosigners_for(all.iter().copied(), &[7u8; 32]).is_empty());
}
