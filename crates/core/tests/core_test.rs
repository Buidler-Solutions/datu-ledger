use datu_core::checkpoint::Checkpoint;
use datu_core::feed::verify_feed_order;
use datu_core::merkle::merkle_root;
use datu_core::pq::PqPrivateKey;
use datu_core::{CheckpointBody, Entry, EntryBody};
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

fn body(seq: u64, prev: Option<[u8; 32]>) -> EntryBody {
    EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "test".into(),
        seq,
        prev,
        refs: vec![],
        timestamp_ms: 1,
        payload: b"hello".to_vec(),
    }
}

fn cp_body(height: u64, prev: Option<[u8; 32]>) -> CheckpointBody {
    CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: 1,
        entries_count: 1,
        entry_ids_root: [7u8; 32],
    }
}

#[test]
fn sign_verify_roundtrip() {
    let k = keys();
    let e = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    assert_eq!(e.body.author, hex::encode(k.ed.verifying_key().as_bytes()));
    assert_eq!(e.body.pq_alg, "mldsa65");
    assert_eq!(e.body.version, 1);
    e.verify().unwrap();
}

#[test]
fn tampered_payload_fails_and_changes_id() {
    let k = keys();
    let e = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    let id = e.id().unwrap();
    let mut tampered = e.clone();
    tampered.body.payload = b"evil".to_vec();
    assert!(tampered.verify().is_err(), "signature must not verify");
    assert_ne!(tampered.id().unwrap(), id, "id must change");
}

#[test]
fn tampered_timestamp_fails() {
    let k = keys();
    let e = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    let mut tampered = e.clone();
    tampered.body.timestamp_ms += 1;
    assert!(tampered.verify().is_err());
}

#[test]
fn tampered_pq_signature_fails() {
    let k = keys();
    let e = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    let mut tampered = e.clone();
    let len = tampered.pq_signature.len();
    tampered.pq_signature[len - 1] ^= 0xFF;
    assert!(
        tampered.verify().is_err(),
        "post-quantum signature must not verify"
    );
}

#[test]
fn pq_public_key_swap_fails() {
    let k = keys();
    let other = keys();
    let e = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    let mut forged = e.clone();
    forged.body.author_pq = Entry::sign(body(0, None), &other.ed, &other.pq)
        .unwrap()
        .body
        .author_pq;
    assert!(forged.verify().is_err());
}

#[test]
fn seq_zero_must_not_have_prev() {
    let k = keys();
    let mut b = body(0, Some([9u8; 32]));
    let e = Entry::sign(b.clone(), &k.ed, &k.pq).unwrap();
    assert!(e.verify().is_err());
    b.prev = None;
    assert!(Entry::sign(b, &k.ed, &k.pq).unwrap().verify().is_ok());
}

#[test]
fn seq_after_zero_must_have_prev() {
    let k = keys();
    let e = Entry::sign(body(1, None), &k.ed, &k.pq).unwrap();
    assert!(e.verify().is_err());
}

#[test]
fn bad_namespace_rejected() {
    let k = keys();
    let mut b = body(0, None);
    b.namespace = "Bad NS!".into();
    let e = Entry::sign(b, &k.ed, &k.pq).unwrap();
    assert!(e.verify().is_err());
}

#[test]
fn oversize_payload_rejected() {
    let k = keys();
    let mut b = body(0, None);
    b.payload = vec![0u8; 256 * 1024 + 1];
    let e = Entry::sign(b, &k.ed, &k.pq).unwrap();
    assert!(e.verify().is_err());
}

#[test]
fn feed_chain_verifies_and_detects_breaks() {
    let k = keys();
    let e0 = Entry::sign(body(0, None), &k.ed, &k.pq).unwrap();
    let e1 = Entry::sign(body(1, Some(e0.id().unwrap())), &k.ed, &k.pq).unwrap();
    let e2 = Entry::sign(body(2, Some(e1.id().unwrap())), &k.ed, &k.pq).unwrap();
    assert!(verify_feed_order(&[e0.clone(), e1.clone(), e2]).is_ok());

    let forged_prev = Entry::sign(body(1, Some([7u8; 32])), &k.ed, &k.pq).unwrap();
    assert!(verify_feed_order(&[e0, forged_prev]).is_err());

    let seq_gap = Entry::sign(body(3, None), &k.ed, &k.pq).unwrap();
    assert!(verify_feed_order(&[e1, seq_gap]).is_err());
}

#[test]
fn merkle_root_is_order_independent_and_set_sensitive() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    assert_eq!(merkle_root(&[]), merkle_root(&[]));
    assert_eq!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    assert_eq!(merkle_root(&[a]), merkle_root(&[a, a]));
    assert_ne!(merkle_root(&[a, b]), merkle_root(&[a, c]));
    assert_ne!(merkle_root(&[a, b]), merkle_root(&[a]));
}

#[test]
fn checkpoint_sign_verify_and_tamper() {
    let k = keys();
    let ids = vec![[1u8; 32], [2u8; 32]];
    let mut b = cp_body(0, None);
    b.entry_ids_root = Checkpoint::root_for(&ids);
    let cp = Checkpoint::sign(b, &k.ed, &k.pq).unwrap();
    cp.verify().unwrap();

    let mut tampered = cp.clone();
    tampered.body.entries_count = 99;
    assert!(tampered.verify().is_err());

    let mut tampered_pq = cp.clone();
    let len = tampered_pq.pq_signature.len();
    tampered_pq.pq_signature[len - 1] ^= 0xFF;
    assert!(tampered_pq.verify().is_err());

    let mut bad_height = cp_body(0, Some([5u8; 32]));
    bad_height.entry_ids_root = Checkpoint::root_for(&ids);
    assert!(
        Checkpoint::sign(bad_height, &k.ed, &k.pq)
            .unwrap()
            .verify()
            .is_err()
    );

    let mut orphan = cp_body(1, None);
    orphan.entry_ids_root = Checkpoint::root_for(&ids);
    assert!(
        Checkpoint::sign(orphan, &k.ed, &k.pq)
            .unwrap()
            .verify()
            .is_err()
    );
}

#[test]
fn checkpoint_chain() {
    let k = keys();
    let c0 = Checkpoint::sign(cp_body(0, None), &k.ed, &k.pq).unwrap();
    let c1 = Checkpoint::sign(cp_body(1, Some(c0.id().unwrap())), &k.ed, &k.pq).unwrap();
    c0.verify().unwrap();
    c1.verify().unwrap();
    let wrong = Checkpoint::sign(cp_body(1, Some([9u8; 32])), &k.ed, &k.pq).unwrap();
    wrong.verify().unwrap(); // self-consistent; store layer catches chain breaks
    assert_ne!(wrong.id().unwrap(), c1.id().unwrap());
}
