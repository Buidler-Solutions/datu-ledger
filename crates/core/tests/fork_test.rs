use datu_core::fork::{analyze, KIND_CHAIN_BREAK, KIND_SAME_HEIGHT_FORK};
use datu_core::merkle::merkle_root;
use datu_core::pq::PqPrivateKey;
use datu_core::{Checkpoint, CheckpointBody};
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

fn cp(
    k: &Keys,
    height: u64,
    prev: Option<[u8; 32]>,
    root: [u8; 32],
    count: u64,
) -> Checkpoint {
    let body = CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: 1,
        entries_count: count,
        entry_ids_root: root,
    };
    Checkpoint::sign(body, &k.ed, &k.pq).unwrap()
}

fn honest_chain(k: &Keys, heights: u64) -> Vec<Checkpoint> {
    let mut out: Vec<Checkpoint> = Vec::new();
    for h in 0..heights {
        let prev = out.last().map(|c: &Checkpoint| c.id().unwrap());
        out.push(cp(k, h, prev, [h as u8 + 1; 32], h + 10));
    }
    out
}

#[test]
fn consistent_streams_have_no_evidence() {
    let a = keys();
    let b = keys();
    let sa = honest_chain(&a, 3);
    let sb = honest_chain(&b, 2);
    assert!(analyze(&sa, &sb).unwrap().is_empty());
    assert!(analyze(&sa, &sa).unwrap().is_empty());
}

#[test]
fn same_height_fork_across_streams_detected() {
    let authority = keys();
    // Both branches share height 0, then diverge at height 1.
    let honest = honest_chain(&authority, 2);
    let mut evil = vec![honest[0].clone()];
    evil.push(cp(
        &authority,
        1,
        Some(honest[0].id().unwrap()),
        [0xEE; 32], // different root = different history
        11,
    ));

    let evidence = analyze(&honest, &evil).unwrap();
    assert_eq!(evidence.len(), 1, "exactly one contradiction expected");
    assert_eq!(evidence[0].kind, KIND_SAME_HEIGHT_FORK);
    assert_eq!(evidence[0].height, 1);
    assert_eq!(evidence[0].checkpoints.len(), 2);
    // The evidence package must be independently verifiable.
    for cp in &evidence[0].checkpoints {
        cp.verify().unwrap();
    }
}

#[test]
fn internal_duplicate_detected() {
    let authority = keys();
    let mut stream = honest_chain(&authority, 2);
    stream.push(cp(&authority, 1, Some(stream[0].id().unwrap()), [9u8; 32], 99));
    let evidence = analyze(&stream, &[]).unwrap();
    assert!(evidence
        .iter()
        .any(|e| e.kind == KIND_SAME_HEIGHT_FORK && e.height == 1));
}

#[test]
fn chain_break_detected() {
    let authority = keys();
    let mut stream = honest_chain(&authority, 3);
    // Height 2 claims to follow height 1 but points elsewhere.
    stream[2] = cp(&authority, 2, Some([0xBA; 32]), stream[2].body.entry_ids_root, 3);
    let evidence = analyze(&stream, &[]).unwrap();
    assert!(evidence
        .iter()
        .any(|e| e.kind == KIND_CHAIN_BREAK && e.height == 2));
}

#[test]
fn invalid_signature_in_stream_rejected() {
    let authority = keys();
    let mut stream = honest_chain(&authority, 2);
    let len = stream[1].pq_signature.len();
    stream[1].pq_signature[len - 1] ^= 0xFF;
    assert!(analyze(&stream, &[]).is_err());
}

#[test]
fn merkle_root_separates_histories() {
    let ids_a = vec![[1u8; 32], [2u8; 32]];
    let ids_b = vec![[1u8; 32], [3u8; 32]];
    let a = keys();
    let b = keys();
    let ca = cp(&a, 0, None, merkle_root(&ids_a), 2);
    let cb = cp(&b, 0, None, merkle_root(&ids_b), 2);
    // Different signers seeing different sets is not a contradiction.
    assert!(analyze(&[ca], &[cb]).unwrap().is_empty());
}
