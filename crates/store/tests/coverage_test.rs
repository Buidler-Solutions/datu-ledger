//! Coverage proofs against historical checkpoints: the store is append-only
//! in insertion order, so a checkpoint's signed set is the id prefix that
//! existed when it was signed - proofs still work after the ledger grows.

use datu_core::checkpoint::CoverageProof;
use datu_core::pq::PqPrivateKey;
use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody, CHECKPOINT_VERSION};
use datu_store::Store;
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

fn feed(k: &Keys, n: u64) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for i in 0..n {
        let prev = out.last().map(|e: &Entry| e.id().unwrap());
        let body = EntryBody {
            version: datu_core::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "gov.records".into(),
            seq: i,
            prev,
            refs: vec![],
            timestamp_ms: 1,
            payload: format!("record {i}").into_bytes(),
        };
        out.push(Entry::sign(body, &k.ed, &k.pq).unwrap());
    }
    out
}

fn checkpoint_over(k: &Keys, store: &Store, height: u64, prev: Option<[u8; 32]>) -> Checkpoint {
    let ids = store.entry_ids().unwrap();
    let body = CheckpointBody {
        version: CHECKPOINT_VERSION,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: 1_000 + height,
        entries_count: ids.len() as u64,
        entry_ids_root: datu_core::merkle::merkle_root(&ids),
    };
    Checkpoint::sign(body, &k.ed, &k.pq).unwrap()
}

#[test]
fn proofs_survive_a_growing_ledger() {
    let server = keys();
    let store = Store::open_in_memory().unwrap();
    let early = feed(&server, 3);
    for e in &early {
        store.insert_entry(e).unwrap();
    }
    // The witness signs what it has seen, then the ledger grows.
    let checkpoint = checkpoint_over(&server, &store, 0, None);
    store.append_checkpoint(&checkpoint).unwrap();
    let later = feed(&Keys { ed: SigningKey::from_bytes(&[7u8; 32]), pq: datu_core::pq::keypair().unwrap().1 }, 2);
    for e in &later {
        store.insert_entry(e).unwrap();
    }
    assert!(store.entry_ids().unwrap().len() > checkpoint.body.entries_count as usize);

    // Historical proof: still possible, and it verifies offline.
    for e in &early {
        let id = e.id().unwrap();
        let proof = store.coverage_proof(&id, &checkpoint).unwrap();
        proof.verify(&checkpoint).unwrap();
    }

    // An entry that arrived after the checkpoint is not in its set.
    let late_id = later[0].id().unwrap();
    assert!(store.coverage_proof(&late_id, &checkpoint).is_err());

    // A checkpoint whose root no prefix here reproduces fails closed.
    let foreign = Checkpoint::sign(
        CheckpointBody {
            version: CHECKPOINT_VERSION,
            signer: String::new(),
            signer_pq: String::new(),
            pq_alg: String::new(),
            height: 1,
            prev: Some(checkpoint.id().unwrap()),
            timestamp_ms: 2_000,
            entries_count: checkpoint.body.entries_count,
            entry_ids_root: [9u8; 32],
        },
        &SigningKey::from_bytes(&[5u8; 32]),
        &server.pq,
    )
    .unwrap();
    let err = store.coverage_proof(&early[0].id().unwrap(), &foreign).unwrap_err();
    assert!(format!("{err}").contains("cannot reconstruct"), "{err}");
}

#[test]
fn fresh_checkpoints_keep_working() {
    let server = keys();
    let store = Store::open_in_memory().unwrap();
    for e in &feed(&server, 2) {
        store.insert_entry(e).unwrap();
    }
    let checkpoint = checkpoint_over(&server, &store, 0, None);
    store.append_checkpoint(&checkpoint).unwrap();
    let ids = store.entry_ids().unwrap();
    let proof: CoverageProof = store.coverage_proof(&ids[1], &checkpoint).unwrap();
    assert_eq!(proof.count, ids.len() as u64);
    proof.verify(&checkpoint).unwrap();
}
