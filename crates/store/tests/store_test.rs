use datu_core::merkle::merkle_root;
use datu_core::pq::PqPrivateKey;
use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody};
use datu_store::{Store, StoreError};
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

fn body(seq: u64, prev: Option<[u8; 32]>, payload: &[u8]) -> EntryBody {
    EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "gov.records".into(),
        seq,
        prev,
        refs: vec![],
        timestamp_ms: 1,
        payload: payload.to_vec(),
    }
}

fn feed(k: &Keys, n: u64) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for i in 0..n {
        let prev = out.last().map(|e: &Entry| e.id().unwrap());
        out.push(
            Entry::sign(
                body(i, prev, format!("record {i}").as_bytes()),
                &k.ed,
                &k.pq,
            )
            .unwrap(),
        );
    }
    out
}

fn cp(k: &Keys, height: u64, prev: Option<[u8; 32]>, ids: &[[u8; 32]]) -> Checkpoint {
    let mut b = CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height,
        prev,
        timestamp_ms: 1,
        entries_count: ids.len() as u64,
        entry_ids_root: merkle_root(ids),
    };
    b.entry_ids_root = merkle_root(ids);
    Checkpoint::sign(b, &k.ed, &k.pq).unwrap()
}

#[test]
fn append_fetch_and_idempotency() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let e = Entry::sign(body(0, None, b"first"), &k.ed, &k.pq).unwrap();
    assert!(store.insert_entry(&e).unwrap(), "first insert is new");
    assert!(!store.insert_entry(&e).unwrap(), "re-insert is a no-op");
    let got = store.get_entry(&e.id().unwrap()).unwrap().unwrap();
    assert_eq!(got, e);
    assert_eq!(store.entry_count().unwrap(), 2); // genesis + this entry
}

#[test]
fn storage_layer_blocks_update_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let store = Store::open(&path).unwrap();
    let k = keys();
    let e = Entry::sign(body(0, None, b"first"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&e).unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    let updated = conn.execute("UPDATE entries SET namespace = 'x'", []);
    assert!(updated.is_err(), "UPDATE must be blocked");
    let deleted = conn.execute("DELETE FROM entries", []);
    assert!(deleted.is_err(), "DELETE must be blocked");

    assert_eq!(store.entry_count().unwrap(), 2); // genesis + this entry
    assert!(store.verify_all().unwrap().entries >= 1);
}

#[test]
fn feed_rewrite_conflict_detected() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let original = Entry::sign(body(0, None, b"original"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&original).unwrap();

    let rewrite = Entry::sign(body(0, None, b"rewritten"), &k.ed, &k.pq).unwrap();
    assert!(matches!(
        store.insert_entry(&rewrite),
        Err(StoreError::Conflict { .. })
    ));
}

#[test]
fn wrong_prev_link_rejected() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let e0 = Entry::sign(body(0, None, b"a"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&e0).unwrap();

    let forged = Entry::sign(body(1, Some([9u8; 32]), b"b"), &k.ed, &k.pq).unwrap();
    assert!(matches!(
        store.insert_entry(&forged),
        Err(StoreError::Chain(_))
    ));
}

#[test]
fn forged_signature_rejected() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let mut e = Entry::sign(body(0, None, b"a"), &k.ed, &k.pq).unwrap();
    e.body.payload = b"tampered".to_vec();
    assert!(store.insert_entry(&e).is_err());
}

#[test]
fn verify_all_over_multi_author_feed_with_refs() {
    let store = Store::open_in_memory().unwrap();
    let k1 = keys();
    let k2 = keys();
    let a0 = Entry::sign(body(0, None, b"a0"), &k1.ed, &k1.pq).unwrap();
    store.insert_entry(&a0).unwrap();

    let mut b_body = body(0, None, b"b0");
    b_body.refs = vec![a0.id().unwrap()];
    let b0 = Entry::sign(b_body, &k2.ed, &k2.pq).unwrap();
    store.insert_entry(&b0).unwrap();

    let a1 = Entry::sign(body(1, Some(a0.id().unwrap()), b"a1"), &k1.ed, &k1.pq).unwrap();
    store.insert_entry(&a1).unwrap();

    let report = store.verify_all().unwrap();
    assert_eq!(report.entries, 4); // genesis + 3
    assert_eq!(report.feeds, 3); // genesis, k1, k2
    assert_eq!(report.pending_links, 0);
}

#[test]
fn out_of_order_arrival_is_pending_not_corrupt() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let entries = feed(&k, 3);
    store.insert_entry(&entries[2]).unwrap();
    store.insert_entry(&entries[0]).unwrap();
    let report = store.verify_all().unwrap();
    assert_eq!(report.entries, 3, "genesis + e0 and e2");
    assert_eq!(report.pending_links, 1, "seq 2 prev not yet seen");
}

#[test]
fn checkpoints_append_chain_and_fork_detect() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let ids = store.entry_ids().unwrap();
    let c0 = cp(&k, 0, None, &ids);
    assert!(store.append_checkpoint(&c0).unwrap());
    assert!(!store.append_checkpoint(&c0).unwrap(), "idempotent");

    let ids = store.entry_ids().unwrap();
    let c1 = cp(&k, 1, Some(c0.id().unwrap()), &ids);
    assert!(store.append_checkpoint(&c1).unwrap());

    let fork = cp(&k, 1, Some(c0.id().unwrap()), &[[1u8; 32]]);
    assert!(matches!(
        store.append_checkpoint(&fork),
        Err(StoreError::Fork { .. })
    ));

    let report = store.verify_all().unwrap();
    assert_eq!(report.checkpoints, 2);
}

#[test]
fn bundle_roundtrip_between_nodes() {
    let alice = Store::open_in_memory().unwrap();
    let k = keys();
    for e in feed(&k, 3) {
        alice.insert_entry(&e).unwrap();
    }
    let ids = alice.entry_ids().unwrap();
    alice.append_checkpoint(&cp(&k, 0, None, &ids)).unwrap();

    let bytes = alice.export_bundle("").unwrap();
    let bob = Store::open_in_memory().unwrap();
    let summary = bob.import_bundle(&bytes, "").unwrap();
    assert_eq!(summary.entries_new, 3);
    assert_eq!(summary.checkpoints_new, 1);
    assert_eq!(bob.entry_count().unwrap(), 4); // genesis + 3

    let report = bob.verify_all().unwrap();
    assert_eq!(report.entries, 4);

    let again = bob.import_bundle(&bytes, "").unwrap();
    assert_eq!(again.entries_new, 0);
    assert_eq!(again.entries_existing, 4);
}

#[test]
fn tampered_bundle_rejected() {
    let alice = Store::open_in_memory().unwrap();
    let k = keys();
    for e in feed(&k, 2) {
        alice.insert_entry(&e).unwrap();
    }
    let mut bytes = alice.export_bundle("").unwrap();
    let len = bytes.len();
    bytes[len - 1] ^= 0xFF;
    let bob = Store::open_in_memory().unwrap();
    assert!(bob.import_bundle(&bytes, "").is_err());
}

#[test]
fn witness_stream_roundtrip_and_fork_rejection() {
    let alice = Store::open_in_memory().unwrap();
    let k = keys();
    let c0 = cp(&k, 0, None, &alice.entry_ids().unwrap());
    let c1 = cp(&k, 1, Some(c0.id().unwrap()), &alice.entry_ids().unwrap());
    alice.append_checkpoint(&c0).unwrap();
    alice.append_checkpoint(&c1).unwrap();

    let bytes = alice.export_witness_stream("").unwrap();
    let bob = Store::open_in_memory().unwrap();
    let summary = bob.import_witness_stream(&bytes, "").unwrap();
    assert_eq!(summary.checkpoints_new, 2);
    assert_eq!(summary.checkpoints_existing, 0);
    assert_eq!(bob.checkpoint_count().unwrap(), 2);

    let again = bob.import_witness_stream(&bytes, "").unwrap();
    assert_eq!(again.checkpoints_existing, 2);

    // A contradictory checkpoint (same signer+height, different root) is
    // refused on merge - that is fork evidence, handled by prove-fork.
    let fork = cp(&k, 1, Some(c0.id().unwrap()), &[[7u8; 32]]);
    let mut evil = alice.export_witness_stream("").unwrap();
    let _ = &mut evil;
    let evil_store = Store::open_in_memory().unwrap();
    evil_store.append_checkpoint(&c0).unwrap();
    evil_store.append_checkpoint(&fork).unwrap();
    let evil_stream = evil_store.export_witness_stream("").unwrap();
    assert!(matches!(
        bob.import_witness_stream(&evil_stream, ""),
        Err(datu_store::StoreError::Fork { .. })
    ));
    // Bob's store is untouched by the refused stream.
    assert_eq!(bob.checkpoint_count().unwrap(), 2);
}

#[test]
fn referencing_finds_cosign_style_links() {
    let author = keys();
    let cosigner = keys();
    let store = Store::open_in_memory().unwrap();
    let feed_entries = feed(&author, 2);
    for e in &feed_entries {
        store.insert_entry(e).unwrap();
    }
    let target_id = feed_entries[0].id().unwrap();
    let mut cosign_body = body(0, None, br#"{"attestation":"x"}"#);
    cosign_body.namespace = "identity.cosign".into();
    cosign_body.refs = vec![target_id];
    let cosign = Entry::sign(cosign_body, &cosigner.ed, &cosigner.pq).unwrap();
    store.insert_entry(&cosign).unwrap();

    let refs = store.referencing(&target_id).unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].id().unwrap(), cosign.id().unwrap());
    assert!(store
        .referencing(&feed_entries[1].id().unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn missing_page_returns_only_what_caller_lacks() {
    let a = keys();
    let alice = Store::open_in_memory().unwrap();
    let bob = Store::open_in_memory().unwrap();
    let entries = feed(&a, 5);
    for e in &entries {
        alice.insert_entry(e).unwrap();
    }
    // Bob already has 2 of Alice's 5 entries.
    bob.insert_entry(&entries[1]).unwrap();
    bob.insert_entry(&entries[3]).unwrap();

    let bob_ids = bob.entry_ids().unwrap();
    let mut have = datu_core::BloomFilter::new_for(bob_ids.len().max(16), 0.001);
    for id in &bob_ids {
        have.insert(id);
    }

    let (page, cursor, more) = alice.missing_page(&have, None, 500).unwrap();
    assert!(!more && cursor.is_none());
    let got: Vec<[u8; 32]> = page.iter().map(|e| e.id().unwrap()).collect();
    let expected: Vec<[u8; 32]> = vec![
        entries[0].id().unwrap(),
        entries[2].id().unwrap(),
        entries[4].id().unwrap(),
    ];
    assert_eq!(got, expected);

    // Small pages with cursors must walk the same result.
    let mut walked: Vec<[u8; 32]> = Vec::new();
    let mut cursor: Option<i64> = None;
    loop {
        let (page, cur, more) = alice.missing_page(&have, cursor, 1).unwrap();
        walked.extend(page.iter().map(|e| e.id().unwrap()));
        cursor = cur;
        if !more {
            assert!(cursor.is_none());
            break;
        }
    }
    assert_eq!(walked, expected);

    // A fully-synced caller gets nothing (their ids include the genesis).
    let all_ids = alice.entry_ids().unwrap();
    let mut have_all = datu_core::BloomFilter::new_for(all_ids.len(), 0.001);
    for id in &all_ids {
        have_all.insert(id);
    }
    let (page, cursor, more) = alice.missing_page(&have_all, None, 500).unwrap();
    assert!(page.is_empty() && !more && cursor.is_none());
}

#[test]
fn delta_request_response_offline_roundtrip() {
    let a = keys();
    let alice = Store::open_in_memory().unwrap();
    let bob = Store::open_in_memory().unwrap();
    let entries = feed(&a, 6);
    for e in &entries {
        alice.insert_entry(e).unwrap();
    }
    let cps = [cp(
        &a,
        0,
        None,
        &entries.iter().map(|e| e.id().unwrap()).collect::<Vec<_>>(),
    )];
    alice.append_checkpoint(&cps[0]).unwrap();
    // Bob already has 3 of Alice's 6 entries.
    for e in [&entries[0], &entries[2], &entries[4]] {
        bob.insert_entry(e).unwrap();
    }

    // Bob writes a "what I have" request file; Alice answers; Bob merges.
    let request = bob.export_haves_request(0.001, "").unwrap();
    let (response, suppressed) = alice.answer_delta(&request, "").unwrap();
    assert_eq!(suppressed, 4); // bob's 3 + the shared genesis
    let summary = bob.merge_delta(&response, "").unwrap();
    assert_eq!(summary.entries_new, 3);
    assert_eq!(summary.entries_existing, 0);
    assert_eq!(summary.checkpoints_new, 1);

    // Bob is now a full mirror; re-asking gets an empty delta.
    let request = bob.export_haves_request(0.001, "").unwrap();
    let (response, suppressed) = alice.answer_delta(&request, "").unwrap();
    assert_eq!(suppressed, 7); // 6 + the genesis
    let summary = bob.merge_delta(&response, "").unwrap();
    assert_eq!(summary.entries_new, 0);

    // Bad magic is rejected.
    assert!(datu_store::decode_delta_response(&[0u8; 16]).is_err());
}

#[test]
fn genesis_is_seeded_below_the_policy_in_every_store() {
    // In-memory and disk stores alike begin with the code-carried genesis.
    let store = Store::open_in_memory().unwrap();
    let genesis = datu_core::genesis::genesis_entry().unwrap();
    let id = genesis.id().unwrap();
    assert!(
        store.has_entry(&id).unwrap(),
        "genesis is present from open"
    );
    assert_eq!(
        store.get_entry(&id).unwrap().unwrap(),
        *genesis,
        "the seeded record is byte-identical to the embedded constant"
    );

    // Even the strictest policy cannot refuse it: read-only still seeds.
    let readonly =
        Store::open_in_memory_with_policy(Some(datu_store::WritePolicy::readonly())).unwrap();
    assert!(readonly.has_entry(&id).unwrap());

    // Reopening a seeded store is a no-op (idempotent, no conflict).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let a = Store::open(&path).unwrap();
    assert!(a.has_entry(&id).unwrap());
    drop(a);
    let b = Store::open(&path).unwrap();
    assert!(b.has_entry(&id).unwrap());
    assert_eq!(b.entry_count().unwrap(), 1);

    // And the whole ledger, genesis included, verifies - lineage flagged.
    let report = store.verify_all().unwrap();
    assert!(report.lineage, "verify_all reports the lineage intact");
    let report = readonly.verify_all().unwrap();
    assert!(report.lineage);
    let report = b.verify_all().unwrap();
    assert!(report.lineage);
}

#[test]
fn conflict_evidence_is_recorded_and_listed() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let original = Entry::sign(body(0, None, b"original"), &k.ed, &k.pq).unwrap();
    let rewrite = Entry::sign(body(0, None, b"rewritten"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&original).unwrap();

    assert!(matches!(
        store.insert_entry(&rewrite),
        Err(StoreError::Conflict { .. })
    ));

    let listed = store.list_conflicts(10).unwrap();
    assert_eq!(listed.len(), 1, "the losing side is preserved");
    assert_eq!(listed[0].id, rewrite.id().unwrap());
    assert_eq!(listed[0].stored_id, original.id().unwrap());
    assert_eq!(listed[0].seq, 0);
    assert_eq!(listed[0].author, rewrite.body.author);
    assert_eq!(store.conflicts_count().unwrap(), 1);
    assert_eq!(store.verify_all().unwrap().conflicts, 1);

    // Replaying the same conflicting entry does not duplicate evidence.
    assert!(matches!(
        store.insert_entry(&rewrite),
        Err(StoreError::Conflict { .. })
    ));
    assert_eq!(store.conflicts_count().unwrap(), 1);

    // The recorded side re-verifies standalone: both hybrid signatures over
    // the exact bytes, zero other context needed.
    let evidence = store
        .conflict_entry(&rewrite.id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(evidence, rewrite);
    evidence.verify().unwrap();
    assert!(store
        .conflict_entry(&original.id().unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn trigger_removal_and_row_splicing_is_detected_by_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let store = Store::open(&path).unwrap();
    let k = keys();
    let e = Entry::sign(body(0, None, b"honest"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&e).unwrap();

    // The file owner can drop triggers and splice rows - the physical layer
    // is theirs. Here: swap in a fully valid entry signed by an attacker key
    // while keeping the stored id column.
    let evil = keys();
    let spliced = Entry::sign(body(0, None, b"evil"), &evil.ed, &evil.pq).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER entries_immutable_update;
         DROP TRIGGER entries_immutable_delete;",
    )
    .unwrap();
    conn.execute(
        "UPDATE entries SET body = ?1, signature = ?2, pq_signature = ?3 WHERE namespace = 'gov.records'",
        rusqlite::params![
            Entry::body_bytes(&spliced.body).unwrap(),
            spliced.signature.as_slice(),
            spliced.pq_signature.as_slice(),
        ],
    )
    .unwrap();
    drop(conn);

    // Content addressing catches it: the stored id no longer matches the
    // recomputed id of the bytes in the row. Nothing accepted the splice.
    assert!(matches!(store.verify_all(), Err(StoreError::Chain(_))));
}

#[test]
fn rollback_is_provable_against_retained_witness_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let k = keys();
    let before = {
        let store = Store::open(&path).unwrap();
        for e in feed(&k, 3) {
            store.insert_entry(&e).unwrap();
        }
        let ids = store.entry_ids().unwrap();
        store.append_checkpoint(&cp(&k, 0, None, &ids)).unwrap();
        store.all_checkpoints().unwrap()
    };

    // Simulate an owner rollback: strip triggers, delete history and the
    // checkpoints that covered it. Locally self-consistent afterwards -
    // detection lives with whoever kept the earlier witness stream.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER entries_immutable_delete;
         DROP TRIGGER checkpoints_immutable_delete;",
    )
    .unwrap();
    conn.execute("DELETE FROM entries WHERE namespace = 'gov.records'", [])
        .unwrap();
    conn.execute("DELETE FROM checkpoints", []).unwrap();
    drop(conn);

    // The rolled-back node re-runs and checkpoints its smaller history.
    let store = Store::open(&path).unwrap();
    let replacement = Entry::sign(body(0, None, b"rewritten history"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&replacement).unwrap();
    let ids = store.entry_ids().unwrap();
    store.append_checkpoint(&cp(&k, 0, None, &ids)).unwrap();
    let after = store.all_checkpoints().unwrap();

    let evidence = datu_core::fork::analyze(&before, &after).unwrap();
    assert!(
        evidence
            .iter()
            .any(|f| f.kind == datu_core::fork::KIND_SAME_HEIGHT_FORK),
        "the retained witness stream proves the rollback"
    );
}

#[test]
fn namespace_seq_derives_per_namespace_ordinals() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    // author writes interleaved across two namespaces: seq 0..4
    let names = [
        "gov.records",
        "audit.claims",
        "gov.records",
        "gov.records",
        "audit.claims",
    ];
    let mut prev: Option<[u8; 32]> = None;
    let mut signed = Vec::new();
    for (i, ns) in names.iter().enumerate() {
        let mut b = body(i as u64, prev, format!("rec {i}").as_bytes());
        b.namespace = (*ns).to_string();
        let e = Entry::sign(b, &k.ed, &k.pq).unwrap();
        store.insert_entry(&e).unwrap();
        prev = Some(e.id().unwrap());
        signed.push(e);
    }
    let author = signed[0].body.author.clone();
    // gov.records ordinals: 0, 1, 2 ; audit.claims ordinals: 0, 1
    let gov: Vec<u64> = signed
        .iter()
        .filter(|e| e.body.namespace == "gov.records")
        .map(|e| {
            store
                .namespace_seq(&author, "gov.records", e.body.seq)
                .unwrap()
        })
        .collect();
    let audit: Vec<u64> = signed
        .iter()
        .filter(|e| e.body.namespace == "audit.claims")
        .map(|e| {
            store
                .namespace_seq(&author, "audit.claims", e.body.seq)
                .unwrap()
        })
        .collect();
    assert_eq!(gov, vec![0, 1, 2]);
    assert_eq!(audit, vec![0, 1]);
    // inserting later entries never renumbers earlier ones
    let mut b = body(5, prev, b"late");
    b.namespace = "gov.records".into();
    let late = Entry::sign(b, &k.ed, &k.pq).unwrap();
    store.insert_entry(&late).unwrap();
    assert_eq!(
        store
            .namespace_seq(&author, "gov.records", signed[0].body.seq)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .namespace_seq(&author, "gov.records", late.body.seq)
            .unwrap(),
        3
    );
}

#[test]
fn entries_after_follows_the_insertion_cursor() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let mut prev: Option<[u8; 32]> = None;
    for i in 0..4u64 {
        let e = Entry::sign(body(i, prev, format!("e{i}").as_bytes()), &k.ed, &k.pq).unwrap();
        prev = Some(e.id().unwrap());
        store.insert_entry(&e).unwrap();
    }
    // genesis inserts first; the tail is oldest-first and excludes the cursor
    let first = store.entries_after(0, 2).unwrap();
    assert_eq!(first.len(), 2);
    assert!(first[0].0 < first[1].0);
    let cursor = first[1].0;
    let rest = store.entries_after(cursor, 10).unwrap();
    assert!(rest.iter().all(|(ord, _)| *ord > cursor));
    assert_eq!(
        store.max_ord().unwrap(),
        rest.last().map(|(o, _)| *o).unwrap()
    );
    // replaying from the end applies nothing
    assert!(store
        .entries_after(store.max_ord().unwrap(), 10)
        .unwrap()
        .is_empty());
}

/// Provenance is local bookkeeping: authored rows say "local", imported
/// rows name the channel, and the note never travels inside a bundle (a
/// peer must not receive this node's observations).
#[test]
fn provenance_records_the_channel_without_entering_the_bundle() {
    let store = Store::open_in_memory().unwrap();
    let k = keys();
    let local = Entry::sign(body(0, None, b"local record"), &k.ed, &k.pq).unwrap();
    store.insert_entry(&local).unwrap();
    assert_eq!(
        store.first_seen_of(&local.id().unwrap()).unwrap(),
        Some("local".to_string())
    );

    let peer = Entry::sign(
        body(1, Some(local.id().unwrap()), b"from a peer"),
        &k.ed,
        &k.pq,
    )
    .unwrap();
    store
        .insert_entry_from(&peer, Some("192.168.254.118:7476"))
        .unwrap();
    assert_eq!(
        store.first_seen_of(&peer.id().unwrap()).unwrap(),
        Some("192.168.254.118:7476".to_string())
    );

    // A bundle out of this store carries entries, not this node's notes.
    let bundle = store.export_bundle("").unwrap();
    let other = Store::open_in_memory().unwrap();
    other.import_bundle(&bundle, "").unwrap();
    let moved = other.get_entry(&peer.id().unwrap()).unwrap().unwrap();
    assert_eq!(moved.id().unwrap(), peer.id().unwrap());
    assert_eq!(
        other.first_seen_of(&peer.id().unwrap()).unwrap(),
        Some("bundle".to_string()),
        "the receiver records its own channel, never the sender's note"
    );
    let raw = String::from_utf8_lossy(&bundle);
    assert!(
        !raw.contains("192.168.254.118"),
        "sender provenance must not appear in the bytes"
    );
}
