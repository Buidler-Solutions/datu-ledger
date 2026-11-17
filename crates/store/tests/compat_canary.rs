//! Golden-store compatibility canary (readiness item R4).
//!
//! `fixtures/golden-node.db` is a real store produced by a released `datu`
//! binary (`init`, three publishes in `gov.golden`, one checkpoint). This
//! test copies the pinned bytes to a tempdir and re-opens them with the
//! *current* code: if a future schema or format change breaks stores
//! written by older binaries, this fails at build time instead of bricking
//! fielded nodes at upgrade time.
//!
//! Regenerating the fixture is a deliberate act (never to paper over a
//! failure here): run a node through `datu init` + publishes + `datu
//! checkpoint` with the *released* binary the fleet runs, close it, and
//! copy `node.db` over the old fixture. Do that only after shipping the
//! migration or compat path that makes old stores survive.

use datu_core::genesis::GENESIS_ID_HEX;
use datu_store::Store;

#[test]
fn golden_store_from_released_binary_opens_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("node.db");
    std::fs::write(&db, include_bytes!("fixtures/golden-node.db")).unwrap();

    let store = Store::open(&db).unwrap();
    let report = store.verify_all().unwrap();

    // The fixture node published three entries; genesis makes four.
    assert_eq!(report.entries, 4, "genesis + 3 gov.golden publishes");
    // Two authors: the founder (genesis) and the fixture node identity.
    assert_eq!(report.feeds, 2);
    // The fixture node signed one checkpoint over everything it saw.
    assert_eq!(report.checkpoints, 1);
    assert_eq!(report.pending_links, 0, "self-contained store");
    assert_eq!(report.conflicts, 0);
    assert!(
        report.lineage,
        "golden store descends from this code's genesis"
    );

    // The lineage is exactly this code's genesis record, byte for byte.
    let genesis = datu_core::genesis::genesis_entry().unwrap();
    let genesis_id = genesis.id().unwrap();
    assert_eq!(hex::encode(genesis_id), GENESIS_ID_HEX);
    let stored = store
        .get_entry(&genesis_id)
        .unwrap()
        .expect("genesis present");
    assert_eq!(stored.body.namespace, "genesis");
    assert_eq!(stored.id().unwrap(), genesis_id);

    // The golden namespace landed intact, three records by one author.
    let golden = store.list_page(Some("gov.golden"), None, 10, 0).unwrap();
    assert_eq!(golden.len(), 3);
    assert!(golden.iter().all(|e| e.body.namespace == "gov.golden"));
    assert_eq!(
        golden.iter().map(|e| e.body.seq).collect::<Vec<_>>(),
        vec![2, 1, 0],
        "list_page is newest-first inside the namespace"
    );

    // The pinned store still accepts a fresh, valid append (the schema this
    // code writes must be the same database the old binary wrote).
    let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pq = datu_core::pq::keypair().unwrap().1;
    let prev_id = store
        .latest(&golden[0].body.author)
        .unwrap()
        .map(|e| e.id().unwrap());
    let body = datu_core::EntryBody {
        version: datu_core::ENTRY_VERSION,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "gov.golden".into(),
        seq: 3,
        prev: prev_id,
        refs: vec![],
        timestamp_ms: 1_700_000_300_000,
        payload: br#"{"kind":"post-upgrade-append"}"#.to_vec(),
    };
    let entry = datu_core::Entry::sign(body, &ed, &pq).unwrap();
    assert!(
        store.insert_entry(&entry).unwrap(),
        "appended after upgrade"
    );
    let report = store.verify_all().unwrap();
    assert_eq!(report.entries, 5);
    assert_eq!(report.feeds, 3, "the new author adds a feed");
}
