use datu_core::merkle::merkle_root;
use datu_core::pq::PqPrivateKey;
use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody};
use datu_indexer::{open, run_once, IndexerConfig, VerifyMode};
use datu_store::Store;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;

/// Sign a small fixture ledger: one author, two namespaces, refs between
/// entries, and one checkpoint-free store (checkpoint tests live elsewhere).
fn write_fixture(dir: &Path) {
    let store = Store::open(&dir.join("node.db")).unwrap();
    let ed = SigningKey::generate(&mut OsRng);
    let pq: PqPrivateKey = datu_core::pq::keypair().unwrap().1;
    let mut prev: Option<[u8; 32]> = None;
    let namespaces = [
        "gov.titles.application",
        "audit.claims",
        "gov.titles.application",
        "audit.claims",
        "gov.titles.application",
    ];
    for (i, ns) in namespaces.iter().enumerate() {
        let mut body = EntryBody {
            version: 1,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: (*ns).to_string(),
            seq: i as u64,
            prev,
            refs: vec![],
            timestamp_ms: 1_700_000_000_000 + i as u64,
            payload: format!("{{\"n\":{i},\"ns\":\"{ns}\"}}").into_bytes(),
        };
        // every entry also cites its predecessor, exercising refs projection
        if let Some(p) = prev {
            body.refs.push(p);
        }
        let entry = Entry::sign(body, &ed, &pq).unwrap();
        prev = Some(entry.id().unwrap());
        store.insert_entry(&entry).unwrap();
    }
}

#[test]
fn projects_verifies_and_is_idempotent() {
    let node = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    write_fixture(node.path());

    let cfg = IndexerConfig::new(node.path());
    let db_url = format!("sqlite://{}", proj.path().join("projection.db").display());
    let mut db = open(&db_url).unwrap();
    let first = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(
        first.applied, 6,
        "five fixture entries plus the code-carried genesis"
    );
    assert_eq!(first.rejected, 0);
    assert!(first.cursor.starts_with("cur1:"));

    // rows land where an app expects them
    let conn = rusqlite::Connection::open(proj.path().join("projection.db")).unwrap();
    let (entries, titles, audits, feeds): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM entries),
               (SELECT COUNT(*) FROM entries WHERE namespace = 'gov.titles.application'),
               (SELECT COUNT(*) FROM entries WHERE namespace = 'audit.claims'),
               (SELECT COUNT(*) FROM feeds)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (entries, titles, audits, feeds),
        (6, 3, 2, 2),
        "fixture + genesis, two authors"
    );
    // per-namespace ordinals are derived in the projection too
    let ns_seq: i64 = conn
        .query_row(
            "SELECT ns_seq FROM entries WHERE namespace = 'gov.titles.application' ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ns_seq, 2, "third title entry has namespace ordinal 2");

    // replay: nothing new, nothing lost
    let second = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(second.applied, 0, "idempotent replay applies nothing");
    assert_eq!(second.cursor, first.cursor, "cursor is stable at rest");
    assert_eq!(
        second.members, first.members,
        "membership replay is idempotent"
    );
}

#[test]
fn namespace_allowlist_scopes_the_projection() {
    let node = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    write_fixture(node.path());

    let mut cfg = IndexerConfig::new(node.path());
    cfg.namespaces = vec!["gov.*".to_string()];
    let db_url = format!("sqlite://{}", proj.path().join("projection.db").display());
    let mut db = open(&db_url).unwrap();
    let stats = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(stats.applied, 3, "only gov.* entries projected");
    assert_eq!(
        stats.filtered, 3,
        "audit.claims and genesis skipped by the allowlist"
    );

    let conn = rusqlite::Connection::open(proj.path().join("projection.db")).unwrap();
    let others: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE namespace NOT LIKE 'gov.%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(others, 0);
}

#[test]
fn verify_none_and_rejection_paths_exist() {
    let node = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    write_fixture(node.path());

    let mut cfg = IndexerConfig::new(node.path());
    cfg.verify = VerifyMode::None;
    let db_url = format!("sqlite://{}", proj.path().join("projection.db").display());
    let mut db = open(&db_url).unwrap();
    let stats = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(stats.applied, 6, "trust mode projects everything");

    let conn = rusqlite::Connection::open(proj.path().join("projection.db")).unwrap();
    let rejected: i64 = conn
        .query_row("SELECT COUNT(*) FROM rejected", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rejected, 0, "nothing rejected in a healthy store");
}

#[test]
fn checkpoint_membership_is_projected_and_root_checked() {
    let node = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    write_fixture(node.path());

    // Sign a checkpoint over the current id set (prefix of insertion order).
    let store = Store::open(&node.path().join("node.db")).unwrap();
    let ids = store.entry_ids().unwrap();
    let ed = SigningKey::generate(&mut OsRng);
    let pq: PqPrivateKey = datu_core::pq::keypair().unwrap().1;
    let body = CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height: 0,
        prev: None,
        timestamp_ms: 1_700_000_100_000,
        entries_count: ids.len() as u64,
        entry_ids_root: merkle_root(&ids),
    };
    let cp = Checkpoint::sign(body, &ed, &pq).unwrap();
    store.append_checkpoint(&cp).unwrap();

    let cfg = IndexerConfig::new(node.path());
    let db_url = format!("sqlite://{}", proj.path().join("projection.db").display());
    let mut db = open(&db_url).unwrap();
    let stats = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(stats.gaps, 0, "the prefix reconstructs this checkpoint");
    assert_eq!(
        stats.members as usize,
        ids.len(),
        "membership covers every id"
    );

    let conn = rusqlite::Connection::open(proj.path().join("projection.db")).unwrap();
    let members: i64 = conn
        .query_row("SELECT COUNT(*) FROM checkpoint_members", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(members as usize, ids.len());

    // A checkpoint over a set this node cannot reconstruct is a gap, not a lie.
    let store2 = Store::open(&node.path().join("node.db")).unwrap();
    let mut bad = body_for_checkpoint(ids.len() as u64 + 10, [0u8; 32]);
    bad.height = 1;
    bad.prev = Some(cp.id().unwrap());
    let bad_cp = Checkpoint::sign(bad, &ed, &pq).unwrap();
    let _ = store2.append_checkpoint(&bad_cp);
    let second = run_once(db.as_mut(), &cfg).unwrap();
    assert!(
        second.gaps >= 1,
        "unreconstructable sets are counted as gaps"
    );
}

fn body_for_checkpoint(count: u64, root: [u8; 32]) -> CheckpointBody {
    CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height: 1,
        prev: None,
        timestamp_ms: 1_700_000_200_000,
        entries_count: count,
        entry_ids_root: root,
    }
}

/// Upgrade-compatibility gate (readiness R4): the projection carries a
/// schema version stamp. A database stamped by a newer indexer must be
/// refused by this binary - loudly, with one exact message - on both the
/// indexing and the status paths, and `--reindex` (reset) must recover it.
#[test]
fn newer_projection_schema_stamp_is_refused_and_reindex_recovers() {
    let node = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    write_fixture(node.path());

    let cfg = IndexerConfig::new(node.path());
    let db_path = proj.path().join("projection.db");
    let db_url = format!("sqlite://{}", db_path.display());

    // A fresh database is stamped with this code's version on first use.
    let mut db = open(&db_url).unwrap();
    run_once(db.as_mut(), &cfg).unwrap();
    let status = db.status().unwrap();
    assert_eq!(
        status["projection_schema_version"], 1,
        "status reports the stamp it wrote"
    );
    let stamp: String = rusqlite::Connection::open(&db_path)
        .unwrap()
        .query_row(
            "SELECT v FROM indexer_meta WHERE k = 'projection_schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stamp, "1");

    // Simulate a future indexer having rewritten this projection.
    rusqlite::Connection::open(&db_path)
        .unwrap()
        .execute(
            "UPDATE indexer_meta SET v = '99' WHERE k = 'projection_schema_version'",
            [],
        )
        .unwrap();

    let mut old = open(&db_url).unwrap();
    let err = run_once(old.as_mut(), &cfg).unwrap_err();
    assert_eq!(err, datu_indexer::NEWER_PROJECTION_ERROR);
    let mut old = open(&db_url).unwrap();
    let err = old.status().unwrap_err();
    assert_eq!(err, datu_indexer::NEWER_PROJECTION_ERROR);

    // Recovery: `--reindex` drops the stamp with the tables and reprojects.
    let mut fresh = open(&db_url).unwrap();
    fresh.reset().unwrap();
    let stats = run_once(fresh.as_mut(), &cfg).unwrap();
    assert_eq!(stats.applied, 6, "reindex replays the whole ledger");
    let status = fresh.status().unwrap();
    assert_eq!(status["projection_schema_version"], 1);
}
