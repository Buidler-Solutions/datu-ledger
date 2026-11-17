//! Live dialect tests. They run only when the matching DSN is provided:
//!
//!   DATU_TEST_PG_URL=postgres://user:pass@localhost/datu_test cargo test -p datu-indexer --features postgres
//!   DATU_TEST_MYSQL_URL=mysql://user:pass@localhost/datu_test cargo test -p datu-indexer --features mysql
//!
//! Without the variable they return immediately, so CI without databases and
//! plain `cargo test` stay green.

use datu_core::pq::PqPrivateKey;
use datu_core::{Entry, EntryBody};
use datu_indexer::{open, run_once, IndexerConfig};
use datu_store::Store;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;

fn write_fixture(dir: &Path) {
    let store = Store::open(&dir.join("node.db")).unwrap();
    let ed = SigningKey::generate(&mut OsRng);
    let pq: PqPrivateKey = datu_core::pq::keypair().unwrap().1;
    let mut prev: Option<[u8; 32]> = None;
    for i in 0..4u64 {
        let body = EntryBody {
            version: 1,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "gov.titles.application".into(),
            seq: i,
            prev,
            refs: vec![],
            timestamp_ms: 1_700_000_000_000 + i,
            payload: format!("{{\"n\":{i}}}").into_bytes(),
        };
        let entry = Entry::sign(body, &ed, &pq).unwrap();
        prev = Some(entry.id().unwrap());
        store.insert_entry(&entry).unwrap();
    }
}

fn run_against(url: &str) {
    let node = tempfile::tempdir().unwrap();
    write_fixture(node.path());
    let cfg = IndexerConfig::new(node.path());
    let mut db = open(url).unwrap();
    db.reset().unwrap();
    let first = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(first.applied, 5, "four fixture entries plus genesis");
    let second = run_once(db.as_mut(), &cfg).unwrap();
    assert_eq!(second.applied, 0, "idempotent replay");
    let status = db.status().unwrap();
    assert_eq!(status["entries"], 5);
    assert_eq!(status["rejected"], 0);
    db.reset().unwrap();
}

#[test]
#[cfg(feature = "postgres")]
fn postgres_projection_roundtrip() {
    let Ok(url) = std::env::var("DATU_TEST_PG_URL") else {
        return;
    };
    run_against(&url);
}

#[test]
#[cfg(feature = "mysql")]
fn mysql_projection_roundtrip() {
    let Ok(url) = std::env::var("DATU_TEST_MYSQL_URL") else {
        return;
    };
    run_against(&url);
}
