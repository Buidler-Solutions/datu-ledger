//! Mint the DATU genesis record: the first entry every ledger seeded from
//! this code begins with, signed by the founder's key.
//!
//! ```sh
//! cargo run -p datu-core --example mint_genesis -- <statement.txt> [secrets-dir]
//! ```
//!
//! The statement file is the record's message - it is embedded nowhere else
//! in the repo (no redundant copies; the minter even refuses a file that
//! repeats its own headline). Secrets are written once to `secrets-dir`
//! (default `~/.datu-genesis`), mode 0600, never printed. Stdout carries only
//! public material: the borsh hex of the signed entry and its author keys -
//! paste those into `crates/core/src/genesis.rs`.
//!
//! Fork founders run this with their own statement and their own keys to
//! start their own lineage; keeping this record marks a ledger as descending
//! from EB. Secretaria aka greenarmor's.

use datu_core::error::Error;
use datu_core::{Entry, EntryBody};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;

const FOUNDER: &str = "EB. Secretaria aka greenarmor";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let statement_path = args
        .first()
        .expect("usage: mint_genesis <statement.txt> [secrets-dir]");
    let secrets_dir = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_default() + "/.datu-genesis");

    let statement = std::fs::read_to_string(statement_path)
        .unwrap_or_else(|e| panic!("cannot read {statement_path}: {e}"));
    let statement = statement.trim_end().to_string();
    let headline = "The Greatest Life Hack";
    let hits = statement.matches(headline).count();
    assert_eq!(
        hits, 1,
        "the statement must carry its message exactly once (found {hits} copies of the headline)"
    );

    let ed = SigningKey::generate(&mut OsRng);
    let (_pq_pk, pq) = datu_core::pq::keypair().unwrap();

    let payload = serde_json::json!({
        "version": 1,
        "kind": "genesis",
        "project": "DATU - a DAG-type accountability ledger, not a blockchain",
        "founder": FOUNDER,
        "statement": statement,
        "charter": "Every ledger seeded from this code begins with this record. \
    Forks that keep it descend from this lineage; forks that mint their own genesis walk their own.",
    });

    let body = EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: "genesis".into(),
        seq: 0,
        prev: None,
        refs: vec![],
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        payload: serde_json::to_vec(&payload).unwrap(),
    };
    let entry = Entry::sign(body, &ed, &pq)
        .map_err(|e: Error| e.to_string())
        .unwrap();
    entry.verify().unwrap();
    let id = entry.id().unwrap();

    write_secret(
        &secrets_dir,
        "genesis-ed25519.hex",
        &hex::encode(ed.to_bytes()),
    );
    write_secret(
        &secrets_dir,
        "genesis-mldsa65.hex",
        &datu_core::pq::sk_to_hex(&pq),
    );

    println!("genesis entry id:   {}", hex::encode(id));
    println!("genesis author:    {}", entry.body.author);
    println!("genesis author_pq: {}", entry.body.author_pq);
    println!("secrets written:   {secrets_dir} (back this up; it is never printed)");
    println!();
    println!("GENESIS_ENTRY_HEX=");
    println!("{}", hex::encode(borsh::to_vec(&entry).unwrap()));
}

fn write_secret(dir: &str, name: &str, secret_hex: &str) {
    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, secret_hex).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}
