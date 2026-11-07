use datu_core::pq::PqPrivateKey;
use datu_core::{Checkpoint, CheckpointBody, Entry, EntryBody};
use datu_p2p::{handle_connection, pull_and_merge};
use datu_store::Store;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::net::TcpListener;

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
            version: 1,
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

#[test]
fn native_pull_copies_only_missing_entries() {
    let server_keys = keys();
    let entries = feed(&server_keys, 5);
    let mut checkpoints = Vec::new();
    let ids: Vec<[u8; 32]> = entries.iter().map(|e| e.id().unwrap()).collect();
    let body = CheckpointBody {
        version: 1,
        signer: String::new(),
        signer_pq: String::new(),
        pq_alg: String::new(),
        height: 0,
        prev: None,
        timestamp_ms: 1,
        entries_count: ids.len() as u64,
        entry_ids_root: datu_core::merkle::merkle_root(&ids),
    };
    checkpoints.push(Checkpoint::sign(body, &server_keys.ed, &server_keys.pq).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let server_store = Store::open_in_memory().unwrap();
        for e in &entries {
            server_store.insert_entry(e).unwrap();
        }
        server_store.append_checkpoint(&checkpoints[0]).unwrap();
        for conn in listener.incoming().flatten() {
            handle_connection(conn, &server_store, None);
        }
    });

    // Client already has 2 of the 5 entries.
    let client = Store::open_in_memory().unwrap();
    client.insert_entry(&feed(&server_keys, 2)[0]).unwrap();
    client.insert_entry(&feed(&server_keys, 2)[1]).unwrap();
    let before = client.entry_ids().unwrap();
    assert_eq!(before.len(), 3); // genesis + the 2 pre-seeded records

    let stats = pull_and_merge(&addr.to_string(), &client, 2, None).unwrap();
    assert_eq!(stats.entries_new, 3);
    assert_eq!(stats.entries_existing, 0); // bloom-known ids are never sent
    assert_eq!(stats.checkpoints_new, 1);
    assert_eq!(client.entry_count().unwrap(), 6); // genesis + 5 records
    client.verify_all().unwrap();

    // Pull again: nothing new (idempotent) - the bloom now covers all ids.
    let stats = pull_and_merge(&addr.to_string(), &client, 500, None).unwrap();
    assert_eq!(stats.entries_new, 0);
    assert_eq!(stats.entries_existing, 0);
}

#[test]
fn bad_magic_is_refused_not_crashed() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let store = Store::open_in_memory().unwrap();
        for conn in listener.incoming().flatten() {
            handle_connection(conn, &store, None);
        }
    });

    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let request = datu_p2p::PullRequest {
        magic: *b"NOTDATU1",
        bloom_m: 64,
        bloom_k: 4,
        bloom_bits: vec![0u8; 8],
        cursor: None,
        limit: 10,
    };
    let bytes = borsh::to_vec(&request).unwrap();
    use std::io::Write;
    stream.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();

    // Server must reply with an Error frame and close.
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    assert!(stream.read_exact(&mut len_buf).is_ok());
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    assert!(stream.read_exact(&mut buf).is_ok());
    let message: datu_p2p::ServerMessage =
        borsh::BorshDeserialize::try_from_slice(&buf).unwrap();
    match message {
        datu_p2p::ServerMessage::Error(m) => assert!(m.contains("unknown frame")),
        other => panic!("expected error, got {other:?}"),
    }
}
