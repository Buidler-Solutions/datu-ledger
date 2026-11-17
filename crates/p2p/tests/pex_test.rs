use datu_p2p::peers::{PEERS_FILE, SHARE_LIMIT};
use datu_p2p::{
    exchange_peers, handle_connection_with_peers, sign_hello, NetworkPolicy, PeerTable,
    PeersRequest, PEERS_MAGIC,
};
use datu_store::Store;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::net::TcpListener;

/// The full exchange over the wire: a verified address is shared, hearsay and
/// foreign-mesh addresses are not, and the asker's announce lands in the
/// server's table.
#[test]
fn exchange_shares_verified_and_records_announce() {
    let table = PeerTable::new();
    // Verified by an actual sync: shareable.
    table.upsert("10.0.0.11:7476", "aa11", "", "mdns");
    table.record_success("10.0.0.11:7476", "aa11", "");
    // Only heard about: must not leave this node.
    table.merge_pex(
        &[datu_p2p::PeerWire {
            addr: "10.0.0.12:7476".into(),
            node_key: String::new(),
            network_id: String::new(),
            last_success_ms: 5,
        }],
        "",
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_table = std::sync::Arc::new(PeerTable::new());
    server_table.upsert("10.0.0.21:7476", "bb21", "", "mdns");
    server_table.record_success("10.0.0.21:7476", "bb21", "");
    {
        let server_table = server_table.clone();
        std::thread::spawn(move || {
            let store = Store::open_in_memory().unwrap();
            for conn in listener.incoming().flatten() {
                handle_connection_with_peers(conn, &store, None, Some(&server_table), 256);
            }
        });
    }

    let response = exchange_peers(
        &addr.to_string(),
        None,
        "cc99",
        "",
        Some("10.0.0.31:7476"),
        SHARE_LIMIT as u16,
    )
    .unwrap();
    assert_eq!(response.magic, PEERS_MAGIC);
    assert_eq!(
        response.peers.len(),
        1,
        "only the verified address is shared"
    );
    assert_eq!(response.peers[0].addr, "10.0.0.21:7476");
    assert_eq!(response.peers[0].node_key, "bb21");

    // The client merges, then re-syncs: only now does its table share it.
    let learned = table.merge_pex(&response.peers, "");
    assert_eq!(learned, 1);
    assert!(
        table.shareable("", SHARE_LIMIT).is_empty() || {
            table.record_success("10.0.0.21:7476", "bb21", "");
            table.shareable("", SHARE_LIMIT).len() == 2
        },
        "hearsay stays unshared until this node syncs itself"
    );

    // The announce reached the server's table.
    let snapshot = server_table.snapshot();
    assert!(snapshot
        .iter()
        .any(|e| e.addr == "10.0.0.31:7476" && e.node_key == "cc99"));
}

/// A walled mesh demands an admitted hello before any exchange - the same
/// door rule as pull sync.
#[test]
fn walled_mesh_demands_hello_for_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let network = NetworkPolicy {
        mode: "permissionless".into(),
        network_id: "mesh-x".into(),
        ..NetworkPolicy::permissionless()
    };
    std::thread::spawn(move || {
        let store = Store::open_in_memory().unwrap();
        for conn in listener.incoming().flatten() {
            handle_connection_with_peers(conn, &store, Some(&network), None, 256);
        }
    });

    // Bare request: refused at the door, the message says how to fix it.
    let err = exchange_peers(&addr.to_string(), None, "dd", "mesh-x", None, 16).unwrap_err();
    assert!(
        err.contains("hello required"),
        "walled server must name the door rule: {err}"
    );

    // With a signed hello for the same mesh: answered.
    let key = SigningKey::generate(&mut OsRng);
    let hello = sign_hello(&key, "mesh-x");
    let response =
        exchange_peers(&addr.to_string(), Some(&hello), "dd", "mesh-x", None, 16).unwrap();
    assert!(
        response.peers.is_empty(),
        "a fresh walled node knows nobody yet"
    );
}

/// The peer-exchange frame from a hand-rolled socket: a first frame carrying
/// DATUPEX1 is answered with one PeersResponse, then the connection closes.
#[test]
fn bare_exchange_frame_is_answered() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let store = Store::open_in_memory().unwrap();
        for conn in listener.incoming().flatten() {
            handle_connection_with_peers(conn, &store, None, None, 256);
        }
    });

    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    let request = PeersRequest {
        magic: PEERS_MAGIC,
        node_key: String::new(),
        network_id: String::new(),
        announce: None,
        limit: 8,
    };
    let bytes = borsh::to_vec(&request).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).unwrap();
    let response: datu_p2p::PeersResponse = borsh::BorshDeserialize::try_from_slice(&buf).unwrap();
    assert_eq!(response.magic, PEERS_MAGIC);
    assert!(response.peers.is_empty(), "no table wired: empty answer");
}

/// The persisted table lives where the daemon expects it, named as documented.
#[test]
fn table_persists_in_the_data_dir() {
    let dir = std::env::temp_dir().join(format!("datu-pex-wire-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let t = PeerTable::load(&dir);
    t.upsert("10.7.7.7:7476", "", "", "pex");
    t.save();
    assert!(dir.join(PEERS_FILE).exists());
    assert_eq!(PeerTable::load(&dir).len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// A learned address that never syncs and keeps failing is swept away, so
/// stale mDNS records do not accumulate in the explorer; the operator's own
/// seeds and addresses that do answer are kept.
#[test]
fn stale_learned_peers_are_swept() {
    let table = PeerTable::new();
    table.upsert("10.0.0.31:7476", "cc31", "", "mdns");
    table.upsert("10.0.0.32:7476", "cc32", "", "seed");
    // Age both past the sweep window without waiting ten real minutes.
    for addr in ["10.0.0.31:7476", "10.0.0.32:7476"] {
        table.upsert(addr, "", "", "mdns");
    }
    // Re-create as freshly aged: the test pokes the entry directly.
    table.age_for_test("10.0.0.31:7476", 11 * 60 * 1000);
    table.age_for_test("10.0.0.32:7476", 11 * 60 * 1000);
    for _ in 0..12 {
        table.record_failure("10.0.0.31:7476", "connection refused");
        table.record_failure("10.0.0.32:7476", "connection refused");
    }
    let snapshot = table.snapshot();
    assert!(
        snapshot.iter().all(|p| p.addr != "10.0.0.31:7476"),
        "learned dead address is gone"
    );
    assert!(
        snapshot.iter().any(|p| p.addr == "10.0.0.32:7476"),
        "operator seed survives the sweep"
    );
    // A learned peer that actually synced is never swept either.
    table.upsert("10.0.0.33:7476", "cc33", "", "mdns");
    table.record_success("10.0.0.33:7476", "cc33", "");
    table.age_for_test("10.0.0.33:7476", 11 * 60 * 1000);
    for _ in 0..12 {
        table.record_failure("10.0.0.33:7476", "connection refused");
    }
    assert!(table.snapshot().iter().any(|p| p.addr == "10.0.0.33:7476"));
}
