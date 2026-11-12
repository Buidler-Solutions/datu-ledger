//! End-to-end network-admission tests over real TCP: the `network.json`
//! semantics (member admission, attested strangers, the mutual mesh wall,
//! walled observers) enforced at the p2p door.

use datu_core::attest::{AttestationDoc, NS_ATTEST};
use datu_core::pq::PqPrivateKey;
use datu_core::{Entry, EntryBody};
use datu_p2p::{
    handle_connection, pull_and_merge, sign_hello, NetworkPolicy, PullRequest, ServerMessage, MAGIC,
};
use datu_store::Store;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::net::{SocketAddr, TcpListener, TcpStream};

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

fn hex_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
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

/// An on-ledger attestation binding `subject` (hex node key) to a role,
/// authored (signed) by `attestor`.
fn attestation(attestor: &Keys, subject: &str) -> Entry {
    let doc = AttestationDoc {
        subject: subject.to_string(),
        label: Some("member".into()),
        claims: serde_json::json!({"role": "validator"}),
    };
    let body = EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: NS_ATTEST.into(),
        seq: 0,
        prev: None,
        refs: vec![],
        timestamp_ms: 1,
        payload: doc.payload_bytes().unwrap(),
    };
    Entry::sign(body, &attestor.ed, &attestor.pq).unwrap()
}

/// A key-level revoke naming `subject` directly (the ejection path for
/// explicit members), authored by `revoker` as their first statement.
fn key_revocation(revoker: &Keys, subject: &str) -> Entry {
    let doc = datu_core::attest::RevokeDoc {
        attestation: None,
        subject: Some(subject.to_string()),
        reason: Some("ejected by the root".into()),
    };
    let body = EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: datu_core::attest::NS_REVOKE.into(),
        seq: 0,
        prev: None,
        refs: vec![],
        timestamp_ms: 2,
        payload: doc.payload_bytes().unwrap(),
    };
    Entry::sign(body, &revoker.ed, &revoker.pq).unwrap()
}

/// A revoke statement naming `attestation_id`, authored by `revoker`.
/// Seq 1 / prev = the attestation, since the same root authored both.
fn revocation(revoker: &Keys, attestation_id: [u8; 32]) -> Entry {
    let doc = datu_core::attest::RevokeDoc {
        attestation: Some(hex::encode(attestation_id)),
        subject: None,
        reason: Some("membership ended".into()),
    };
    let body = EntryBody {
        version: 1,
        author: String::new(),
        author_pq: String::new(),
        pq_alg: String::new(),
        namespace: datu_core::attest::NS_REVOKE.into(),
        seq: 1,
        prev: Some(attestation_id),
        refs: vec![attestation_id],
        timestamp_ms: 2,
        payload: doc.payload_bytes().unwrap(),
    };
    Entry::sign(body, &revoker.ed, &revoker.pq).unwrap()
}

fn permissioned(network_id: &str, members: Vec<String>, roots: Vec<String>) -> NetworkPolicy {
    NetworkPolicy {
        version: 1,
        mode: "permissioned".into(),
        network_id: network_id.into(),
        members,
        roots,
        manifest_root: None,
    }
}

fn walled_observer(network_id: &str) -> NetworkPolicy {
    NetworkPolicy {
        version: 1,
        mode: "permissionless".into(),
        network_id: network_id.into(),
        members: Vec::new(),
        roots: Vec::new(),
        manifest_root: None,
    }
}

fn store_with(k: &Keys, n: u64) -> Store {
    let store = Store::open_in_memory().unwrap();
    for e in feed(k, n) {
        store.insert_entry(&e).unwrap();
    }
    store
}

/// Serve pulls on a background thread under `network` until the test ends.
fn spawn(store: Store, network: Option<NetworkPolicy>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            handle_connection(conn, &store, network.as_ref());
        }
    });
    addr
}

#[test]
fn network_policy_json_roundtrip_and_validation() {
    let open = NetworkPolicy::permissionless();
    assert_eq!(
        NetworkPolicy::from_json(&open.to_json().unwrap()).unwrap(),
        open
    );
    assert!(!open.is_permissioned());

    let walled = permissioned("gov-mesh", vec!["aa".into()], vec!["bb".into()]);
    assert_eq!(
        NetworkPolicy::from_json(&walled.to_json().unwrap()).unwrap(),
        walled
    );
    assert!(walled.is_permissioned());

    let bad_version = walled
        .to_json()
        .unwrap()
        .replace("\"version\": 1", "\"version\": 2");
    let err = NetworkPolicy::from_json(&bad_version).unwrap_err();
    assert!(err.contains("version"), "{err}");

    let bad_mode = r#"{"version":1,"mode":"clubby","network_id":"","members":[],"roots":[]}"#;
    let err = NetworkPolicy::from_json(bad_mode).unwrap_err();
    assert!(err.contains("mode"), "{err}");

    assert!(walled.self_admitted("aa"));
    assert!(walled.self_admitted("bb"));
    assert!(!walled.self_admitted("cc"));
}

#[test]
fn open_server_serves_plain_client_without_hello() {
    let server_keys = keys();
    let store = store_with(&server_keys, 3);
    let addr = spawn(store, None);

    let client = Store::open_in_memory().unwrap();
    let stats = pull_and_merge(&addr.to_string(), &client, 500, None).unwrap();
    assert_eq!(stats.entries_new, 3);
    assert_eq!(client.entry_count().unwrap(), 4); // genesis + 3 records
    client.verify_all().unwrap();
}

#[test]
fn permissioned_server_admits_member_hello() {
    let server_keys = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    let network = permissioned(
        "gov-mesh",
        vec![hex_key(&client_keys.ed)],
        vec![hex_key(&server_keys.ed)],
    );
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let stats = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap();
    assert_eq!(stats.entries_new, 3);
    assert_eq!(client.entry_count().unwrap(), 4); // genesis + 3 records
    client.verify_all().unwrap();
}

#[test]
fn permissioned_server_refuses_stranger() {
    let server_keys = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    let network = permissioned(
        "gov-mesh",
        vec![hex_key(&server_keys.ed)],
        vec![hex_key(&server_keys.ed)],
    );
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(err.contains("not admitted"), "{err}");
    assert_eq!(client.entry_count().unwrap(), 1); // only the genesis
}

#[test]
fn attested_stranger_is_admitted_by_root() {
    let server_keys = keys();
    let root = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    store
        .insert_entry(&attestation(&root, &hex_key(&client_keys.ed)))
        .unwrap();
    let network = permissioned("gov-mesh", vec![], vec![hex_key(&root.ed)]);
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let stats = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap();
    assert_eq!(stats.entries_new, 4); // 3 records + the attestation itself
    client.verify_all().unwrap();
}

#[test]
fn revoked_attestation_no_longer_admits() {
    let server_keys = keys();
    let root = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    let attest = attestation(&root, &hex_key(&client_keys.ed));
    let attestation_id = attest.id().unwrap();
    store.insert_entry(&attest).unwrap();
    store
        .insert_entry(&revocation(&root, attestation_id))
        .unwrap();
    let network = permissioned("gov-mesh", vec![], vec![hex_key(&root.ed)]);
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(
        err.contains("not admitted"),
        "a revoked root attestation must not admit: {err}"
    );
}

#[test]
fn attestation_by_non_root_does_not_admit() {
    let server_keys = keys();
    let root = keys();
    let someone_else = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    store
        .insert_entry(&attestation(&someone_else, &hex_key(&client_keys.ed)))
        .unwrap();
    let network = permissioned("gov-mesh", vec![], vec![hex_key(&root.ed)]);
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(err.contains("not admitted"), "{err}");
}

#[test]
fn tampered_hello_signature_is_refused() {
    let server_keys = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    let network = permissioned("gov-mesh", vec![hex_key(&client_keys.ed)], vec![]);
    let addr = spawn(store, Some(network));

    let mut hello = sign_hello(&client_keys.ed, "gov-mesh");
    hello.signature[0] ^= 0x01;
    let client = Store::open_in_memory().unwrap();
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(err.contains("signature"), "{err}");
}

#[test]
fn walled_observer_serves_same_mesh_and_refuses_open_peers() {
    let server_keys = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    let addr = spawn(store, Some(walled_observer("gov-mesh")));

    // Same mesh id: the observer mirrors it, permissionless, no members.
    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let stats = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap();
    assert_eq!(stats.entries_new, 3);
    client.verify_all().unwrap();

    // Open-network dialer (empty id): the wall refuses, both directions.
    let err = pull_and_merge(
        &addr.to_string(),
        &client,
        500,
        Some(&sign_hello(&client_keys.ed, "")),
    )
    .unwrap_err();
    assert!(err.contains("network mismatch"), "{err}");
}

#[test]
fn walled_server_answers_hello_required_to_plain_request() {
    let server_keys = keys();
    let store = store_with(&server_keys, 3);
    let addr = spawn(store, Some(walled_observer("gov-mesh")));

    let mut stream = TcpStream::connect(addr).unwrap();
    let request = PullRequest {
        magic: MAGIC,
        bloom_m: 64,
        bloom_k: 4,
        bloom_bits: vec![0u8; 8],
        cursor: None,
        limit: 10,
    };
    let bytes = borsh::to_vec(&request).unwrap();
    use std::io::Write;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();

    use std::io::Read;
    let mut len_buf = [0u8; 4];
    assert!(stream.read_exact(&mut len_buf).is_ok());
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    assert!(stream.read_exact(&mut buf).is_ok());
    let message: ServerMessage = borsh::BorshDeserialize::try_from_slice(&buf).unwrap();
    match message {
        ServerMessage::Error(m) => assert!(m.contains("hello required"), "{m}"),
        other => panic!("expected error, got {other:?}"),
    }
}

#[test]
fn mesh_client_against_open_server_hits_the_wall() {
    let server_keys = keys();
    let store = store_with(&server_keys, 3);
    let addr = spawn(store, None);

    // The wall is mutual: an open server also refuses a mesh-carrying hello.
    let client_keys = keys();
    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(err.contains("network mismatch"), "{err}");
    assert_eq!(client.entry_count().unwrap(), 1); // only the genesis
}

#[test]
fn a_key_revocation_ejects_an_explicit_member() {
    let server_keys = keys();
    let root = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    // The client IS an explicit member, and a root revokes its key anyway.
    store
        .insert_entry(&key_revocation(&root, &hex_key(&client_keys.ed)))
        .unwrap();
    let network = permissioned(
        "gov-mesh",
        vec![hex_key(&client_keys.ed)],
        vec![hex_key(&root.ed)],
    );
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    let err = pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap_err();
    assert!(
        err.contains("revoked"),
        "the ledger outranks the membership list: {err}"
    );
}

#[test]
fn a_key_revocation_from_a_non_root_does_not_eject() {
    let server_keys = keys();
    let root = keys();
    let stranger = keys();
    let client_keys = keys();
    let store = store_with(&server_keys, 3);
    store
        .insert_entry(&key_revocation(&stranger, &hex_key(&client_keys.ed)))
        .unwrap();
    let network = permissioned(
        "gov-mesh",
        vec![hex_key(&client_keys.ed)],
        vec![hex_key(&root.ed)],
    );
    let addr = spawn(store, Some(network));

    let client = Store::open_in_memory().unwrap();
    let hello = sign_hello(&client_keys.ed, "gov-mesh");
    pull_and_merge(&addr.to_string(), &client, 500, Some(&hello)).unwrap();
}
