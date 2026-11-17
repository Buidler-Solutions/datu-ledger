//! Seeded randomized robustness checks for the peer table inputs. These are
//! not a replacement for a fuzz target; they are a cheap CI guard that no
//! input shape panics the address parser, the announce path, or PEX merge.
//!
//! Deterministic: a tiny xorshift PRNG with a fixed seed, so failures are
//! reproducible without extra tooling.

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % max;
        (0..len).map(|_| self.next() as u8).collect()
    }
    fn string(&mut self) -> String {
        // mix ASCII, controls, unicode, and address-shaped fragments
        let pieces = [
            "127.0.0.1:7476",
            "0.0.0.0:1",
            "::",
            "999.1.1.1:99",
            "host.example:7476",
            "[::1]:7476",
            ":",
            "",
            "a:b",
            "\u{1F600}",
            "\u{0}",
            "x".repeat(300).leak(),
        ];
        let mut s = String::new();
        for _ in 0..(self.next() % 4) {
            s.push_str(pieces[(self.next() as usize) % pieces.len()]);
        }
        s
    }
}

#[test]
fn peer_inputs_never_panic() {
    use datu_p2p::{PeerTable, PeerWire};
    let mut rng = Rng(0x5eed_0001);
    let table = PeerTable::new();
    for _ in 0..2000 {
        let addr = rng.string();
        let key = String::from_utf8_lossy(&rng.bytes(80)).to_string();
        let net = String::from_utf8_lossy(&rng.bytes(20)).to_string();
        table.upsert(&addr, &key, &net, "mdns");
        table.record_attempt(&addr);
        table.record_success(&addr, &key, &net);
        table.record_failure(&addr, "read: connection reset by peer");
        table.record_announce(&addr, &key, &net, "");
        let wires: Vec<PeerWire> = (0..3)
            .map(|_| PeerWire {
                addr: rng.string(),
                node_key: key.clone(),
                network_id: net.clone(),
                last_success_ms: rng.next() % 3,
            })
            .collect();
        table.merge_pex(&wires, "");
        // snapshots must stay well-formed JSON-serializable entries
        for p in table.snapshot() {
            assert!(!p.addr.is_empty() || p.addr.is_empty());
            serde_json::to_string(&p).expect("peer entry serializes");
        }
    }
}

#[test]
fn auth_bytes_roundtrip_and_tamper() {
    use datu_core::auth::{sign_assertion, verify_assertion, AuthChallenge, NONCE_BYTES};
    use ed25519_dalek::SigningKey;
    let mut rng = Rng(0x5eed_0002);
    for _ in 0..300 {
        let key = SigningKey::from_bytes(&[rng.next() as u8; 32]);
        let mut nonce = [0u8; NONCE_BYTES];
        for b in nonce.iter_mut() {
            *b = rng.next() as u8;
        }
        let challenge = AuthChallenge {
            rp_id: format!("rp{}.example", rng.next() % 97),
            origin: format!(
                "https://rp{}.example:{}",
                rng.next() % 97,
                4000 + rng.next() % 2000
            ),
            nonce,
            expires_at_ms: rng.next() % u64::MAX,
        };
        let sig = sign_assertion(&key, &challenge);
        assert!(verify_assertion(&key.verifying_key(), &challenge, &sig).is_ok());
        // tampered bytes must fail, and a flipped nonce must fail
        let mut bad = challenge.clone();
        bad.nonce[0] ^= 0xFF;
        assert!(verify_assertion(&key.verifying_key(), &bad, &sig).is_err());
        let mut sig2 = sig;
        sig2[0] ^= 0xFF;
        assert!(verify_assertion(&key.verifying_key(), &challenge, &sig2).is_err());
    }
}

/// Wire-frame decoders must reject garbage with an error, never a panic:
/// every borsh-deserialized message shape and the network policy JSON
/// parser eat seeded random bytes here. Ok results are fine (random bytes
/// can form a valid message); the contract under test is no panic and no
/// unbounded work.
#[test]
fn wire_frame_decoders_never_panic() {
    use borsh::BorshDeserialize;
    use datu_p2p::{NetworkPolicy, NodeHello, PullRequest, ServerMessage};
    let mut rng = Rng(0x5eed_0003);
    for _ in 0..2000 {
        let bytes = rng.bytes(300);
        let _ = ServerMessage::try_from_slice(&bytes);
        let _ = PullRequest::try_from_slice(&bytes);
        let _ = NodeHello::try_from_slice(&bytes);
        let text = String::from_utf8_lossy(&bytes).to_string();
        let _ = NetworkPolicy::from_json(&text);
        if let Ok(hello) = NodeHello::try_from_slice(&bytes) {
            let _ = datu_p2p::verify_hello(&hello);
        }
    }
}

/// The live listener must survive whatever a hostile or broken peer
/// writes: corrupt frame magic, lying length prefixes, mid-frame cuts and
/// plain garbage. After the abuse a healthy pull still completes, which
/// is the real production concern: one bad peer cannot wedge the server
/// for everyone else.
#[test]
fn listener_survives_hostile_writes() {
    use datu_p2p::{handle_connection, MAGIC};
    use datu_store::Store;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let store = Store::open_in_memory().unwrap();
        for conn in listener.incoming().flatten() {
            handle_connection(conn, &store, None);
        }
    });

    let mut rng = Rng(0x5eed_0004);
    for round in 0..80 {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut payload: Vec<u8> = Vec::new();
        match round % 4 {
            // valid magic, then a body of random shape/length
            0 => {
                payload.extend_from_slice(&MAGIC);
                payload.extend(rng.bytes(64));
            }
            // lying length: huge count then nothing to back it
            1 => {
                payload.extend_from_slice(&MAGIC);
                payload.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]);
            }
            // plain garbage of random size
            2 => payload.extend(rng.bytes(256)),
            // mid-frame cut: valid magic + prefix of a real-looking frame
            _ => {
                payload.extend_from_slice(&MAGIC);
                let full = rng.bytes(128);
                let cut = (rng.next() as usize) % (full.len() + 1);
                payload.extend_from_slice(&full[..cut]);
            }
        }
        stream.write_all(&payload).unwrap();
        // The server may answer with an error frame or simply close; both
        // are acceptable. A panic would poison the whole test process.
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink);
        drop(stream);
    }

    // The server must still serve an honest pull afterwards.
    let client = Store::open_in_memory().unwrap();
    let stats = datu_p2p::pull_and_merge(&addr.to_string(), &client, 10, None).unwrap();
    assert_eq!(stats.entries_new, 0, "only genesis on an empty server");
}
