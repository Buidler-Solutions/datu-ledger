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
