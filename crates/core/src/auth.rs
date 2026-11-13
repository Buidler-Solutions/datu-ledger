//! SignetAuth Level 1: domain-separated challenge-response login assertions.
//!
//! An `AuthAssertion` is an Ed25519 signature over a canonical, prefixed byte
//! string, never over a ledger structure. The `datu-auth-v1` domain prefix
//! guarantees an auth assertion can never be confused with (or replayed as) an
//! entry, checkpoint, or party signature, all of which sign borsh encodings or
//! blake3 digests of ledger types.
//!
//! Wire shape (the canonical signed bytes):
//! `datu-auth-v1\n<rp_id>\n<origin>\n<nonce_hex>\n<expires_at_ms>\n`

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Domain-separation prefix for every SignetAuth assertion.
pub const AUTH_DOMAIN: &str = "datu-auth-v1";
/// Nonces are 128 bits, hex-encoded (32 chars) on the wire.
pub const NONCE_BYTES: usize = 16;
/// Default challenge lifetime. Relying parties should reject anything older.
pub const DEFAULT_CHALLENGE_TTL_MS: u64 = 60_000;

/// The signed challenge material. `nonce` is raw bytes on this struct;
/// hex only on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthChallenge {
    /// Relying party identifier, e.g. "app.example.com" (the WebAuthn rp_id analogue).
    pub rp_id: String,
    /// Exact origin the requesting page ran on, e.g. "https://app.example.com".
    pub origin: String,
    /// Single-use random nonce issued by the relying party.
    pub nonce: [u8; NONCE_BYTES],
    /// Expiry of the challenge (milliseconds since Unix epoch).
    pub expires_at_ms: u64,
}

impl AuthChallenge {
    /// Canonical signed bytes with the domain prefix.
    pub fn to_signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.rp_id.len() + self.origin.len());
        out.extend_from_slice(AUTH_DOMAIN.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.rp_id.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.origin.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(hex::encode(self.nonce).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.expires_at_ms.to_string().as_bytes());
        out.push(b'\n');
        out
    }

    /// Whether the challenge is still valid at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }
}

/// Sign arbitrary bytes with an Ed25519 key (Level 1 primitive; auth is the
/// first consumer). Not restricted to auth: intentionally exported for FFI.
pub fn sign_bytes(key: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    key.sign(bytes).to_bytes()
}

/// Produce a SignetAuth assertion: Ed25519 over the canonical challenge bytes.
pub fn sign_assertion(key: &SigningKey, challenge: &AuthChallenge) -> [u8; 64] {
    sign_bytes(key, &challenge.to_signed_bytes())
}

/// Verify a SignetAuth assertion against an identity key and a challenge.
///
/// The relying party supplies the challenge it issued; this checks only the
/// signature. Single-use nonce tracking and `expires_at_ms` freshness against
/// the RP's own clock are the relying party's bookkeeping (`is_live` helps).
pub fn verify_assertion(
    pubkey: &VerifyingKey,
    challenge: &AuthChallenge,
    signature: &[u8; 64],
) -> Result<()> {
    let sig = Signature::from_bytes(signature);
    pubkey
        .verify(&challenge.to_signed_bytes(), &sig)
        .map_err(|e| Error::Crypto(format!("auth assertion invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn challenge() -> AuthChallenge {
        AuthChallenge {
            rp_id: "app.example.com".into(),
            origin: "https://app.example.com".into(),
            nonce: [0x42u8; NONCE_BYTES],
            expires_at_ms: 1_800_000_000_000,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let ch = challenge();
        let sig = sign_assertion(&key, &ch);
        verify_assertion(&key.verifying_key(), &ch, &sig).unwrap();
    }

    #[test]
    fn wrong_key_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let sig = sign_assertion(&key, &challenge());
        assert!(verify_assertion(&other.verifying_key(), &challenge(), &sig).is_err());
    }

    #[test]
    fn tampered_challenge_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sign_assertion(&key, &challenge());
        let mut ch = challenge();
        ch.nonce = [0x00u8; NONCE_BYTES];
        assert!(verify_assertion(&key.verifying_key(), &ch, &sig).is_err());
    }

    #[test]
    fn tampered_origin_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sign_assertion(&key, &challenge());
        let mut ch = challenge();
        ch.origin = "https://evil.example".into();
        assert!(verify_assertion(&key.verifying_key(), &ch, &sig).is_err());
    }

    #[test]
    fn tampered_rp_id_fails() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sign_assertion(&key, &challenge());
        let mut ch = challenge();
        ch.rp_id = "evil.example".into();
        assert!(verify_assertion(&key.verifying_key(), &ch, &sig).is_err());
    }

    #[test]
    fn domain_prefix_present_and_deterministic() {
        let ch = challenge();
        let bytes = ch.to_signed_bytes();
        assert!(bytes.starts_with(b"datu-auth-v1\n"));
        assert_eq!(bytes, ch.to_signed_bytes());
    }

    #[test]
    fn liveness_window() {
        let mut ch = challenge();
        ch.expires_at_ms = 1_000;
        assert!(ch.is_live(999));
        assert!(!ch.is_live(1_000));
    }

    #[test]
    fn distinct_from_ledger_signatures() {
        // A signature over raw entry-like bytes must not verify as an auth
        // assertion and vice versa: the domain prefix guarantees disjoint
        // signed-message spaces.
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let ch = challenge();
        let raw_sig = sign_bytes(&key, b"some borsh entry bytes");
        assert!(verify_assertion(&key.verifying_key(), &ch, &raw_sig).is_err());
        let auth_sig = sign_assertion(&key, &ch);
        let sig = Signature::from_bytes(&auth_sig);
        assert!(key
            .verifying_key()
            .verify(b"some borsh entry bytes", &sig)
            .is_err());
    }
}
