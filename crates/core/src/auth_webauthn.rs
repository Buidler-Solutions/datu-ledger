//! SignetAuth Level 3a: WebAuthn (passkey) formats for a Synet-backed
//! virtual authenticator.
//!
//! A browser extension proxies `navigator.credentials` calls to the Signet
//! bridge; the bridge creates credentials and signs assertions with the
//! identity's Ed25519 key. Everything here is pure format work so the browser
//! side and the verifier side can be tested without a real authenticator:
//!
//! - Credential public key: COSE_Key, kty OKP (1), alg EdDSA (-8),
//!   crv Ed25519 (6), x = the raw 32-byte public key.
//! - authenticatorData: SHA-256(rp_id) || flags || signCount (u32 BE).
//! - Assertion signature: Ed25519 over authenticatorData || SHA-256(clientDataJSON).
//!
//! There is no attestation statement and no credential protection extension:
//! this is a synced-credential-grade authenticator whose root of trust is the
//! Signet vault (optionally gated by a device passkey in the panel).

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// COSE algorithm identifier for EdDSA (Ed25519).
pub const COSE_ALG_EDDSA: i64 = -8;
/// COSE key type for OKP (octet key pair).
pub const COSE_KTY_OKP: i64 = 1;
/// COSE curve identifier for Ed25519.
pub const COSE_CRV_ED25519: i64 = 6;
/// authenticatorData flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// authenticatorData flag: user verified (passphrase or biometric unlock).
pub const FLAG_UV: u8 = 0x04;

/// Encode a COSE_Key for an Ed25519 public key (CTAP2 canonical CBOR:
/// integer keys ascending, 1, 3, -1, -2).
pub fn cose_ed25519_pubkey(key: &VerifyingKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(42);
    out.push(0xa4); // map, 4 pairs
    out.extend_from_slice(&[0x01, 0x01]); // 1: 1   (kty OKP)
    out.extend_from_slice(&[0x03, 0x26]); // 3: -8  (alg EdDSA)
    out.extend_from_slice(&[0x20, 0x06]); // -1: 6  (crv Ed25519)
    out.extend_from_slice(&[0x21, 0x58, 0x20]); // -2: bytes(32)
    out.extend_from_slice(key.as_bytes());
    out
}

/// SHA-256, the hash WebAuthn uses for rp_id and clientDataJSON.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// authenticatorData: SHA-256(rp_id) || flags || signCount (u32 BE).
pub fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&sha256(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

/// What an authenticator returns for `navigator.credentials.get()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebauthnAssertion {
    /// authenticatorData bytes (browser base64-encodes them into PublicKeyCredential).
    pub authenticator_data: Vec<u8>,
    /// Ed25519 signature over authenticatorData || SHA-256(clientDataJSON).
    pub signature: [u8; 64],
}

/// Sign a WebAuthn assertion for one ceremony.
pub fn sign_webauthn_assertion(
    key: &SigningKey,
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    client_data_json: &[u8],
) -> WebauthnAssertion {
    let auth_data = authenticator_data(rp_id, flags, sign_count);
    let mut message = auth_data.clone();
    message.extend_from_slice(&sha256(client_data_json));
    let signature = key.sign(&message).to_bytes();
    WebauthnAssertion {
        authenticator_data: auth_data,
        signature,
    }
}

/// Verify an assertion the way a relying party's WebAuthn library does:
/// recompute SHA-256(clientDataJSON), check the rp_id hash inside
/// authenticatorData matches the RP, then verify the signature.
pub fn verify_webauthn_assertion(
    pubkey: &VerifyingKey,
    rp_id: &str,
    assertion: &WebauthnAssertion,
    client_data_json: &[u8],
) -> Result<()> {
    if assertion.authenticator_data.len() != 37 {
        return Err(Error::Crypto("authenticatorData must be 37 bytes".into()));
    }
    if assertion.authenticator_data[..32] != sha256(rp_id.as_bytes()) {
        return Err(Error::Crypto(
            "authenticatorData rpIdHash does not match rp_id".into(),
        ));
    }
    let flags = assertion.authenticator_data[32];
    if flags & FLAG_UP == 0 {
        return Err(Error::Crypto("user presence flag missing".into()));
    }
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&sha256(client_data_json));
    let sig = Signature::from_bytes(&assertion.signature);
    pubkey
        .verify(&message, &sig)
        .map_err(|e| Error::Crypto(format!("webauthn assertion invalid: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    const CLIENT_DATA: &[u8] =
        b"{\"type\":\"webauthn.get\",\"challenge\":\"AAECAwQFBgcICQoLDA0ODw\",\"origin\":\"https://app.example.com\"}";

    #[test]
    fn cose_key_shape() {
        let cose = cose_ed25519_pubkey(&key().verifying_key());
        assert_eq!(cose.len(), 42);
        assert_eq!(
            &cose[..8],
            &[0xa4, 0x01, 0x01, 0x03, 0x26, 0x20, 0x06, 0x21]
        );
        assert_eq!(&cose[8..10], &[0x58, 0x20]);
        assert_eq!(&cose[10..], key().verifying_key().as_bytes());
    }

    #[test]
    fn authenticator_data_layout() {
        let data = authenticator_data("app.example.com", FLAG_UP | FLAG_UV, 7);
        assert_eq!(data.len(), 37);
        assert_eq!(&data[..32], &sha256(b"app.example.com"));
        assert_eq!(data[32], FLAG_UP | FLAG_UV);
        assert_eq!(&data[33..], &7u32.to_be_bytes());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let k = key();
        let assertion =
            sign_webauthn_assertion(&k, "app.example.com", FLAG_UP | FLAG_UV, 1, CLIENT_DATA);
        verify_webauthn_assertion(
            &k.verifying_key(),
            "app.example.com",
            &assertion,
            CLIENT_DATA,
        )
        .unwrap();
    }

    #[test]
    fn wrong_rp_id_fails() {
        let k = key();
        let assertion = sign_webauthn_assertion(&k, "app.example.com", FLAG_UP, 1, CLIENT_DATA);
        assert!(verify_webauthn_assertion(
            &k.verifying_key(),
            "evil.example",
            &assertion,
            CLIENT_DATA
        )
        .is_err());
    }

    #[test]
    fn tampered_client_data_fails() {
        let k = key();
        let assertion = sign_webauthn_assertion(&k, "app.example.com", FLAG_UP, 1, CLIENT_DATA);
        let mut other = CLIENT_DATA.to_vec();
        other[10] ^= 1;
        assert!(verify_webauthn_assertion(
            &k.verifying_key(),
            "app.example.com",
            &assertion,
            &other
        )
        .is_err());
    }

    #[test]
    fn missing_user_presence_fails() {
        let k = key();
        let assertion = sign_webauthn_assertion(&k, "app.example.com", 0, 1, CLIENT_DATA);
        assert!(verify_webauthn_assertion(
            &k.verifying_key(),
            "app.example.com",
            &assertion,
            CLIENT_DATA
        )
        .is_err());
    }

    #[test]
    fn truncated_authenticator_data_fails() {
        let k = key();
        let assertion = WebauthnAssertion {
            authenticator_data: vec![0u8; 10],
            signature: [0u8; 64],
        };
        assert!(verify_webauthn_assertion(
            &k.verifying_key(),
            "app.example.com",
            &assertion,
            CLIENT_DATA
        )
        .is_err());
    }
}
