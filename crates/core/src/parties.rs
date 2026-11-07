//! Party signatures: the people a record is *about* must sign it.
//!
//! A land-title application is not valid on the say-so of the registrar
//! alone - the holder (the citizen the title belongs to) must consent, and
//! the citizen owns that consent: it is made with the citizen's own keys
//! (typically from their wallet), not the institution's.
//!
//! A [`SignedDocument`] wraps the document plus one signature per party,
//! each binding `(v, kind, doc, role, key)`:
//!
//! - `role` - what this party is in the transaction ("holder", "registrar",
//!   "witness", ...), so a signature cannot be replayed into another role;
//! - `key` - the party's Ed25519 verifying key, so a signature cannot be
//!   replayed onto another party;
//! - Ed25519 is mandatory; ML-DSA-65 is optional but is the wallet default,
//!   making party consent quantum-resistant like everything else.
//!
//! The wrapped document is what a gated namespace publishes as the entry
//! payload (canonical JSON). The entry author remains accountable for the
//! record; the party signatures prove the affected parties saw and approved
//! *this exact document*.

use crate::entry::parse_key;
use crate::error::{Error, Result};
use crate::pq;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier};
use fips204::traits::Signer as PqSigner;
use serde::{Deserialize, Serialize};

pub const PARTIES_VERSION: u8 = 1;

/// One party's consent over a document.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PartySignature {
    /// This party's role in the transaction, e.g. "holder", "registrar".
    pub role: String,
    /// Party identity: hex Ed25519 verifying key.
    pub key: String,
    /// Ed25519 signature over the document digest (hex).
    pub ed_signature: String,
    /// Party ML-DSA-65 public key (hex), present iff `pq_signature` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_key: Option<String>,
    /// ML-DSA-65 signature over the same digest (base64), if provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_alg: Option<String>,
    pub timestamp_ms: u64,
}

/// A document with the consent of every party it concerns.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SignedDocument {
    pub v: u8,
    /// What kind of transaction this is, e.g. "land.title.application".
    pub kind: String,
    /// The transaction document itself (any JSON object).
    pub doc: serde_json::Value,
    pub parties: Vec<PartySignature>,
}

impl SignedDocument {
    pub fn new(kind: &str, doc: serde_json::Value) -> SignedDocument {
        SignedDocument {
            v: PARTIES_VERSION,
            kind: kind.to_string(),
            doc,
            parties: Vec::new(),
        }
    }

    /// The digest a party with `role` and `key` signs: BLAKE3-256 over the
    /// canonical JSON of `(v, kind, doc, role, key)`. `serde_json` maps are
    /// BTree-ordered, so the encoding is deterministic.
    pub fn digest(&self, role: &str, key: &str) -> Result<[u8; 32]> {
        let canonical = serde_json::json!({
            "v": self.v,
            "kind": self.kind,
            "doc": self.doc,
            "role": role,
            "key": key,
        });
        let bytes =
            serde_json::to_vec(&canonical).map_err(|e| Error::Encoding(e.to_string()))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Sign as the party identified by `key` in `role`. Ed25519 always;
    /// ML-DSA-65 too when a PQ key is given. Re-signing a role replaces the
    /// previous signature.
    pub fn sign(
        &mut self,
        role: &str,
        key: &SigningKey,
        pq_key: Option<&pq::PqPrivateKey>,
    ) -> Result<()> {
        let key_hex = hex::encode(key.verifying_key().as_bytes());
        let digest = self.digest(role, &key_hex)?;
        let ed_signature = hex::encode(key.sign(&digest).to_bytes());
        let (pq_key_hex, pq_signature, pq_alg) = match pq_key {
            Some(sk) => (
                Some(pq::pk_to_hex(&sk.get_public_key())),
                Some(B64.encode(pq::sign(sk, &digest)?)),
                Some(pq::PQ_ALG.to_string()),
            ),
            None => (None, None, None),
        };
        self.parties.retain(|p| p.role != role);
        self.parties.push(PartySignature {
            role: role.to_string(),
            key: key_hex,
            ed_signature,
            pq_key: pq_key_hex,
            pq_signature,
            pq_alg,
            timestamp_ms: now_ms(),
        });
        Ok(())
    }

    /// Verify every party signature (Ed25519 mandatory, ML-DSA-65 when
    /// present). Returns the verified `(role, key)` pairs, or the first
    /// failure.
    pub fn verify(&self) -> Result<Vec<(String, String)>> {
        if self.v != PARTIES_VERSION {
            return Err(Error::InvalidEntry(format!(
                "unsupported signed-document version {}",
                self.v
            )));
        }
        let mut out = Vec::with_capacity(self.parties.len());
        for party in &self.parties {
            let vk = parse_key(&party.key)?;
            let digest = self.digest(&party.role, &party.key)?;
            let sig_bytes = hex::decode(&party.ed_signature)
                .map_err(|_| Error::Crypto("party signature must be hex".into()))?;
            let sig: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| Error::Crypto("ed25519 signature must be 64 bytes".into()))?;
            vk.verify(&digest, &Signature::from_bytes(&sig))
                .map_err(|_| Error::Crypto(format!(
                    "party signature for role '{}' does not verify",
                    party.role
                )))?;
            if let (Some(sig_b64), Some(pq_key)) = (&party.pq_signature, &party.pq_key) {
                let alg = party.pq_alg.as_deref().unwrap_or("");
                let sig = B64
                    .decode(sig_b64)
                    .map_err(|_| Error::Crypto("bad party pq signature encoding".into()))?;
                pq::verify(pq_key, alg, &digest, &sig)?;
            } else if party.pq_signature.is_some() || party.pq_key.is_some() {
                return Err(Error::Crypto(
                    "party pq signature and pq key must be present together".into(),
                ));
            }
            out.push((party.role.clone(), party.key.clone()));
        }
        Ok(out)
    }

    /// Does this document carry a *verified* signature for `role`?
    pub fn has_verified_role(&self, role: &str) -> bool {
        self.verify()
            .map(|roles| roles.iter().any(|(r, _)| r == role))
            .unwrap_or(false)
    }

    /// Canonical JSON payload bytes for an entry.
    pub fn payload_bytes(&self) -> std::result::Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    /// Parse entry payload bytes as a signed document; `None` if it is not
    /// one (wrong shape or malformed JSON).
    pub fn from_payload(payload: &[u8]) -> Option<SignedDocument> {
        serde_json::from_slice(payload).ok()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
