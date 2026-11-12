use crate::error::{Error, Result};
use crate::pq;
use blake3;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier, VerifyingKey};
use fips204::traits::Signer as PqSigner;

/// Content address of an entry: BLAKE3-256 over the canonical (borsh) body.
pub type EntryId = [u8; 32];

pub const ENTRY_VERSION: u8 = 1;

pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// The signed, canonically-encoded body of a ledger entry.
///
/// Immutability: the entry id is derived from these exact bytes, the author's
/// hybrid signature (Ed25519 + ML-DSA-65) covers these exact bytes, and
/// `prev` chains to the id of the previous entry in the author's feed. Any
/// mutation changes the id, breaks both signatures, and orphans every
/// subsequent entry.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct EntryBody {
    pub version: u8,
    /// Author identity: hex-encoded Ed25519 verifying key.
    pub author: String,
    /// Author's post-quantum public key: hex-encoded ML-DSA-65.
    pub author_pq: String,
    /// Post-quantum algorithm identifier ("mldsa65").
    pub pq_alg: String,
    /// Logical namespace, e.g. "gov.records", "audit.claims".
    pub namespace: String,
    /// Per-author monotonically increasing sequence, starting at 0.
    pub seq: u64,
    /// Id of the previous entry in this author's feed (None iff seq == 0).
    pub prev: Option<EntryId>,
    /// Causal references to other entries: the DAG edges.
    pub refs: Vec<EntryId>,
    /// Author-claimed creation time (milliseconds since Unix epoch). A claim,
    /// not truth; provable ordering comes only from `prev`/`refs`.
    pub timestamp_ms: u64,
    /// Opaque payload bytes (typically UTF-8 JSON).
    pub payload: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub body: EntryBody,
    /// Ed25519 signature over the canonical borsh encoding of `body`.
    pub signature: [u8; 64],
    /// ML-DSA-65 (FIPS 204) signature over the same canonical bytes.
    pub pq_signature: Vec<u8>,
}

pub fn parse_key(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str).map_err(|e| Error::Crypto(format!("bad key hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Crypto("key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::Crypto(format!("bad key: {e}")))
}

fn valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 64
        && ns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

impl Entry {
    pub fn body_bytes(body: &EntryBody) -> Result<Vec<u8>> {
        borsh::to_vec(body).map_err(|e| Error::Encoding(e.to_string()))
    }

    pub fn id(&self) -> Result<EntryId> {
        Ok(*blake3::hash(&Self::body_bytes(&self.body)?).as_bytes())
    }

    /// Hybrid-sign a body with an Ed25519 key and an ML-DSA-65 key; stamps
    /// version, author and author_pq from the keys.
    pub fn sign(mut body: EntryBody, key: &SigningKey, pq_key: &pq::PqPrivateKey) -> Result<Entry> {
        body.version = ENTRY_VERSION;
        body.author = hex::encode(key.verifying_key().as_bytes());
        body.author_pq = pq::pk_to_hex(&pq_key.get_public_key());
        body.pq_alg = pq::PQ_ALG.to_string();
        let bytes = Self::body_bytes(&body)?;
        let signature = key.sign(&bytes).to_bytes();
        let pq_signature = pq::sign(pq_key, &bytes)?;
        Ok(Entry {
            body,
            signature,
            pq_signature,
        })
    }

    /// Full self-contained verification: version, namespace shape, chain
    /// invariants, and BOTH signatures over the canonical bytes.
    pub fn verify(&self) -> Result<()> {
        if self.body.version != ENTRY_VERSION {
            return Err(Error::InvalidEntry(format!(
                "unsupported version {}",
                self.body.version
            )));
        }
        if !valid_namespace(&self.body.namespace) {
            return Err(Error::InvalidEntry(
                "namespace must be 1-64 chars of [a-z0-9.-]".into(),
            ));
        }
        if self.body.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidEntry("payload exceeds size limit".into()));
        }
        if self.body.seq == 0 && self.body.prev.is_some() {
            return Err(Error::Chain(
                "first entry (seq 0) must have prev = None".into(),
            ));
        }
        if self.body.seq > 0 && self.body.prev.is_none() {
            return Err(Error::Chain(
                "entries after seq 0 must reference the previous entry".into(),
            ));
        }
        let bytes = Self::body_bytes(&self.body)?;

        let verifying_key = parse_key(&self.body.author)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|e| Error::Crypto(format!("bad signature: {e}")))?;

        pq::verify(
            &self.body.author_pq,
            &self.body.pq_alg,
            &bytes,
            &self.pq_signature,
        )?;

        Ok(())
    }
}
