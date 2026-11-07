use crate::entry::parse_key;
use crate::error::{Error, Result};
use crate::merkle::merkle_root;
use crate::pq;
use blake3;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier};
use fips204::traits::Signer as PqSigner;

/// Content address of a checkpoint: BLAKE3-256 over the canonical body.
pub type CheckpointId = [u8; 32];

pub const CHECKPOINT_VERSION: u8 = 1;

/// A node's signed statement of everything it has seen: the Merkle root over
/// the full set of entry ids. Checkpoints are chained per signer (`prev`).
///
/// Two checkpoints by the same signer that disagree, or a later history that
/// no longer matches an earlier checkpoint, are cryptographic proof of
/// tampering. Checkpoints are small enough to travel by any channel.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointBody {
    pub version: u8,
    /// Node identity: hex-encoded Ed25519 verifying key.
    pub signer: String,
    /// Node's post-quantum public key: hex-encoded ML-DSA-65.
    pub signer_pq: String,
    /// Post-quantum algorithm identifier ("mldsa65").
    pub pq_alg: String,
    /// Per-signer checkpoint index, starting at 0.
    pub height: u64,
    /// Id of this signer's previous checkpoint (None iff height == 0).
    pub prev: Option<CheckpointId>,
    /// Signer-claimed time, milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Number of entries covered by this checkpoint.
    pub entries_count: u64,
    /// Merkle root over the sorted set of covered entry ids.
    pub entry_ids_root: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub body: CheckpointBody,
    /// Ed25519 signature over the canonical borsh encoding of `body`.
    pub signature: [u8; 64],
    /// ML-DSA-65 (FIPS 204) signature over the same canonical bytes.
    pub pq_signature: Vec<u8>,
}

impl Checkpoint {
    pub fn body_bytes(body: &CheckpointBody) -> Result<Vec<u8>> {
        borsh::to_vec(body).map_err(|e| Error::Encoding(e.to_string()))
    }

    pub fn id(&self) -> Result<CheckpointId> {
        Ok(*blake3::hash(&Self::body_bytes(&self.body)?).as_bytes())
    }

    /// Hybrid-sign a checkpoint body with an Ed25519 key and an ML-DSA-65 key.
    pub fn sign(
        mut body: CheckpointBody,
        key: &SigningKey,
        pq_key: &pq::PqPrivateKey,
    ) -> Result<Checkpoint> {
        body.version = CHECKPOINT_VERSION;
        body.signer = hex::encode(key.verifying_key().as_bytes());
        body.signer_pq = pq::pk_to_hex(&pq_key.get_public_key());
        body.pq_alg = pq::PQ_ALG.to_string();
        let bytes = Self::body_bytes(&body)?;
        let signature = key.sign(&bytes).to_bytes();
        let pq_signature = pq::sign(pq_key, &bytes)?;
        Ok(Checkpoint {
            body,
            signature,
            pq_signature,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.body.version != CHECKPOINT_VERSION {
            return Err(Error::InvalidEntry(format!(
                "unsupported checkpoint version {}",
                self.body.version
            )));
        }
        if self.body.height == 0 && self.body.prev.is_some() {
            return Err(Error::Chain("height 0 must have prev = None".into()));
        }
        if self.body.height > 0 && self.body.prev.is_none() {
            return Err(Error::Chain(
                "checkpoints after height 0 must chain to the previous one".into(),
            ));
        }
        let bytes = Self::body_bytes(&self.body)?;

        let verifying_key = parse_key(&self.body.signer)?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|e| Error::Crypto(format!("bad signature: {e}")))?;

        pq::verify(&self.body.signer_pq, &self.body.pq_alg, &bytes, &self.pq_signature)?;

        Ok(())
    }

    pub fn root_for(entry_ids: &[[u8; 32]]) -> [u8; 32] {
        merkle_root(entry_ids)
    }
}
