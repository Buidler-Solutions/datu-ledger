use crate::entry::parse_key;
use crate::error::{Error, Result};
use crate::merkle::{merkle_proof, merkle_root, merkle_root_from_proof};
use serde::{Deserialize, Serialize};
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

/// Offline-verifiable proof that a checkpoint's signer had *seen* an entry
/// id as of the checkpoint's claimed time: the Merkle path from the id to
/// the checkpoint's `entry_ids_root`.
///
/// The checkpoint proves the whole set; this path pins the one entry into
/// it. Together they are the witness time-attestation behind provable
/// landing windows and deadlines: anyone holding the pair can re-verify,
/// with zero other context, that the signer's ledger included the entry by
/// the checkpoint's timestamp. A single witness is one accountable clock;
/// independent witnesses compound into settlement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CoverageProof {
    /// Hex entry id being proven.
    pub entry_id: String,
    /// Position of the id in the checkpoint's sorted id set.
    pub index: u64,
    /// Size of that set (equal to the checkpoint's `entries_count`).
    pub count: u64,
    /// Sibling hashes from the leaf level upward (hex).
    pub siblings: Vec<String>,
}

impl CoverageProof {
    /// Build the proof for `entry_id` over exactly this id set (`None` when
    /// the id is not in the set). The set must be the one the checkpoint
    /// hashed: proofs over any other set reach a different root.
    pub fn build(items: &[[u8; 32]], entry_id: &[u8; 32]) -> Option<CoverageProof> {
        let mut sorted: Vec<[u8; 32]> = items.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let index = sorted.iter().position(|id| id == entry_id)?;
        let siblings = merkle_proof(items, entry_id)?
            .iter()
            .map(hex::encode)
            .collect();
        Some(CoverageProof {
            entry_id: hex::encode(entry_id),
            index: index as u64,
            count: sorted.len() as u64,
            siblings,
        })
    }

    /// Recompute the root this proof supports and compare it with the
    /// checkpoint's. Does not re-verify the checkpoint's signatures -
    /// verifiers call [`Checkpoint::verify`] first, then this.
    pub fn verify(&self, checkpoint: &Checkpoint) -> Result<()> {
        let malformed = |why: &str| Error::Encoding(why.to_string());
        let entry_id: [u8; 32] = hex::decode(&self.entry_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| malformed("proof entry_id is not a 32-byte hex id"))?;
        let siblings: Vec<[u8; 32]> = self
            .siblings
            .iter()
            .map(|sibling| {
                hex::decode(sibling)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| malformed("proof sibling is not a 32-byte hex hash"))
            })
            .collect::<Result<_>>()?;
        if self.count != checkpoint.body.entries_count {
            return Err(Error::Crypto(format!(
                "proof covers {} ids but the checkpoint covers {}",
                self.count, checkpoint.body.entries_count
            )));
        }
        let index = usize::try_from(self.index).map_err(|_| malformed("proof index out of range"))?;
        let count = usize::try_from(self.count).map_err(|_| malformed("proof count out of range"))?;
        let root = merkle_root_from_proof(&entry_id, index, count, &siblings)
            .ok_or_else(|| malformed("proof path does not describe that position"))?;
        if root != checkpoint.body.entry_ids_root {
            return Err(Error::Crypto(
                "the proof does not reach the checkpoint's entry_ids_root".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn signed_checkpoint(ids: &[[u8; 32]], timestamp_ms: u64) -> Checkpoint {
        let key = SigningKey::generate(&mut OsRng);
        let pq_key = pq::keypair().unwrap().1;
        let body = CheckpointBody {
            version: CHECKPOINT_VERSION,
            signer: String::new(),
            signer_pq: String::new(),
            pq_alg: String::new(),
            height: 0,
            prev: None,
            timestamp_ms,
            entries_count: ids.len() as u64,
            entry_ids_root: merkle_root(ids),
        };
        Checkpoint::sign(body, &key, &pq_key).unwrap()
    }

    fn ids(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8 + 1; 32]).collect()
    }

    #[test]
    fn coverage_proof_verifies_against_its_checkpoint() {
        let set = ids(7);
        let checkpoint = signed_checkpoint(&set, 1_000);
        checkpoint.verify().unwrap();
        assert_eq!(checkpoint.body.timestamp_ms, 1_000);
        for id in &set {
            let proof = CoverageProof::build(&set, id).unwrap();
            proof.verify(&checkpoint).unwrap();
        }
        assert!(CoverageProof::build(&set, &[99u8; 32]).is_none());
    }

    #[test]
    fn tampered_coverage_proofs_are_rejected() {
        let set = ids(7);
        let checkpoint = signed_checkpoint(&set, 1_000);
        let base = CoverageProof::build(&set, &set[3]).unwrap();

        let mut wrong_index = base.clone();
        wrong_index.index = 2;
        assert!(wrong_index.verify(&checkpoint).is_err());

        let mut wrong_sibling = base.clone();
        wrong_sibling.siblings[0] = "00".repeat(32);
        assert!(wrong_sibling.verify(&checkpoint).is_err());

        let mut wrong_count = base.clone();
        wrong_count.count = 6;
        assert!(wrong_count.verify(&checkpoint).is_err());

        let mut malformed = base;
        malformed.entry_id = "not hex".into();
        assert!(malformed.verify(&checkpoint).is_err());
    }
}
