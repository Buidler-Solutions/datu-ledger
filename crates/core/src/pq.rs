//! Post-quantum signatures: ML-DSA-65 (FIPS 204, final standard).
//!
//! Every record in this system is *hybrid signed*: an Ed25519 signature
//! (small, fast, battle-tested) AND an ML-DSA-65 signature (resistant to
//! Shor's algorithm on quantum computers). Both must verify. A record that
//! survives decades must survive both threat models.

use crate::error::{Error, Result};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as PqSigner, Verifier};

pub const PQ_ALG: &str = "mldsa65";
pub const PK_LEN: usize = ml_dsa_65::PK_LEN;
pub const SK_LEN: usize = ml_dsa_65::SK_LEN;
pub const SIG_LEN: usize = ml_dsa_65::SIG_LEN;

pub type PqPublicKey = ml_dsa_65::PublicKey;
pub type PqPrivateKey = ml_dsa_65::PrivateKey;

pub fn keypair() -> Result<(PqPublicKey, PqPrivateKey)> {
    ml_dsa_65::try_keygen()
        .map_err(|e| Error::Crypto(format!("ml-dsa-65 keygen failed: {e}")))
}

pub fn pk_to_hex(pk: &PqPublicKey) -> String {
    hex::encode(pk.clone().into_bytes())
}

pub fn sk_to_hex(sk: &PqPrivateKey) -> String {
    hex::encode(sk.clone().into_bytes())
}

pub fn pk_from_hex(s: &str) -> Result<PqPublicKey> {
    let bytes =
        hex::decode(s).map_err(|e| Error::Crypto(format!("bad pq key hex: {e}")))?;
    let arr: [u8; PK_LEN] = bytes.try_into().map_err(|_| {
        Error::Crypto(format!("ml-dsa-65 public key must be {PK_LEN} bytes"))
    })?;
    PqPublicKey::try_from_bytes(arr)
        .map_err(|e| Error::Crypto(format!("bad ml-dsa-65 public key: {e}")))
}

pub fn sk_from_hex(s: &str) -> Result<PqPrivateKey> {
    let bytes =
        hex::decode(s).map_err(|e| Error::Crypto(format!("bad pq key hex: {e}")))?;
    let arr: [u8; SK_LEN] = bytes.try_into().map_err(|_| {
        Error::Crypto(format!("ml-dsa-65 secret key must be {SK_LEN} bytes"))
    })?;
    PqPrivateKey::try_from_bytes(arr)
        .map_err(|e| Error::Crypto(format!("bad ml-dsa-65 secret key: {e}")))
}

pub fn sign(sk: &PqPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let sig = sk
        .try_sign(msg, &[])
        .map_err(|e| Error::Crypto(format!("ml-dsa-65 signing failed: {e}")))?;
    Ok(sig.to_vec())
}

pub fn verify(pk_hex: &str, alg: &str, msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    if alg != PQ_ALG {
        return Err(Error::Crypto(format!(
            "unsupported post-quantum algorithm '{alg}' (expected {PQ_ALG})"
        )));
    }
    let pk = pk_from_hex(pk_hex)?;
    let arr: [u8; SIG_LEN] = sig_bytes.try_into().map_err(|_| {
        Error::Crypto(format!("ml-dsa-65 signature must be {SIG_LEN} bytes"))
    })?;
    if pk.verify(msg, &arr, &[]) {
        Ok(())
    } else {
        Err(Error::Crypto(
            "post-quantum signature verification failed".into(),
        ))
    }
}
