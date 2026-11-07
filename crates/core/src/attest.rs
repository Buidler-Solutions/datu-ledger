//! Identity attestations: binding claims (legal name, role, institution) to
//! signing keys using plain ledger entries, plus N-of-M cosigning via causal
//! references - no new cryptography, no privileged registry.
//!
//! An institution runs `attest create` from its node: the entry's author is
//! the attestor, the payload names the subject key. Other parties cosign by
//! publishing a `identity.cosign` entry referencing the attestation id.
//! Anyone counting distinct cosign authors gets an N-of-M picture of how much
//! independent weight stands behind a key ↔ identity binding. Trust policies
//! (who counts, how many) stay with the verifier - the ledger only proves who
//! signed what.

use crate::entry::Entry;
use serde::{Deserialize, Serialize};

/// Namespace for key ↔ identity binding statements.
pub const NS_ATTEST: &str = "identity.attest";
/// Namespace for cosignatures over an attestation (entry refs the target id).
pub const NS_COSIGN: &str = "identity.cosign";

/// The payload document of an `identity.attest` entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttestationDoc {
    /// Attested subject: hex-encoded Ed25519 verifying key.
    pub subject: String,
    /// Optional human-readable subject name, e.g. "Acme Ltd".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Free-form claims object, e.g. {"legal_name":"Acme Ltd","role":"bidder"}.
    pub claims: serde_json::Value,
}

impl AttestationDoc {
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
}

/// The payload document of an `identity.cosign` entry.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CosignDoc {
    /// Hex id of the attestation being cosigned.
    pub attestation: String,
}

/// Parse an entry as an attestation; `None` if it is not one (wrong
/// namespace or malformed payload).
pub fn parse_attestation(entry: &Entry) -> Option<AttestationDoc> {
    if entry.body.namespace != NS_ATTEST {
        return None;
    }
    serde_json::from_slice(&entry.body.payload).ok()
}

/// Parse an entry as a cosignature; `None` if it is not one.
pub fn parse_cosign(entry: &Entry) -> Option<CosignDoc> {
    if entry.body.namespace != NS_COSIGN {
        return None;
    }
    serde_json::from_slice(&entry.body.payload).ok()
}

/// Every attestation about `subject`, oldest first, as (entry, doc) pairs.
/// Every returned entry has already been signature-verified by the store
/// that served it.
pub fn attestations_for<'a, I>(entries: I, subject: &str) -> Vec<(&'a Entry, AttestationDoc)>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let mut out = Vec::new();
    for entry in entries {
        if let Some(doc) = parse_attestation(entry) {
            if doc.subject == subject {
                out.push((entry, doc));
            }
        }
    }
    out
}

/// Distinct cosigners of `attestation_id`: entries in `identity.cosign`
/// whose causal refs include the attestation id. One entry per author
/// (first wins); a doc naming a different attestation is not counted even
/// if the ref is present.
pub fn cosigners_for<'a, I>(entries: I, attestation_id: &[u8; 32]) -> Vec<(&'a Entry, CosignDoc)>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let id_hex = hex::encode(attestation_id);
    let mut out: Vec<(&'a Entry, CosignDoc)> = Vec::new();
    for entry in entries {
        if !entry.body.refs.iter().any(|r| r == attestation_id) {
            continue;
        }
        if let Some(doc) = parse_cosign(entry) {
            if doc.attestation != id_hex {
                continue;
            }
            if !out.iter().any(|(e, _)| e.body.author == entry.body.author) {
                out.push((entry, doc));
            }
        }
    }
    out
}
