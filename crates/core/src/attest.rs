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
/// Namespace for revocations of attestations (a revoke names the attestation
/// id it kills; entries are append-only, so revocation is a new statement,
/// never an edit).
pub const NS_REVOKE: &str = "identity.revoke";

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

/// The payload document of an `identity.revoke` entry: it revokes exactly
/// the attestation it names. Revoking is a verifier-side act: only
/// revocations authored by a *configured* attestor count, and only for the
/// node whose configuration names that attestor. The ledger stores the
/// statement; trust policy decides its weight.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokeDoc {
    /// Hex id of the attestation being revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// Hex subject key revoked directly: the ejection path for explicit
    /// `members`/`writers` keys that hold no attestation to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Optional human-readable reason (shows in `attest status`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RevokeDoc {
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
}

/// Parse an entry as a revocation; `None` if it is not one.
pub fn parse_revoke(entry: &Entry) -> Option<RevokeDoc> {
    if entry.body.namespace != NS_REVOKE {
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

/// Every revocation naming `attestation_id`, whatever its author (display
/// surface for `attest status`; admission uses [`revoked_by`]).
pub fn revocations_for<'a, I>(entries: I, attestation_id: &[u8; 32]) -> Vec<(&'a Entry, RevokeDoc)>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let id_hex = hex::encode(attestation_id);
    let mut out = Vec::new();
    for entry in entries {
        if let Some(doc) = parse_revoke(entry) {
            if doc.attestation.as_deref() == Some(id_hex.as_str()) {
                out.push((entry, doc));
            }
        }
    }
    out
}

/// The set of attestation ids revoked by *trusted* revokers: revoke entries
/// whose author is one of `attestors` (the verifier's configured roots).
/// A revocation from anyone else is ledger content without effect - the
/// same stance as attestations themselves. Malformed ids revoke nothing.
/// Set membership is order-independent: a revoke counts whenever it is
/// present, so every node converges on the same verdict after sync.
pub fn revoked_by<'a, I>(entries: I, attestors: &[String]) -> std::collections::BTreeSet<[u8; 32]>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let mut revoked = std::collections::BTreeSet::new();
    for entry in entries {
        if !attestors.contains(&entry.body.author) {
            continue;
        }
        if let Some(doc) = parse_revoke(entry) {
            if let Some(attestation) = &doc.attestation {
                if let Ok(bytes) = hex::decode(attestation) {
                    if let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        revoked.insert(id);
                    }
                }
            }
        }
    }
    revoked
}

/// Subject keys (lowercase hex) revoked directly by trusted revokers: the
/// ejection path for explicit `members`/`writers` keys, which hold no
/// attestation for [`revoked_by`] to name. Same trust stance - only
/// revocations authored by a configured root count.
pub fn revoked_keys_by<'a, I>(
    entries: I,
    attestors: &[String],
) -> std::collections::BTreeSet<String>
where
    I: IntoIterator<Item = &'a Entry>,
{
    let mut revoked = std::collections::BTreeSet::new();
    for entry in entries {
        if !attestors.contains(&entry.body.author) {
            continue;
        }
        if let Some(doc) = parse_revoke(entry) {
            if let Some(subject) = &doc.subject {
                revoked.insert(subject.to_lowercase());
            }
        }
    }
    revoked
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn signed(
        ns: &str,
        payload: &[u8],
        key: &SigningKey,
        pq: &crate::pq::PqPrivateKey,
        seq: u64,
    ) -> Entry {
        let body = crate::EntryBody {
            version: crate::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: ns.to_string(),
            seq,
            prev: None,
            refs: vec![],
            timestamp_ms: 1,
            payload: payload.to_vec(),
        };
        Entry::sign(body, key, pq).unwrap()
    }

    #[test]
    fn revoked_by_counts_only_trusted_revokers_with_valid_ids() {
        let root = SigningKey::generate(&mut OsRng);
        let root_pq = crate::pq::keypair().unwrap().1;
        let stranger = SigningKey::generate(&mut OsRng);
        let stranger_pq = crate::pq::keypair().unwrap().1;
        let trusted = vec![hex::encode(root.verifying_key().as_bytes())];

        let revoked_id = [7u8; 32];
        let other_id = [9u8; 32];
        let good = RevokeDoc {
            attestation: Some(hex::encode(revoked_id)),
            subject: None,
            reason: None,
        }
        .payload_bytes()
        .unwrap();
        let untrusted = RevokeDoc {
            attestation: Some(hex::encode(other_id)),
            subject: None,
            reason: None,
        }
        .payload_bytes()
        .unwrap();
        let malformed = RevokeDoc {
            attestation: Some("not hex".into()),
            subject: None,
            reason: None,
        }
        .payload_bytes()
        .unwrap();

        let entries = vec![
            signed(NS_REVOKE, &good, &root, &root_pq, 0),
            signed(NS_REVOKE, &untrusted, &stranger, &stranger_pq, 0),
            signed(NS_REVOKE, &malformed, &root, &root_pq, 1),
        ];
        let revoked = revoked_by(entries.iter(), &trusted);
        assert!(revoked.contains(&revoked_id));
        assert!(
            !revoked.contains(&other_id),
            "untrusted revokers do not count"
        );
        assert_eq!(revoked.len(), 1, "malformed ids revoke nothing");
    }

    #[test]
    fn revoked_keys_count_only_trusted_revokers() {
        let root = SigningKey::generate(&mut OsRng);
        let root_pq = crate::pq::keypair().unwrap().1;
        let stranger = SigningKey::generate(&mut OsRng);
        let stranger_pq = crate::pq::keypair().unwrap().1;
        let trusted = vec![hex::encode(root.verifying_key().as_bytes())];
        let subject = hex::encode([3u8; 32]).to_uppercase(); // case-insensitive

        let make = |subject: &str| {
            RevokeDoc {
                attestation: None,
                subject: Some(subject.to_string()),
                reason: Some("ejected".into()),
            }
            .payload_bytes()
            .unwrap()
        };
        let entries = vec![
            signed(NS_REVOKE, &make(&subject), &root, &root_pq, 0),
            signed(
                NS_REVOKE,
                &make(&hex::encode([4u8; 32])),
                &stranger,
                &stranger_pq,
                0,
            ),
        ];
        let revoked = revoked_keys_by(entries.iter(), &trusted);
        assert!(revoked.contains(&hex::encode([3u8; 32])));
        assert!(
            !revoked.contains(&hex::encode([4u8; 32])),
            "untrusted revokers do not count"
        );
        assert_eq!(revoked.len(), 1);
    }

    #[test]
    fn revoke_doc_roundtrips() {
        let doc = RevokeDoc {
            attestation: Some("ab".repeat(32)),
            subject: None,
            reason: Some("rotated".into()),
        };
        let parsed: RevokeDoc = serde_json::from_slice(&doc.payload_bytes().unwrap()).unwrap();
        assert_eq!(parsed, doc);
    }
}
