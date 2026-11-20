//! Two-signature enrollment: the ceremony that turns a raw key into an
//! attested member without the registry ever holding the citizen's key.
//!
//! The rule the ceremony enforces: **keys are born on the citizen device,
//! the registry only attests.** A registry cannot enroll a key it created
//! for someone, and cannot enroll a key whose owner never took part - the
//! subject must sign the enrollment document with the very key being
//! enrolled, so a "ghost" (a key the named person does not control) cannot
//! complete the ceremony.
//!
//! The ceremony rides on [`SignedDocument`] (party signatures), no new
//! cryptography:
//!
//! 1. `enroll open` - the registry builds the document (subject key, label,
//!    claims) and signs it as party `registrar`;
//! 2. `enroll accept` - the citizen signs the same document as party
//!    `subject`, which only verifies if their key is the subject key;
//! 3. `enroll approve` - the registry verifies both signatures and publishes
//!    an `identity.enroll` record (the ceremony evidence) plus the
//!    `identity.attest` entry that writer policy consumes, causally bound
//!    to the ceremony record.
//!
//! Verifiers never trust an `identity.enroll` entry without verifying its
//! party signatures - the record is evidence of consent, not authority.

use crate::entry::Entry;
use crate::parties::SignedDocument;
use serde::{Deserialize, Serialize};

/// Namespace for enrollment ceremony records (the two-signature evidence
/// an attestation was built on).
pub const NS_ENROLL: &str = "identity.enroll";
/// Signed-document kind for the enrollment ceremony.
pub const KIND: &str = "identity.enroll";
/// Party role of the registry that opened the enrollment.
pub const ROLE_REGISTRAR: &str = "registrar";
/// Party role of the citizen whose key is being enrolled.
pub const ROLE_SUBJECT: &str = "subject";

/// The enrollment document inside the SignedDocument: what the registry
/// offers to attest and the citizen consents to be bound by.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnrollDoc {
    /// The key being enrolled: hex Ed25519 verifying key, born on the
    /// citizen's device.
    pub subject: String,
    /// Optional human-readable subject label, e.g. "Acme Ltd".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Free-form claims the registry will attest, e.g.
    /// {"legal_name":"Acme Ltd","role":"bidder"}.
    pub claims: serde_json::Value,
}

/// Build the enrollment document (unsigned; the registrar signs next).
pub fn build_doc(subject: &str, label: Option<&str>, claims: serde_json::Value) -> SignedDocument {
    SignedDocument::new(
        KIND,
        serde_json::json!({
            "subject": subject,
            "label": label,
            "claims": claims,
        }),
    )
}

/// The enrollment document inside a signed document, with the kind check.
pub fn parse_doc(document: &SignedDocument) -> Result<EnrollDoc, String> {
    if document.kind != KIND {
        return Err(format!(
            "kind '{}' is not an enrollment document ('{KIND}')",
            document.kind
        ));
    }
    serde_json::from_value(document.doc.clone())
        .map_err(|e| format!("enrollment document is malformed: {e}"))
}

/// Verify the full ceremony: both party signatures check out, the subject
/// signature was made by the very key being enrolled (the anti-ghost
/// check), and - when `registrar` is given - the registrar signature was
/// made by that key (the approver is the registry that opened).
/// Returns the verified enrollment document.
pub fn verify_ceremony(
    document: &SignedDocument,
    registrar: Option<&str>,
) -> Result<EnrollDoc, String> {
    let doc = parse_doc(document)?;
    let roles = document
        .verify()
        .map_err(|e| format!("party signature verification failed: {e}"))?;
    let subject_key = roles
        .iter()
        .find(|(role, _)| role == ROLE_SUBJECT)
        .map(|(_, key)| key.clone())
        .ok_or_else(|| {
            format!("no verified '{ROLE_SUBJECT}' signature: the subject must consent with the key being enrolled")
        })?;
    if subject_key != doc.subject {
        return Err(format!(
            "subject signature key {subject_key} is not the enrolled key {}: a ghost enrollment (someone else signing for the subject) never completes",
            doc.subject
        ));
    }
    let registrar_key = roles
        .iter()
        .find(|(role, _)| role == ROLE_REGISTRAR)
        .map(|(_, key)| key.clone())
        .ok_or_else(|| format!("no verified '{ROLE_REGISTRAR}' signature: the registry must have opened this enrollment"))?;
    if let Some(expected) = registrar {
        if registrar_key != expected {
            return Err(format!(
                "registrar signature key {registrar_key} is not this node ({expected}): only the registry that opened the enrollment may approve it"
            ));
        }
    }
    Ok(doc)
}

/// Parse an entry as an enrollment ceremony record; `None` if it is not
/// one (wrong namespace or malformed payload).
pub fn parse_enrollment(entry: &Entry) -> Option<(SignedDocument, EnrollDoc)> {
    if entry.body.namespace != NS_ENROLL {
        return None;
    }
    let document = SignedDocument::from_payload(&entry.body.payload)?;
    parse_doc(&document).ok().map(|doc| (document, doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryBody};
    use ed25519_dalek::SigningKey;

    fn node_identity() -> (String, SigningKey) {
        let sk = SigningKey::from([7u8; 32]);
        (hex::encode(sk.verifying_key().as_bytes()), sk)
    }

    fn citizen_identity() -> (String, SigningKey) {
        let sk = SigningKey::from([9u8; 32]);
        (hex::encode(sk.verifying_key().as_bytes()), sk)
    }

    #[test]
    fn ceremony_completes_and_proves_both_keys() {
        let (reg_hex, reg_key) = node_identity();
        let (sub_hex, sub_key) = citizen_identity();
        let mut doc = build_doc(
            &sub_hex,
            Some("Acme Ltd"),
            serde_json::json!({"legal_name": "Acme Ltd", "role": "bidder"}),
        );
        doc.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        assert!(
            !doc.has_verified_role(ROLE_SUBJECT),
            "subject has not consented yet"
        );
        doc.sign(ROLE_SUBJECT, &sub_key, None).unwrap();
        let verified = verify_ceremony(&doc, Some(&reg_hex)).unwrap();
        assert_eq!(verified.subject, sub_hex);
        assert_eq!(verified.label.as_deref(), Some("Acme Ltd"));
    }

    #[test]
    fn ghost_subject_cannot_complete() {
        let (_reg_hex, reg_key) = node_identity();
        let (sub_hex, _sub_key) = citizen_identity();
        let (ghost_hex, ghost_key) = node_identity();
        let mut doc = build_doc(&sub_hex, None, serde_json::json!({"role": "bidder"}));
        doc.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        doc.sign(ROLE_SUBJECT, &ghost_key, None).unwrap();
        let err = verify_ceremony(&doc, None).unwrap_err();
        assert!(
            err.contains("ghost"),
            "the wrong signer must be named a ghost: {err}"
        );
        assert_ne!(ghost_hex, sub_hex);
    }

    #[test]
    fn missing_consent_or_wrong_registrar_fail() {
        let (reg_hex, reg_key) = node_identity();
        let (sub_hex, sub_key) = citizen_identity();
        let mut unconsented = build_doc(&sub_hex, None, serde_json::json!({"role": "x"}));
        unconsented.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        let err = verify_ceremony(&unconsented, Some(&reg_hex)).unwrap_err();
        assert!(err.contains(ROLE_SUBJECT), "{err}");

        let mut doc = build_doc(&sub_hex, None, serde_json::json!({"role": "x"}));
        doc.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        doc.sign(ROLE_SUBJECT, &sub_key, None).unwrap();
        let err = verify_ceremony(&doc, Some(&sub_hex)).unwrap_err();
        assert!(err.contains("registrar"), "{err}");
    }

    #[test]
    fn tampered_claims_break_the_signatures() {
        let (_reg_hex, reg_key) = node_identity();
        let (sub_hex, sub_key) = citizen_identity();
        let mut doc = build_doc(&sub_hex, None, serde_json::json!({"role": "bidder"}));
        doc.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        doc.sign(ROLE_SUBJECT, &sub_key, None).unwrap();
        let tampered = serde_json::json!({"role": "owner"});
        doc.doc
            .as_object_mut()
            .unwrap()
            .insert("claims".into(), tampered);
        let err = verify_ceremony(&doc, None).unwrap_err();
        assert!(err.contains("verification failed"), "{err}");
    }

    #[test]
    fn entries_round_trip_as_enrollment_records() {
        let (reg_hex, reg_key) = node_identity();
        let (sub_hex, sub_key) = citizen_identity();
        let mut doc = build_doc(&sub_hex, Some("Phone"), serde_json::json!({"a": 1}));
        doc.sign(ROLE_REGISTRAR, &reg_key, None).unwrap();
        doc.sign(ROLE_SUBJECT, &sub_key, None).unwrap();
        let payload = doc.payload_bytes().unwrap();
        let body = EntryBody {
            version: crate::ENTRY_VERSION,
            author: reg_hex,
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: NS_ENROLL.to_string(),
            seq: 0,
            prev: None,
            refs: vec![],
            timestamp_ms: 0,
            payload,
        };
        let pq_key = crate::pq::keypair().unwrap().1;
        let entry = Entry::sign(body, &reg_key, &pq_key).unwrap();
        let (parsed, enroll) = parse_enrollment(&entry).unwrap();
        assert_eq!(enroll.subject, sub_hex);
        assert!(parsed.has_verified_role(ROLE_SUBJECT));
    }
}
