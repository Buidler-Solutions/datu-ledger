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

/// Namespace for guardian-recovery ceremony records.
pub const NS_RECOVER: &str = "identity.recover";
/// Signed-document kind for a guardian recovery.
pub const KIND_RECOVER: &str = "identity.recovery";
/// Party role of the citizen proving they hold the NEW key (its owner).
pub const ROLE_CITIZEN: &str = "citizen";
/// Party role of a guardian co-signing the recovery (one signature each).
pub const ROLE_GUARDIAN: &str = "guardian";

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

/// The recovery document: a lost key is replaced by a new one, co-signed by
/// guardians who vouch that the person asking is the person they say.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RecoveryDoc {
    /// The NEW key, held by the citizen (they sign with it: proof of
    /// possession, the same anti-ghost rule as enrollment).
    pub subject: String,
    /// The lost key being replaced.
    pub lost: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Claims for the replacement attestation.
    pub claims: serde_json::Value,
}

/// Build the recovery document (unsigned; the citizen signs first).
pub fn build_recovery(
    subject: &str,
    lost: &str,
    label: Option<&str>,
    claims: serde_json::Value,
) -> SignedDocument {
    SignedDocument::new(
        KIND_RECOVER,
        serde_json::json!({
            "subject": subject,
            "lost": lost,
            "label": label,
            "claims": claims,
        }),
    )
}

/// The recovery document inside a signed document, with the kind check.
pub fn parse_recovery(document: &SignedDocument) -> Result<RecoveryDoc, String> {
    if document.kind != KIND_RECOVER {
        return Err(format!(
            "kind '{}' is not a recovery document ('{KIND_RECOVER}')",
            document.kind
        ));
    }
    serde_json::from_value(document.doc.clone())
        .map_err(|e| format!("recovery document is malformed: {e}"))
}

/// Append a party signature under `role` without replacing others in the
/// same role: recovery needs one signature per guardian, and the parties
/// helper keeps a single slot per role. Signing again with the same
/// (role, key) replaces just that entry, so a guardian can correct theirs.
pub fn sign_append(
    document: &mut SignedDocument,
    role: &str,
    key: &ed25519_dalek::SigningKey,
    pq_key: Option<&crate::pq::PqPrivateKey>,
) -> Result<(), String> {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use fips204::traits::Signer as _;
    let key_hex = hex::encode(key.verifying_key().as_bytes());
    let digest = document.digest(role, &key_hex).map_err(|e| e.to_string())?;
    let signature = key.sign(&digest);
    let (pq_public, pq_signature, pq_alg) = match pq_key {
        Some(sk) => (
            Some(crate::pq::pk_to_hex(&sk.get_public_key())),
            Some(
                base64::engine::general_purpose::STANDARD
                    .encode(crate::pq::sign(sk, &digest).map_err(|e| e.to_string())?),
            ),
            Some(crate::pq::PQ_ALG.to_string()),
        ),
        None => (None, None, None),
    };
    document
        .parties
        .retain(|p| !(p.role == role && p.key == key_hex));
    document.parties.push(crate::parties::PartySignature {
        role: role.to_string(),
        key: key_hex,
        ed_signature: hex::encode(signature.to_bytes()),
        pq_key: pq_public,
        pq_signature,
        pq_alg,
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    });
    Ok(())
}

/// Verify a recovery ceremony: every signature checks out, the `citizen`
/// signature was made by the NEW key itself (anti-ghost), and at least
/// `min_guardians` DISTINCT guardian keys co-signed. Returns the document
/// and the guardian keys, so the approver can name them.
pub fn verify_recovery(
    document: &SignedDocument,
    min_guardians: usize,
) -> Result<(RecoveryDoc, Vec<String>), String> {
    let doc = parse_recovery(document)?;
    let roles = document
        .verify()
        .map_err(|e| format!("party signature verification failed: {e}"))?;
    let citizen = roles
        .iter()
        .find(|(role, _)| role == ROLE_CITIZEN)
        .map(|(_, key)| key.clone())
        .ok_or_else(|| {
            format!("no verified '{ROLE_CITIZEN}' signature: the holder of the new key must sign")
        })?;
    if citizen != doc.subject {
        return Err(format!(
            "citizen signature key {citizen} is not the new key {}: whoever recovers must hold the replacement key",
            doc.subject
        ));
    }
    let mut guardians: Vec<String> = Vec::new();
    for (role, key) in roles {
        if role == ROLE_GUARDIAN && !guardians.contains(&key) {
            guardians.push(key);
        }
    }
    if guardians.len() < min_guardians {
        return Err(format!(
            "recovery needs {min_guardians} distinct guardian signature(s), found {}: guardians vouch that the person asking is the person they say",
            guardians.len()
        ));
    }
    Ok((doc, guardians))
}

/// Parse an entry as a recovery ceremony record.
pub fn parse_recovery_entry(entry: &Entry) -> Option<(SignedDocument, RecoveryDoc)> {
    if entry.body.namespace != NS_RECOVER {
        return None;
    }
    let document = SignedDocument::from_payload(&entry.body.payload)?;
    parse_recovery(&document).ok().map(|doc| (document, doc))
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

    fn key(seed: u8) -> (String, ed25519_dalek::SigningKey) {
        let sk = ed25519_dalek::SigningKey::from([seed; 32]);
        (hex::encode(sk.verifying_key().as_bytes()), sk)
    }

    #[test]
    fn recovery_needs_the_new_key_and_a_guardian_quorum() {
        let (new_hex, new_key) = key(11);
        let (old_hex, _old_key) = key(12);
        let (_g1_hex, g1) = key(13);
        let (_g2_hex, g2) = key(14);
        let mut doc = build_recovery(
            &new_hex,
            &old_hex,
            Some("Acme Ltd"),
            serde_json::json!({"role": "bidder"}),
        );
        doc.sign(ROLE_CITIZEN, &new_key, None).unwrap();
        sign_append(&mut doc, ROLE_GUARDIAN, &g1, None).unwrap();

        // One guardian is not a quorum of two.
        let err = verify_recovery(&doc, 2).unwrap_err();
        assert!(err.contains("needs 2") && err.contains("found 1"), "{err}");

        sign_append(&mut doc, ROLE_GUARDIAN, &g2, None).unwrap();
        let (verified, guardians) = verify_recovery(&doc, 2).unwrap();
        assert_eq!(verified.subject, new_hex);
        assert_eq!(verified.lost, old_hex);
        assert_eq!(guardians.len(), 2);
    }

    #[test]
    fn recovery_ghosts_and_duplicates_are_refused() {
        let (new_hex, new_key) = key(21);
        let (old_hex, _old_key) = key(22);
        let (_g_hex, g) = key(23);
        let (_x_hex, x) = key(24);

        // A signer that is not the new key cannot play the citizen.
        let mut doc = build_recovery(&new_hex, &old_hex, None, serde_json::json!({}));
        doc.sign(ROLE_CITIZEN, &x, None).unwrap();
        let err = verify_recovery(&doc, 0).unwrap_err();
        assert!(err.contains("must hold the replacement key"), "{err}");

        // The same guardian signing twice is one guardian.
        let mut doc = build_recovery(&new_hex, &old_hex, None, serde_json::json!({}));
        doc.sign(ROLE_CITIZEN, &new_key, None).unwrap();
        sign_append(&mut doc, ROLE_GUARDIAN, &g, None).unwrap();
        sign_append(&mut doc, ROLE_GUARDIAN, &g, None).unwrap();
        let err = verify_recovery(&doc, 2).unwrap_err();
        assert!(err.contains("found 1"), "duplicates must not count: {err}");

        // Tampering with the lost key after signatures breaks them.
        let mut doc = build_recovery(&new_hex, &old_hex, None, serde_json::json!({}));
        doc.sign(ROLE_CITIZEN, &new_key, None).unwrap();
        sign_append(&mut doc, ROLE_GUARDIAN, &g, None).unwrap();
        doc.doc
            .as_object_mut()
            .unwrap()
            .insert("lost".into(), serde_json::json!("ff"));
        let err = verify_recovery(&doc, 1).unwrap_err();
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
