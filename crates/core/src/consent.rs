//! What a key has consented to, across the whole ledger.
//!
//! Consent in DATU is not a checkbox: it is a signature on a specific
//! document, bound to a role and a key. Enrollment acceptance, guardian
//! recovery, party-signed records and enrollment approvals all carry the
//! citizen's own signature. This module answers the natural question a data
//! subject asks - "what did I agree to?" - by reading those statements back
//! out of the entries a node holds. Nothing here invents consent: a
//! statement exists only if a verified entry carries the signature.

use crate::entry::Entry;
use crate::parties::SignedDocument;
use serde::{Deserialize, Serialize};

/// One consent statement held by a key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsentStatement {
    /// Entry holding the signature (hex id).
    pub entry: String,
    /// What kind of document was signed, e.g. "identity.enroll".
    pub kind: String,
    /// The role the key signed under, e.g. "subject" or "holder".
    pub role: String,
    /// Human summary from the document, when it carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Entry author (the party that published the document).
    pub by: String,
    pub timestamp_ms: u64,
}

/// Every consent the `key` gave, as recorded by party-signed documents the
/// node holds, oldest first. An entry counts once (the first role wins, so a
/// document mentioning the same key twice is not double-counted).
pub fn consents_of(entries: &[Entry], key: &str) -> Vec<ConsentStatement> {
    let wanted = key.to_lowercase();
    let mut out = Vec::new();
    for entry in entries {
        let Some(document) = SignedDocument::from_payload(&entry.body.payload) else {
            continue;
        };
        let Some(party) = document
            .parties
            .iter()
            .find(|p| p.key.eq_ignore_ascii_case(&wanted))
        else {
            continue;
        };
        // Only a signature that actually verifies counts as consent.
        if document.verify().is_err() {
            continue;
        }
        let Ok(id) = entry.id() else {
            continue;
        };
        out.push(ConsentStatement {
            entry: hex::encode(id),
            kind: document.kind.clone(),
            role: party.role.clone(),
            summary: summary_of(&document),
            by: entry.body.author.clone(),
            timestamp_ms: entry.body.timestamp_ms,
        });
    }
    out.sort_by(|a, b| {
        a.timestamp_ms
            .cmp(&b.timestamp_ms)
            .then(a.entry.cmp(&b.entry))
    });
    out
}

/// A short, human-readable description from the document body, so a consent
/// list reads like a register instead of a wall of JSON.
fn summary_of(document: &SignedDocument) -> Option<String> {
    let doc = document.doc.as_object()?;
    for field in ["label", "subject", "admits", "kind", "title"] {
        if let Some(value) = doc.get(field).and_then(|v| v.as_str()) {
            return Some(format!("{field}: {value}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryBody};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> (String, SigningKey) {
        let sk = SigningKey::from([seed; 32]);
        (hex::encode(sk.verifying_key().as_bytes()), sk)
    }

    fn sign_entry(seed: u8, seq: u64, prev: Option<[u8; 32]>, document: &SignedDocument) -> Entry {
        let sk = SigningKey::from([seed; 32]);
        let pq = crate::pq::keypair().unwrap().1;
        let body = EntryBody {
            version: crate::ENTRY_VERSION,
            author: String::new(),
            author_pq: String::new(),
            pq_alg: String::new(),
            namespace: "identity.enroll".into(),
            seq,
            prev,
            refs: vec![],
            timestamp_ms: 1_700_000_000_000 + seq,
            payload: document.payload_bytes().unwrap(),
        };
        Entry::sign(body, &sk, &pq).unwrap()
    }

    #[test]
    fn only_signed_and_verified_consents_are_listed() {
        let (citizen, citizen_key) = key(11);
        let (_registrar, registrar_key) = key(12);
        let (_other, other_key) = key(13);

        let mut doc = crate::enroll::build_doc(
            &citizen,
            Some("Acme Ltd"),
            serde_json::json!({"role": "bidder"}),
        );
        doc.sign(crate::enroll::ROLE_REGISTRAR, &registrar_key, None)
            .unwrap();
        doc.sign(crate::enroll::ROLE_SUBJECT, &citizen_key, None)
            .unwrap();
        let accepted = sign_entry(12, 0, None, &doc);

        // A document the citizen did not sign must not appear for them.
        let mut foreign =
            crate::parties::SignedDocument::new("gov.contract", serde_json::json!({"x":1}));
        foreign.sign("holder", &other_key, None).unwrap();
        let foreign_entry = sign_entry(13, 0, None, &foreign);

        let entries = vec![accepted.clone(), foreign_entry];
        let consent = consents_of(&entries, &citizen);
        assert_eq!(consent.len(), 1, "only their own signature counts");
        assert_eq!(consent[0].kind, "identity.enroll");
        assert_eq!(consent[0].role, "subject");
        assert_eq!(consent[0].summary.as_deref(), Some("label: Acme Ltd"));
        assert_eq!(consent[0].entry, hex::encode(accepted.id().unwrap()));

        // The other key sees only its own document.
        let other = consents_of(&entries, &"0".repeat(64));
        assert!(other.is_empty());
    }

    #[test]
    fn tampered_documents_do_not_count_as_consent() {
        let (citizen, citizen_key) = key(21);
        let (_r, registrar_key) = key(22);
        let mut doc = crate::enroll::build_doc(&citizen, None, serde_json::json!({}));
        doc.sign(crate::enroll::ROLE_REGISTRAR, &registrar_key, None)
            .unwrap();
        doc.sign(crate::enroll::ROLE_SUBJECT, &citizen_key, None)
            .unwrap();
        let mut entry = sign_entry(22, 0, None, &doc);
        // Tamper with the payload after signing: the signature no longer
        // verifies, so it is not consent.
        entry.body.payload = serde_json::to_vec(&serde_json::json!({"kind": "identity.enroll", "doc": {"subject": citizen}, "parties": []})).unwrap();
        let consent = consents_of(&[entry], &citizen);
        assert!(consent.is_empty(), "unverified signatures are not consent");
    }
}
