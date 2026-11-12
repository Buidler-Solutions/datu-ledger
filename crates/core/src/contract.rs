//! Document contracts: predicate rules a governed document must satisfy.
//!
//! A contract is a *predicate*, not a program: a pure function over the
//! governed document and its direct causal references (the closure, one
//! hop of `refs`). Nothing executes, nothing mutates state, nothing can
//! surprise an evaluator later - which is what makes contracts safe on a
//! no-consensus DAG. Contracts gate; people act.
//!
//! A contract is itself ledger content, content-addressed like everything
//! else: a [`ContractSpec`] is carried as the body of a party-signed
//! document of kind [`CONTRACT_KIND`], published as a normal entry in the
//! [`CONTRACTS_NAMESPACE`] (or a sub-namespace of it) through the ordinary
//! writer policy. The entry id *is* the contract's address.
//!
//! A governed document opts in by naming the rule it claims to satisfy:
//! a `contract` field in its body, `{"id": "<hex entry id>", "version": 1}`.
//! Validators enforce (admission); open mirrors accept everything and can
//! still evaluate and report via the same pure predicate.
//!
//! Resolution is fail-closed: the contract entry must be present on the
//! evaluating node, it must live in the contracts namespace, and the pinned
//! version must match. A rule the node cannot see locally is not a rule.
//!
//! Deadlines keep "late" meaningless in the good sense: citations whose
//! entries carry a timestamp past the document's deadline field do not
//! count toward reference requirements. Late arrivals are not counted by
//! the rule - they remain visible as evidence, just not as compliance.

use crate::parties::SignedDocument;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Namespace (and prefix) where contract entries live.
pub const CONTRACTS_NAMESPACE: &str = "gov.contracts";

/// Contract spec format version.
pub const CONTRACT_VERSION: u8 = 1;

/// The document kind a contract entry's payload carries.
pub const CONTRACT_KIND: &str = "gov.contract";

/// Is this a namespace contract entries may live in? The bare namespace or
/// any sub-namespace of it (`gov.contracts.titles`, ...).
pub fn is_contracts_namespace(ns: &str) -> bool {
    ns == CONTRACTS_NAMESPACE || ns.starts_with(&format!("{CONTRACTS_NAMESPACE}."))
}

fn default_count() -> usize {
    1
}

/// A `datu-sealed-*` / `dag-sealed-*` reader-ACL object (field-level
/// encryption; see the wallet crate). A plaintext personal field breaks the
/// seal demand.
pub fn is_sealed(value: &serde_json::Value) -> bool {
    value
        .get("sealed")
        .and_then(|s| s.as_str())
        .map(|s| s.starts_with("datu-sealed-") || s.starts_with("dag-sealed-"))
        .unwrap_or(false)
}

/// One reference requirement: the closure must contain at least `count`
/// cited entries whose documents are of `kind` and satisfy the optional
/// party and author constraints.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RefRequirement {
    /// Document kind a qualifying citation must carry.
    pub kind: String,
    /// How many qualifying citations the closure must hold.
    #[serde(default = "default_count")]
    pub count: usize,
    /// If set, a qualifying document must carry a *verified* party
    /// signature for this role, e.g. "inspector".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
    /// If set, a qualifying document must carry at least this many distinct
    /// verified party keys (independent cosigners).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cosigners: Option<usize>,
    /// If set, the qualifying *entry* must be authored by this key (hex):
    /// the authority-feed predicate. One designated author sequences the
    /// feed, so "the authority allocated this" is deterministic without
    /// consensus - the citation is the allocation receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// One party requirement on the governed document itself. Mirrors the
/// writer policy's `RoleRule` semantics: verified party signature, key
/// pinning, self-binding to a document field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PartyRequirement {
    /// Role that must carry a verified party signature, e.g. "holder".
    pub role: String,
    /// If set, the signing party's key must be exactly this key (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// If set, the signing party's key must equal this document field -
    /// the record must be signed by the party it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_field: Option<String>,
}

/// A contract: the predicate a document of kind `admits` must satisfy.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ContractSpec {
    pub version: u8,
    /// The document kind this contract admits, e.g. "land.title.grant".
    pub admits: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_refs: Vec<RefRequirement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_parties: Vec<PartyRequirement>,
    /// Document field carrying the deadline (ms since epoch). Closure
    /// entries stamped after it do not count toward `requires_refs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_from_field: Option<String>,
    /// Document field carrying the earliest landing time (ms). The
    /// governed entry's own timestamp must be at or after it. Validator-
    /// clock subjective at admission; violations stay provable later via
    /// witness checkpoints over the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_field: Option<String>,
    /// Document field carrying the latest landing time (ms). The governed
    /// entry's own timestamp must be at or before it - the release window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_field: Option<String>,
    /// Document fields that must be **encrypted** (a `datu-sealed-*`
    /// object) whenever they appear in the governed document. A missing
    /// field is fine; a present field in plaintext is a denial.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_sealed: Vec<String>,
}

impl ContractSpec {
    /// Parse a contract entry payload: a party-signed document of kind
    /// [`CONTRACT_KIND`] whose body is the spec itself. `None` if the
    /// payload is not that shape (wrong kind, bad JSON, unknown version).
    pub fn from_payload(payload: &[u8]) -> Option<ContractSpec> {
        let document = SignedDocument::from_payload(payload)?;
        if document.kind != CONTRACT_KIND {
            return None;
        }
        let spec: ContractSpec = serde_json::from_value(document.doc).ok()?;
        if spec.version != CONTRACT_VERSION {
            return None;
        }
        Some(spec)
    }

    /// Full evaluation with per-condition detail (for `datu contract check`
    /// and audits). Pure: same document, entry timestamp, and closure, same
    /// report. `entry_ts` is the governed entry's own author-claimed
    /// timestamp (used only by the landing window predicates).
    pub fn evaluate_report(
        &self,
        document: &SignedDocument,
        entry_ts: u64,
        closure: &[ClosureEntry],
    ) -> ContractReport {
        let mut conditions = Vec::new();
        let mut reasons = Vec::new();

        let kind_met = document.kind == self.admits;
        conditions.push(ConditionStatus {
            kind: ConditionKind::Kind,
            requirement: format!("document kind is '{}'", self.admits),
            required: self.admits.clone(),
            found: document.kind.clone(),
            met: kind_met,
        });
        if !kind_met {
            reasons.push(format!(
                "this contract admits documents of kind '{}', not '{}'",
                self.admits, document.kind
            ));
        }

        // Parties on the governed document (same semantics as the writer
        // policy's role rules: verified signature, key pin, field bind).
        let parties = document.verify().unwrap_or_default();
        for req in &self.requires_parties {
            let satisfied = parties.iter().any(|(role, key)| {
                role == &req.role
                    && req.key.as_ref().map(|k| k == key).unwrap_or(true)
                    && req
                        .bind_field
                        .as_ref()
                        .map(|field| {
                            document.doc.get(field).and_then(|v| v.as_str())
                                == Some(key.as_str())
                        })
                        .unwrap_or(true)
            });
            let mut describe = format!("a verified '{}' party signature", req.role);
            if let Some(key) = &req.key {
                describe.push_str(&format!(
                    " by key {}",
                    &key[..16.min(key.len())]
                ));
            }
            if let Some(field) = &req.bind_field {
                describe.push_str(&format!(
                    " whose key equals the document's '{field}' field"
                ));
            }
            conditions.push(ConditionStatus {
                kind: ConditionKind::Party,
                requirement: describe.clone(),
                required: "verified".into(),
                found: if satisfied { "present".into() } else { "missing".into() },
                met: satisfied,
            });
            if !satisfied {
                reasons.push(format!("contract requires {describe}"));
            }
        }

        // Deadline: citations stamped after it do not count. A contract
        // that names a deadline field fails closed on documents that do
        // not carry a number there.
        let deadline = self.deadline_from_field.as_ref().and_then(|field| {
            document.doc.get(field).and_then(|v| v.as_u64())
        });
        if let Some(field) = &self.deadline_from_field {
            let met = deadline.is_some();
            conditions.push(ConditionStatus {
                kind: ConditionKind::Deadline,
                requirement: format!("deadline field '{field}' carries a number"),
                required: "numeric".into(),
                found: deadline
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "missing".into()),
                met,
            });
            if !met {
                reasons.push(format!(
                    "contract deadline lives in field '{field}' but the document does not carry a number there"
                ));
            }
        }

        // Landing window: the governed entry's own timestamp against
        // declared bounds. Validator-clock subjective at admission (an
        // author-claimed ts is a claim, not truth); violations stay
        // provable later via witness checkpoints over the entry.
        for (field, opens) in [
            self.not_before_field.as_ref().map(|f| (f, true)),
            self.not_after_field.as_ref().map(|f| (f, false)),
        ]
        .into_iter()
        .flatten()
        {
            let bound = document.doc.get(field).and_then(|v| v.as_u64());
            let met = match bound {
                Some(b) if opens => entry_ts >= b,
                Some(b) => entry_ts <= b,
                None => false,
            };
            conditions.push(ConditionStatus {
                kind: ConditionKind::Window,
                requirement: format!(
                    "entry lands {} doc field '{}', the {} of the window",
                    if opens { "at or after" } else { "at or before" },
                    field,
                    if opens { "opening" } else { "closing" }
                ),
                required: bound
                    .map(|b| b.to_string())
                    .unwrap_or_else(|| "numeric".into()),
                found: format!("entry ts {entry_ts}"),
                met,
            });
            if !met {
                let why = match bound {
                    Some(b) if opens => {
                        format!("entry ts {entry_ts} is before the window opening {b}")
                    }
                    Some(b) => format!("entry ts {entry_ts} is after the window closing {b}"),
                    None => format!(
                        "document does not carry a number in '{field}' (fail-closed)"
                    ),
                };
                reasons.push(format!("contract landing window: {why}"));
            }
        }

        // Sealed fields: personal data is never published in plaintext.
        // A missing field is fine (nothing to leak); a present field must
        // be a sealed object.
        for field in &self.requires_sealed {
            let (found, met) = match document.doc.get(field.as_str()) {
                None => ("absent".to_string(), true),
                Some(value) => {
                    let sealed = is_sealed(value);
                    (if sealed { "sealed" } else { "plaintext" }.to_string(), sealed)
                }
            };
            conditions.push(ConditionStatus {
                kind: ConditionKind::Sealed,
                requirement: format!("field '{field}' is encrypted when present"),
                required: "sealed".into(),
                found: found.clone(),
                met,
            });
            if !met {
                reasons.push(format!(
                    "contract requires field '{field}' to be encrypted: the ledger stores ciphertext only"
                ));
            }
        }

        for req in &self.requires_refs {
            let counts = |entry: &ClosureEntry| -> bool {
                deadline.map(|d| entry.timestamp_ms <= d).unwrap_or(true)
            };
            let on_feed = |entry: &ClosureEntry| -> bool {
                req.author
                    .as_ref()
                    .map(|author| &entry.author == author)
                    .unwrap_or(true)
            };
            let found = closure
                .iter()
                .filter(|entry| counts(entry) && on_feed(entry))
                .filter(|entry| {
                    entry
                        .document
                        .as_ref()
                        .map(|doc| req.satisfied_by(doc))
                        .unwrap_or(false)
                })
                .count();
            let met = found >= req.count;
            let mut qualifiers = String::new();
            if let Some(role) = &req.party {
                qualifiers.push_str(&format!(" with a verified '{role}' party"));
            }
            if let Some(min) = req.min_cosigners {
                qualifiers.push_str(&format!(" with at least {min} distinct cosigners"));
            }
            if let Some(author) = &req.author {
                qualifiers.push_str(&format!(
                    " authored by {} (the authority feed)",
                    &author[..16.min(author.len())]
                ));
            }
            conditions.push(ConditionStatus {
                kind: ConditionKind::Refs,
                requirement: format!("{} cited ref(s) of kind '{}'{}", req.count, req.kind, qualifiers),
                required: req.count.to_string(),
                found: found.to_string(),
                met,
            });
            if !met {
                reasons.push(format!(
                    "contract requires {} cited ref(s) of kind '{}'{}, found {} (late or off-feed citations do not count)",
                    req.count, req.kind, qualifiers, found
                ));
            }
        }

        ContractReport {
            admitted: reasons.is_empty(),
            reasons,
            conditions,
        }
    }

    /// Verdict only. Pure.
    pub fn evaluate(
        &self,
        document: &SignedDocument,
        entry_ts: u64,
        closure: &[ClosureEntry],
    ) -> ContractVerdict {
        match self.evaluate_report(document, entry_ts, closure) {
            report if report.admitted => ContractVerdict::Admitted,
            report => ContractVerdict::Denied(report.reasons.join("; ")),
        }
    }
}

impl RefRequirement {
    /// Does a closure document satisfy this citation requirement? A
    /// document whose party signatures do not verify at all satisfies
    /// nothing.
    pub fn satisfied_by(&self, doc: &SignedDocument) -> bool {
        if doc.kind != self.kind {
            return false;
        }
        let parties = match doc.verify() {
            Ok(parties) => parties,
            Err(_) => return false,
        };
        if let Some(role) = &self.party {
            if !parties.iter().any(|(r, _)| r == role) {
                return false;
            }
        }
        if let Some(min) = self.min_cosigners {
            let distinct: BTreeSet<&String> =
                parties.iter().map(|(_, key)| key).collect();
            if distinct.len() < min {
                return false;
            }
        }
        true
    }
}

/// The contract a governed document declares for itself.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ContractRef {
    /// Hex entry id of the contract entry.
    pub id: String,
    /// Spec format version the document pins.
    pub version: u8,
}

impl ContractRef {
    /// Read the declaration out of a document body: a `contract` field of
    /// shape `{"id": "<hex>", "version": 1}`. `Ok(None)` means no contract
    /// declared; `Err` means one is declared but malformed (fail-closed:
    /// that is a denial, not an opt-out).
    pub fn from_doc(doc: &serde_json::Value) -> Result<Option<ContractRef>, String> {
        let Some(field) = doc.get("contract") else {
            return Ok(None);
        };
        let malformed = |why: &str| {
            Err(format!(
                "document declares a contract but the declaration is malformed ({why})"
            ))
        };
        if !field.is_object() {
            return malformed("'contract' is not an object");
        }
        let Some(id) = field.get("id").and_then(|v| v.as_str()) else {
            return malformed("missing 'id' string");
        };
        let Some(version) = field.get("version").and_then(|v| v.as_u64()) else {
            return malformed("missing 'version' number");
        };
        if version > u8::MAX as u64 {
            return malformed("'version' out of range");
        }
        Ok(Some(ContractRef {
            id: id.to_string(),
            version: version as u8,
        }))
    }

    pub fn parse_id(&self) -> Option<[u8; 32]> {
        hex::decode(&self.id).ok().and_then(|bytes| bytes.try_into().ok())
    }
}

/// One direct causal reference of the governed entry, resolved as far as
/// this node can see it: its id, author, author-claimed timestamp, and its
/// payload as a signed document if it is one.
#[derive(Clone, Debug)]
pub struct ClosureEntry {
    pub id: [u8; 32],
    pub author: String,
    pub timestamp_ms: u64,
    pub document: Option<SignedDocument>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ContractVerdict {
    Admitted,
    Denied(String),
}

/// Which family of predicate a condition belongs to (lets walkers render
/// citation-side conditions apart from document-side ones).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionKind {
    /// Governed document kind matches `admits`.
    Kind,
    /// Verified party on the governed document.
    Party,
    /// Deadline field present; citations stamped after it do not count.
    Deadline,
    /// Landing-window bound on the governed entry's own timestamp.
    Window,
    /// Document field must be sealed when present.
    Sealed,
    /// Cited-reference requirement (counts the closure).
    Refs,
}

impl ConditionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConditionKind::Kind => "kind",
            ConditionKind::Party => "party",
            ConditionKind::Deadline => "deadline",
            ConditionKind::Window => "window",
            ConditionKind::Sealed => "sealed",
            ConditionKind::Refs => "refs",
        }
    }
}

/// One evaluated condition, met or not (report surface for
/// `datu contract check` and audits).
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionStatus {
    pub kind: ConditionKind,
    pub requirement: String,
    pub required: String,
    pub found: String,
    pub met: bool,
}

/// Full predicate evaluation outcome.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContractReport {
    pub admitted: bool,
    pub reasons: Vec<String>,
    pub conditions: Vec<ConditionStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn signed_doc(kind: &str, doc: serde_json::Value, roles: &[(&str, SigningKey)]) -> SignedDocument {
        let mut document = SignedDocument::new(kind, doc);
        for (role, key) in roles {
            document.sign(role, key, None).unwrap();
        }
        document
    }

    fn spec() -> ContractSpec {
        ContractSpec {
            version: CONTRACT_VERSION,
            admits: "land.title.grant".into(),
            requires_refs: vec![RefRequirement {
                kind: "land.title.inspection".into(),
                count: 1,
                party: Some("inspector".into()),
                min_cosigners: None,
                author: None,
            }],
            requires_parties: vec![PartyRequirement {
                role: "holder".into(),
                key: None,
                bind_field: Some("holder_key".into()),
            }],
            deadline_from_field: Some("deadline_ms".into()),
            not_before_field: None,
            not_after_field: None,
            requires_sealed: vec![],
        }
    }

    fn closure_of(entries: &[(&SignedDocument, u64)], author: &str) -> Vec<ClosureEntry> {
        entries
            .iter()
            .map(|entry| ClosureEntry {
                id: [0u8; 32],
                author: author.to_string(),
                timestamp_ms: entry.1,
                document: Some(entry.0.clone()),
            })
            .collect()
    }

    #[test]
    fn compliant_document_admits() {
        let holder = SigningKey::generate(&mut OsRng);
        let inspector = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"parcel": "PH-1", "holder_key": holder_key, "deadline_ms": 1000}),
            &[("holder", holder)],
        );
        let inspection = signed_doc(
            "land.title.inspection",
            serde_json::json!({"parcel": "PH-1"}),
            &[("inspector", inspector)],
        );
        let closure = closure_of(&[(&inspection, 500)], "inspector-author");
        assert!(matches!(
            spec().evaluate(&doc, 2000, &closure),
            ContractVerdict::Admitted
        ));
    }

    #[test]
    fn wrong_kind_denied() {
        let doc = signed_doc("land.title.loan", serde_json::json!({}), &[]);
        let report = spec().evaluate_report(&doc, 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons[0].contains("land.title.grant"));
    }

    #[test]
    fn bind_field_mismatch_denied() {
        let holder = SigningKey::generate(&mut OsRng);
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": format!("{}0", "0".repeat(63)), "deadline_ms": 1000}),
            &[("holder", holder)],  // signed by holder, but doc names another key
        );
        let report = spec().evaluate_report(&doc, 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("'holder'")));
    }

    #[test]
    fn late_citation_does_not_count() {
        let holder = SigningKey::generate(&mut OsRng);
        let inspector = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 1000}),
            &[("holder", holder)],
        );
        let inspection = signed_doc(
            "land.title.inspection",
            serde_json::json!({}),
            &[("inspector", inspector)],
        );
        let late = closure_of(&[(&inspection, 1500)], "inspector-author");
        assert!(matches!(
            spec().evaluate(&doc, 2000, &late),
            ContractVerdict::Denied(_)
        ));
        let on_time = closure_of(&[(&inspection, 1000)], "inspector-author");
        assert!(matches!(
            spec().evaluate(&doc, 2000, &on_time),
            ContractVerdict::Admitted
        ));
    }

    #[test]
    fn missing_deadline_field_fails_closed() {
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"deadline_ms": "soon"}),
            &[],
        );
        let report = spec().evaluate_report(&doc, 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("deadline")));
    }

    #[test]
    fn min_cosigners_counts_distinct_keys() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let one = signed_doc("x.report", serde_json::json!({}), &[("witness", a.clone())]);
        let req = RefRequirement {
            kind: "x.report".into(),
            count: 1,
            party: None,
            min_cosigners: Some(2),
            author: None,
        };
        assert!(!req.satisfied_by(&one));
        let mut two = signed_doc("x.report", serde_json::json!({}), &[("witness", a)]);
        two.sign("second", &b, None).unwrap();
        assert!(req.satisfied_by(&two));
    }

    #[test]
    fn contract_ref_roundtrip_and_malformed() {
        let doc = serde_json::json!({
            "contract": {"id": "aa".repeat(32), "version": 1}
        });
        let r = ContractRef::from_doc(&doc).unwrap().unwrap();
        assert_eq!(r.version, 1);
        assert!(r.parse_id().is_some());
        assert!(ContractRef::from_doc(&serde_json::json!({"x": 1}))
            .unwrap()
            .is_none());
        assert!(ContractRef::from_doc(&serde_json::json!({"contract": {"id": 5}})).is_err());
    }

    #[test]
    fn spec_payload_roundtrip() {
        let issuer = SigningKey::generate(&mut OsRng);
        let document = signed_doc(
            CONTRACT_KIND,
            serde_json::to_value(spec()).unwrap(),
            &[("issuer", issuer)],
        );
        let payload = serde_json::to_vec(&document).unwrap();
        let parsed = ContractSpec::from_payload(&payload).unwrap();
        assert_eq!(parsed, spec());
        let not_a_contract = serde_json::to_vec(&signed_doc("other.kind", serde_json::json!({}), &[]))
            .unwrap();
        assert!(ContractSpec::from_payload(&not_a_contract).is_none());
    }

    #[test]
    fn authority_feed_pin_only_counts_that_author() {
        let mut s = spec();
        s.requires_refs = vec![RefRequirement {
            kind: "land.title.inspection".into(),
            count: 1,
            party: None,
            min_cosigners: None,
            author: Some("feed-author".into()),
        }];
        let holder = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 1000}),
            &[("holder", holder)],
        );
        let inspection = signed_doc("land.title.inspection", serde_json::json!({}), &[]);

        let other_feed = closure_of(&[(&inspection, 500)], "someone-else");
        assert!(matches!(
            s.evaluate(&doc, 2000, &other_feed),
            ContractVerdict::Denied(_)
        ));
        let authority_feed = closure_of(&[(&inspection, 500)], "feed-author");
        assert!(matches!(
            s.evaluate(&doc, 2000, &authority_feed),
            ContractVerdict::Admitted
        ));
    }

    #[test]
    fn landing_window_bounds_the_entry_timestamp() {
        let holder = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 9000, "opens": 1000, "closes": 3000}),
            &[("holder", holder)],
        );
        let inspection = signed_doc(
            "land.title.inspection",
            serde_json::json!({}),
            &[("inspector", SigningKey::generate(&mut OsRng))],
        );
        let closure = closure_of(&[(&inspection, 500)], "inspector");

        let mut s = spec();
        s.not_before_field = Some("opens".into());
        s.not_after_field = Some("closes".into());

        assert!(matches!(
            s.evaluate(&doc, 2000, &closure),
            ContractVerdict::Admitted
        ));
        let early = s.evaluate_report(&doc, 500, &closure);
        assert!(!early.admitted);
        assert!(early.reasons.iter().any(|r| r.contains("before the window opening")));
        let late = s.evaluate_report(&doc, 4000, &closure);
        assert!(!late.admitted);
        assert!(late.reasons.iter().any(|r| r.contains("after the window closing")));
    }

    #[test]
    fn landing_window_fails_closed_without_the_field() {
        let holder = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let doc = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 9000}),
            &[("holder", holder)],
        );
        let mut s = spec();
        s.not_after_field = Some("closes".into());
        let report = s.evaluate_report(&doc, 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("fail-closed")));
    }

    #[test]
    fn sealed_fields_must_be_ciphertext() {
        let holder = SigningKey::generate(&mut OsRng);
        let holder_key = hex::encode(holder.verifying_key().as_bytes());
        let mut s = spec();
        s.requires_sealed = vec!["owner_name".into()];

        let plain = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 9000, "owner_name": "Amina"}),
            &[("holder", holder.clone())],
        );
        let report = s.evaluate_report(&plain, 2000, &[]);
        assert!(!report.admitted);
        assert!(report.reasons.iter().any(|r| r.contains("owner_name")));

        let sealed = signed_doc(
            "land.title.grant",
            serde_json::json!({"holder_key": holder_key, "deadline_ms": 9000,
                "owner_name": {"sealed": "datu-sealed-v2", "ciphertext": "..."}}),
            &[("holder", holder)],
        );
        let inspection = signed_doc(
            "land.title.inspection",
            serde_json::json!({}),
            &[("inspector", SigningKey::generate(&mut OsRng))],
        );
        let closure = closure_of(&[(&inspection, 500)], "inspector");
        assert!(matches!(
            s.evaluate(&sealed, 2000, &closure),
            ContractVerdict::Admitted
        ));
    }
}
