//! Contract enforcement and evaluation on the store.
//!
//! Resolution is fail-closed and local: the contract entry must be present
//! on *this* node, live in the contracts namespace, and match the pinned
//! version - a rule the node cannot see is not a rule. The closure is the
//! governed entry's direct `refs` (one hop, deterministic).
//!
//! Two consumers share one predicate:
//!
//! - **Admission** (validators): `gate()` calls `enforce_contract` at the
//!   end of the gated-namespace branch, so a document that declares a
//!   contract is only stored when the contract admits it.
//! - **Evaluation** (everyone): `check_contract` re-runs the same pure
//!   predicate for `datu contract check` and `verify_all` reporting -
//!   open observers mirror everything and can still evaluate.

use datu_core::contract::{
    is_contracts_namespace, ClosureEntry, ConditionKind, ConditionStatus, ContractRef,
    ContractSpec, CONTRACTS_NAMESPACE,
};
use datu_core::parties::SignedDocument;
use datu_core::Entry;

use crate::{Store, StoreError, StoreResult};

/// The outcome of evaluating the contract an entry declares.
#[derive(Debug, Clone)]
pub struct ContractCheck {
    /// Declared contract entry id (all-zero when the declaration does not
    /// even parse as an id).
    pub contract_id: [u8; 32],
    /// Declared contract version.
    pub version: u8,
    /// Kind of the governed document.
    pub kind: String,
    pub admitted: bool,
    /// Why not (resolution failures included; empty when admitted).
    pub reasons: Vec<String>,
    /// Per-condition detail (empty when the contract could not be resolved).
    pub conditions: Vec<ConditionStatus>,
}

impl Store {
    /// Evaluate the contract this entry's document declares, if any.
    /// `Ok(None)` = the entry declares no contract (nothing to evaluate).
    /// Resolution failures surface as `admitted: false` with reasons, not
    /// as errors: this is evidence, not a storage failure.
    pub fn check_contract(&self, entry: &Entry) -> StoreResult<Option<ContractCheck>> {
        let Some(document) = SignedDocument::from_payload(&entry.body.payload) else {
            return Ok(None);
        };
        let declared = match ContractRef::from_doc(&document.doc) {
            Ok(None) => return Ok(None),
            Ok(Some(declared)) => declared,
            Err(reason) => {
                return Ok(Some(ContractCheck {
                    contract_id: [0u8; 32],
                    version: 0,
                    kind: document.kind.clone(),
                    admitted: false,
                    reasons: vec![reason],
                    conditions: Vec::new(),
                }))
            }
        };
        let contract_id = declared.parse_id().unwrap_or([0u8; 32]);
        let (admitted, reasons, conditions) = match self.resolve_contract(&declared) {
            Err(reason) => (false, vec![reason], Vec::new()),
            Ok(spec) => {
                let report = spec.evaluate_report(
                    &document,
                    entry.body.timestamp_ms,
                    &self.closure_of(entry),
                );
                (report.admitted, report.reasons, report.conditions)
            }
        };
        Ok(Some(ContractCheck {
            contract_id,
            version: declared.version,
            kind: document.kind.clone(),
            admitted,
            reasons,
            conditions,
        }))
    }

    /// Resolve a declaration to its spec, fail-closed at every step.
    fn resolve_contract(&self, declared: &ContractRef) -> Result<ContractSpec, String> {
        let Some(id) = declared.parse_id() else {
            return Err(format!(
                "contract id '{}' is not a 32-byte hex entry id",
                &declared.id[..32.min(declared.id.len())]
            ));
        };
        let Some(entry) = self
            .get_entry(&id)
            .map_err(|e| format!("cannot read contract entry: {e}"))?
        else {
            return Err(format!(
                "contract entry {} is not present on this node (fail-closed: a rule must be local evidence)",
                declared.id
            ));
        };
        if !is_contracts_namespace(&entry.body.namespace) {
            return Err(format!(
                "contract entry {} lives in namespace '{}', not '{}' (only contract-namespace entries are rules)",
                &declared.id[..16.min(declared.id.len())],
                entry.body.namespace,
                CONTRACTS_NAMESPACE
            ));
        }
        let Some(spec) = ContractSpec::from_payload(&entry.body.payload) else {
            return Err(format!(
                "contract entry {} does not carry a contract spec (a '{}' document holding the rule)",
                &declared.id[..16.min(declared.id.len())],
                datu_core::contract::CONTRACT_KIND
            ));
        };
        if spec.version != declared.version {
            return Err(format!(
                "document pins contract v{} but entry {} holds v{}",
                declared.version, declared.id, spec.version
            ));
        }
        Ok(spec)
    }

    /// The governed entry's direct causal closure, resolved as far as this
    /// node can see: one hop of `refs`, each with its payload parsed as a
    /// signed document when it is one. Refs this node has not seen resolve
    /// to nothing and therefore satisfy nothing.
    fn closure_of(&self, entry: &Entry) -> Vec<ClosureEntry> {
        entry
            .body
            .refs
            .iter()
            .filter_map(|id| {
                self.get_entry(id).ok().flatten().map(|referenced| ClosureEntry {
                    id: *id,
                    author: referenced.body.author.clone(),
                    timestamp_ms: referenced.body.timestamp_ms,
                    document: SignedDocument::from_payload(&referenced.body.payload),
                })
            })
            .collect()
    }

    /// Admission check: deny when the entry declares a contract its
    /// document does not satisfy (or that cannot be resolved). A no-op for
    /// entries that declare nothing.
    pub(crate) fn enforce_contract(&self, entry: &Entry) -> StoreResult<()> {
        match self.check_contract(entry)? {
            None => Ok(()),
            Some(check) if check.admitted => Ok(()),
            Some(check) => Err(StoreError::Denied(format!(
                "contract {}: {}",
                hex::encode(check.contract_id),
                check.reasons.join("; ")
            ))),
        }
    }

    /// The pending view of a governed agreement: the contract an *anchor*
    /// entry declares, judged over the evidence that exists so far - every
    /// stored entry citing the anchor - instead of the anchor's own refs.
    /// This is the walker behind "conditions outstanding" surfaces (escrow
    /// status, reward pending, Signet's pending-for-me card): a future
    /// satisfying document would cite the citing entries, so counting them
    /// now answers "what is still outstanding".
    ///
    /// Only the citation-side predicates (refs and deadline) are judged
    /// here; kind, party signatures, window, and seals belong to the future
    /// document itself. `Ok(None)` = the anchor declares no contract.
    pub fn contract_outlook(&self, anchor_id: &[u8; 32]) -> StoreResult<Option<ContractOutlook>> {
        let Some(anchor) = self.get_entry(anchor_id)? else {
            return Err(StoreError::Denied(format!(
                "entry {} is not present on this node",
                hex::encode(anchor_id)
            )));
        };
        let Some(document) = SignedDocument::from_payload(&anchor.body.payload) else {
            return Ok(None);
        };
        let declared = match ContractRef::from_doc(&document.doc) {
            Ok(None) => return Ok(None),
            Ok(Some(declared)) => declared,
            Err(reason) => {
                return Ok(Some(ContractOutlook::unresolved(&document, vec![reason])))
            }
        };
        let contract_id = declared.parse_id().unwrap_or([0u8; 32]);
        let outlook = match self.resolve_contract(&declared) {
            Err(reason) => ContractOutlook::unresolved(&document, vec![reason]),
            // A WASM-body contract is not DSL-judgeable: its verdict is a
            // function of the future satisfying document itself, not of
            // citation-side evidence, so it cannot be decomposed into
            // pending conditions. Walkers still see the anchor, the rule,
            // and the reason; readiness arrives with the document.
            Ok(spec) if spec.wasm.is_some() => ContractOutlook {
                contract_id,
                version: declared.version,
                kind: document.kind.clone(),
                admits: spec.admits.clone(),
                ready: false,
                reasons: vec![
                    "the rule is a wasm predicate; the pending view requires the satisfying document".into(),
                ],
                conditions: Vec::new(),
                citing: Vec::new(),
            },
            Ok(spec) => {
                // Every stored entry citing the anchor is candidate evidence
                // for a future satisfying document.
                let citing_entries: Vec<Entry> = self
                    .all_entries()?
                    .into_iter()
                    .filter(|entry| entry.body.refs.iter().any(|r| r == anchor_id))
                    .collect();
                let citing: Vec<CitedEntry> = citing_entries
                    .iter()
                    .map(|entry| {
                        Ok::<_, StoreError>(CitedEntry {
                            id: entry.id().map_err(StoreError::Core)?,
                            author: entry.body.author.clone(),
                            namespace: entry.body.namespace.clone(),
                            kind: SignedDocument::from_payload(&entry.body.payload)
                                .map(|doc| doc.kind),
                            timestamp_ms: entry.body.timestamp_ms,
                        })
                    })
                    .collect::<StoreResult<_>>()?;
                let closure: Vec<ClosureEntry> = citing_entries
                    .into_iter()
                    .map(|entry| {
                        Ok::<_, StoreError>(ClosureEntry {
                            id: entry.id().map_err(StoreError::Core)?,
                            author: entry.body.author.clone(),
                            timestamp_ms: entry.body.timestamp_ms,
                            document: SignedDocument::from_payload(&entry.body.payload),
                        })
                    })
                    .collect::<StoreResult<_>>()?;
                // Judge only the citation-side predicates: evaluate a
                // synthetic future document of the admitted kind carrying
                // the anchor's fields (the deadline lives there), then keep
                // the deadline and refs conditions.
                let future = SignedDocument::new(&spec.admits, document.doc.clone());
                let report = spec.evaluate_report(&future, anchor.body.timestamp_ms, &closure);
                let conditions: Vec<ConditionStatus> = report
                    .conditions
                    .into_iter()
                    .filter(|condition| {
                        matches!(
                            condition.kind,
                            ConditionKind::Deadline | ConditionKind::Refs
                        )
                    })
                    .collect();
                let ready = conditions.iter().all(|condition| condition.met);
                ContractOutlook {
                    contract_id,
                    version: declared.version,
                    kind: document.kind.clone(),
                    admits: spec.admits.clone(),
                    ready,
                    reasons: Vec::new(),
                    conditions,
                    citing,
                }
            }
        };
        Ok(Some(outlook))
    }
}

/// The pending view of the contract an anchor document declares.
#[derive(Debug, Clone)]
pub struct ContractOutlook {
    /// Declared contract entry id (all-zero when unresolvable).
    pub contract_id: [u8; 32],
    pub version: u8,
    /// Kind of the anchor document (e.g. the escrow agreement).
    pub kind: String,
    /// Kind a satisfying future document must carry.
    pub admits: String,
    /// Are the citation-side requirements already satisfied by the
    /// evidence this node can see?
    pub ready: bool,
    /// Why not (resolution failures; empty when the contract resolved).
    pub reasons: Vec<String>,
    /// Citation-side conditions only (deadline + refs).
    pub conditions: Vec<ConditionStatus>,
    /// Entries citing the anchor, insertion order - the evidence so far.
    pub citing: Vec<CitedEntry>,
}

impl ContractOutlook {
    fn unresolved(document: &SignedDocument, reasons: Vec<String>) -> ContractOutlook {
        ContractOutlook {
            contract_id: [0u8; 32],
            version: 0,
            kind: document.kind.clone(),
            admits: String::new(),
            ready: false,
            reasons,
            conditions: Vec::new(),
            citing: Vec::new(),
        }
    }
}

/// One piece of evidence in the pending view: a stored entry citing the
/// anchor agreement.
#[derive(Debug, Clone)]
pub struct CitedEntry {
    pub id: [u8; 32],
    pub author: String,
    pub namespace: String,
    /// Document kind when the payload is a signed document.
    pub kind: Option<String>,
    pub timestamp_ms: u64,
}
