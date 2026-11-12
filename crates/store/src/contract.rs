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
    is_contracts_namespace, ClosureEntry, ConditionStatus, ContractRef, ContractSpec,
    CONTRACTS_NAMESPACE,
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
                let report = spec.evaluate_report(&document, &self.closure_of(entry));
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
}
