//! On-ledger governance manifests (design §D): the versioned, signed chain
//! that turns "officially recognized" from an implicit per-node policy file
//! into an artifact every observer can verify offline.
//!
//! A manifest is an ordinary hybrid-signed entry in
//! `gov.mesh.<network_id>.policy` whose payload is a [`ManifestDoc`]. The
//! chain rule is the whole authority model:
//!
//! - the **first** manifest (`supersedes: null`) must be authored by a key
//!   this node pinned out-of-band (`network.json` → `manifest_root`);
//! - every **later** manifest must be authored by a key in the *previous*
//!   manifest's `roots` - the current authority authorizes the next;
//! - rotation/revocation = a later manifest whose `roots` omit the key;
//!   key-status-at-signing-time is derivable by replaying the chain.
//!
//! Entries in the manifest namespace that are malformed or authored by
//! non-root keys are simply never linked into the chain - observers may hold
//! anything; governance comes from verifiable linkage. Two *different* valid
//! continuations of the same manifest are a split: a constitutional crisis
//! made visible, reported as an error (fail-visible, never fail-silent).

use crate::policy::{WritePolicy, POLICY_VERSION};
use crate::Store;
use serde::{Deserialize, Serialize};

/// Namespace of a mesh's manifest chain.
pub fn manifest_namespace(network_id: &str) -> String {
    format!("gov.mesh.{network_id}.policy")
}

/// One governance manifest: the writer policy an official mesh runs under,
/// plus the authority that may replace it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestDoc {
    /// Manifest format version (currently 1).
    pub version: u8,
    /// The mesh this chain governs (must match the pinning `network.json`).
    pub network_id: String,
    /// Keys authorized to sign the NEXT manifest. Rotation: add the new key
    /// alongside the old; revocation: omit the old key. A key that is absent
    /// from every later manifest can no longer speak for the mesh.
    pub roots: Vec<String>,
    /// The writer policy this manifest installs - the exact grammar
    /// `datu policy init` writes, compiled straight into the gate.
    pub policy: WritePolicy,
    /// Entry id (hex) of the manifest this one supersedes; `null` on the
    /// first. `datu manifest publish` maintains this link automatically.
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The result of verifying a manifest chain: the newest policy plus the
/// provenance of how it was reached.
#[derive(Debug, Clone)]
pub struct CompiledManifest {
    /// The policy the gate consumes. `readonly` is forced off - read-only is
    /// an operational flag of a node, never a governance act. The current
    /// roots are admitted as attestors so governance can always publish.
    pub policy: WritePolicy,
    /// Entry id (hex) of the newest verified manifest.
    pub manifest_id: String,
    /// The chain, oldest first: (entry id hex, author key hex, note).
    pub chain: Vec<(String, String, Option<String>)>,
    /// The newest manifest document.
    pub doc: ManifestDoc,
}

impl ManifestDoc {
    pub fn new(network_id: &str, roots: Vec<String>, policy: WritePolicy) -> ManifestDoc {
        ManifestDoc {
            version: 1,
            network_id: network_id.to_string(),
            roots,
            policy,
            supersedes: None,
            note: None,
        }
    }
}

/// Read the manifest namespace for `network_id` as `(entry id hex, author
/// key, doc)` triples. Junk (unparseable payloads, wrong network id, empty
/// roots) is ignored - observers hold anything, linkage carries authority.
fn load_docs(
    store: &Store,
    network_id: &str,
) -> Result<Vec<(String, String, ManifestDoc)>, String> {
    let ns = manifest_namespace(network_id);
    let entries = store
        .list(Some(&ns), None, 100_000)
        .map_err(|e| format!("cannot read manifest namespace: {e}"))?;
    let mut docs: Vec<(String, String, ManifestDoc)> = Vec::new();
    for entry in &entries {
        if let Ok(doc) = serde_json::from_slice::<ManifestDoc>(&entry.body.payload) {
            if doc.network_id == network_id && doc.version == 1 && !doc.roots.is_empty() {
                docs.push((
                    hex::encode(entry.id().map_err(|e| e.to_string())?),
                    entry.body.author.clone(),
                    doc,
                ));
            }
        }
    }
    Ok(docs)
}

/// Verify the manifest chain for `network_id` against the out-of-band pinned
/// root keys and compile the newest manifest into a gate-ready policy.
///
/// Returns `Ok(None)` when the namespace holds no manifest at all (the caller
/// decides - a pinned root with no manifest fails closed at the caller).
/// Returns `Err` on a split: two different valid continuations (or two
/// geneses by different pinned roots) - a governance dispute that must be
/// visible, not silently resolved.
pub fn compile(
    store: &Store,
    network_id: &str,
    pinned_roots: &[String],
) -> Result<Option<CompiledManifest>, String> {
    let docs = load_docs(store, network_id)?;

    // Genesis: supersedes = None, authored by a pinned root.
    let geneses: Vec<&(String, String, ManifestDoc)> = docs
        .iter()
        .filter(|(_, author, doc)| doc.supersedes.is_none() && pinned_roots.iter().any(|r| r == author))
        .collect();
    if geneses.is_empty() {
        return Ok(None);
    }
    if geneses.len() > 1 {
        return Err(format!(
            "manifest split at genesis: {} pinned-root manifests exist ({}…) - a governance dispute, fail-visible by design",
            geneses.len(),
            geneses[0].0
        ));
    }

    let mut chain: Vec<(String, String, Option<String>)> = Vec::new();
    let (mut current_id, mut current_doc) = (geneses[0].0.clone(), geneses[0].2.clone());
    chain.push((geneses[0].0.clone(), geneses[0].1.clone(), current_doc.note.clone()));

    loop {
        // Only continuations signed by a key the *current* manifest still
        // names are candidates. Anything else - a retired root, a stranger,
        // junk - is invisible here, so it can neither link nor manufacture a
        // split. A split is two *authorized* claims to the same succession.
        let nexts: Vec<&(String, String, ManifestDoc)> = docs
            .iter()
            .filter(|(_, _, doc)| doc.supersedes.as_deref() == Some(current_id.as_str()))
            .filter(|(_, author, _)| current_doc.roots.iter().any(|r| r == author))
            .collect();
        match nexts.len() {
            0 => break,
            1 => {
                let (id, author, doc) = nexts[0];
                chain.push((id.clone(), author.clone(), doc.note.clone()));
                current_id = id.clone();
                current_doc = doc.clone();
            }
            _ => {
                return Err(format!(
                    "manifest split after {current_id}: {} different continuations exist (by {}) - a governance dispute, fail-visible by design",
                    nexts.len(),
                    nexts.iter().map(|(_, a, _)| a[..8.min(a.len())].to_string()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }

    let mut policy = current_doc.policy.clone();
    policy.version = POLICY_VERSION;
    policy.readonly = false;
    // Governance can always govern: the current roots are admitted as
    // attestors (attestors may write gated namespaces directly), so the next
    // manifest publish is never locked out by the policy it replaces.
    for root in &current_doc.roots {
        if !policy.attestors.contains(root) {
            policy.attestors.push(root.clone());
        }
    }

    Ok(Some(CompiledManifest {
        policy,
        manifest_id: current_id,
        chain,
        doc: current_doc,
    }))
}

/// The current head of the manifest chain regardless of any pinned root -
/// used by `datu manifest publish` to link the next entry and to check that
/// the publishing key is still a root. Returns `(head entry id, roots
/// authorized to continue)`. More than one genesis is a split (fail-visible,
/// same as [`compile`]).
pub fn head(store: &Store, network_id: &str) -> Result<Option<(String, Vec<String>)>, String> {
    let docs = load_docs(store, network_id)?;

    let geneses: Vec<&(String, String, ManifestDoc)> = docs
        .iter()
        .filter(|(_, _, doc)| doc.supersedes.is_none())
        .collect();
    if geneses.is_empty() {
        return Ok(None);
    }
    if geneses.len() > 1 {
        return Err(format!(
            "manifest split at genesis: {} founding manifests exist (by {}) - resolve the dispute before publishing",
            geneses.len(),
            geneses.iter().map(|(_, a, _)| a[..8.min(a.len())].to_string()).collect::<Vec<_>>().join(", ")
        ));
    }

    let (mut current_id, mut current_roots) = (geneses[0].0.clone(), geneses[0].2.roots.clone());
    loop {
        let nexts: Vec<&(String, String, ManifestDoc)> = docs
            .iter()
            .filter(|(_, _, doc)| doc.supersedes.as_deref() == Some(current_id.as_str()))
            .filter(|(_, author, _)| current_roots.iter().any(|r| r == author))
            .collect();
        match nexts.len() {
            0 => return Ok(Some((current_id, current_roots))),
            1 => {
                let (id, _, doc) = nexts[0];
                current_id = id.clone();
                current_roots = doc.roots.clone();
            }
            _ => {
                return Err(format!(
                    "manifest split after {current_id}: {} different continuations exist (by {}) - resolve the dispute before publishing",
                    nexts.len(),
                    nexts.iter().map(|(_, a, _)| a[..8.min(a.len())].to_string()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
}
