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
//!
//! Freshness (design §H) is a separate question from validity: a chain can
//! verify perfectly and still be an old one. [`status`] answers both, and
//! never pretends that a node can know about a revocation it never received.

use crate::policy::{WritePolicy, POLICY_VERSION};
use crate::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

/// How well this node can place a verified manifest in time (design §H).
/// Deliberately not a claim about the world: `Unverified` and `Stale` are
/// *absence of evidence*, and a node can never know about a revocation it
/// has not received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// The chain verifies and an independent checkpoint dated at or after
    /// the head manifest exists, so this node is not looking at a silent,
    /// abandoned past.
    Current,
    /// The chain verifies but freshness cannot be established (no
    /// independent checkpoint at/after it) or newer evidence shows this view
    /// is behind (a manifest naming a predecessor this node does not hold, or
    /// a manifest it cannot evaluate). Keep serving; never call it current.
    Stale,
    /// No chain verifies at all for this node: no genesis from the pinned
    /// root, unreadable namespace, or an unsupported policy version.
    Unverified,
    /// Competing valid claims to the same succession: a governance dispute.
    Conflicted,
}

impl Freshness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Freshness::Current => "current",
            Freshness::Stale => "stale",
            Freshness::Unverified => "unverified",
            Freshness::Conflicted => "conflicted",
        }
    }
}

/// What this node can say about a mesh's governance right now. Returned by
/// [`status`], which never errors: "cannot verify" is an answer, not a crash.
#[derive(Clone, Debug)]
pub struct ManifestStatus {
    pub freshness: Freshness,
    /// Plain-language justification for `freshness`.
    pub reason: String,
    /// Newest verified manifest, when a chain verifies.
    pub manifest_id: Option<String>,
    pub author: Option<String>,
    pub published_ms: Option<u64>,
    pub roots: Vec<String>,
    /// Verified chain, oldest first.
    pub chain_ids: Vec<String>,
    /// Signer of the checkpoint that established freshness (independent of
    /// the head manifest's author).
    pub corroborated_by: Option<String>,
    /// Manifest ids named as predecessors that this node does not hold -
    /// evidence that a newer chain exists somewhere this node cannot reach.
    pub missing_predecessors: Vec<String>,
    /// Competing claims (entry id, author) when the chain is conflicted.
    pub conflicts: Vec<(String, String)>,
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

/// One manifest entry that passed the cheap structural filter, with the
/// fields the chain rules and freshness need.
#[derive(Clone, Debug)]
struct Loaded {
    id: String,
    author: String,
    timestamp_ms: u64,
    doc: ManifestDoc,
}

/// Everything the manifest namespace yields: what can be evaluated, and what
/// this build cannot evaluate (a policy version from the future, say).
struct Docs {
    valid: Vec<Loaded>,
    /// (entry id, policy version) of otherwise well-formed manifests this
    /// build cannot evaluate. Their existence is a freshness fact.
    unsupported: Vec<(String, u8)>,
}

/// Read the manifest namespace for `network_id`. Junk (unparseable payloads,
/// wrong network id, empty roots) is ignored - observers hold anything,
/// linkage carries authority.
fn load_docs(store: &Store, network_id: &str) -> Result<Docs, String> {
    let ns = manifest_namespace(network_id);
    let entries = store
        .list(Some(&ns), None, 100_000)
        .map_err(|e| format!("cannot read manifest namespace: {e}"))?;
    let mut docs = Docs {
        valid: Vec::new(),
        unsupported: Vec::new(),
    };
    for entry in &entries {
        let Ok(doc) = serde_json::from_slice::<ManifestDoc>(&entry.body.payload) else {
            continue;
        };
        if doc.network_id != network_id || doc.version != 1 || doc.roots.is_empty() {
            continue;
        }
        let id = hex::encode(entry.id().map_err(|e| e.to_string())?);
        if doc.policy.version > POLICY_VERSION {
            docs.unsupported.push((id, doc.policy.version));
            continue;
        }
        docs.valid.push(Loaded {
            id,
            author: entry.body.author.clone(),
            timestamp_ms: entry.body.timestamp_ms,
            doc,
        });
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
    compile_impl(store, network_id, Some(pinned_roots))
}

/// `pinned: None` = no pin to check against (a node that already trusted
/// whatever chain it holds, e.g. the publisher asking "is my view fresh?").
fn compile_impl(
    store: &Store,
    network_id: &str,
    pinned: Option<&[String]>,
) -> Result<Option<CompiledManifest>, String> {
    let docs = load_docs(store, network_id)?.valid;

    // Genesis: supersedes = None, authored by a pinned root (or by anyone,
    // when there is no pin to check).
    let geneses: Vec<&Loaded> = docs
        .iter()
        .filter(|m| m.doc.supersedes.is_none() && author_pinned(&m.author, pinned))
        .collect();
    if geneses.is_empty() {
        return Ok(None);
    }
    if geneses.len() > 1 {
        return Err(format!(
            "manifest split at genesis: {} pinned-root manifests exist ({}…) - a governance dispute, fail-visible by design",
            geneses.len(),
            geneses[0].id
        ));
    }

    let mut chain: Vec<(String, String, Option<String>)> = Vec::new();
    let (mut current_id, mut current_doc) = (geneses[0].id.clone(), geneses[0].doc.clone());
    chain.push((geneses[0].id.clone(), geneses[0].author.clone(), current_doc.note.clone()));

    loop {
        // Only continuations signed by a key the *current* manifest still
        // names are candidates. Anything else - a retired root, a stranger,
        // junk - is invisible here, so it can neither link nor manufacture a
        // split. A split is two *authorized* claims to the same succession.
        let nexts: Vec<&Loaded> = docs
            .iter()
            .filter(|m| m.doc.supersedes.as_deref() == Some(current_id.as_str()))
            .filter(|m| current_doc.roots.iter().any(|r| *r == m.author))
            .collect();
        match nexts.len() {
            0 => break,
            1 => {
                let m = nexts[0];
                chain.push((m.id.clone(), m.author.clone(), m.doc.note.clone()));
                current_id = m.id.clone();
                current_doc = m.doc.clone();
            }
            _ => {
                return Err(format!(
                    "manifest split after {current_id}: {} different continuations exist (by {}) - a governance dispute, fail-visible by design",
                    nexts.len(),
                    nexts.iter().map(|m| m.author[..8.min(m.author.len())].to_string()).collect::<Vec<_>>().join(", ")
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
    let docs = load_docs(store, network_id)?.valid;

    let geneses: Vec<&Loaded> = docs.iter().filter(|m| m.doc.supersedes.is_none()).collect();
    if geneses.is_empty() {
        return Ok(None);
    }
    if geneses.len() > 1 {
        return Err(format!(
            "manifest split at genesis: {} founding manifests exist (by {}) - resolve the dispute before publishing",
            geneses.len(),
            geneses.iter().map(|m| m.author[..8.min(m.author.len())].to_string()).collect::<Vec<_>>().join(", ")
        ));
    }

    let (mut current_id, mut current_roots) =
        (geneses[0].id.clone(), geneses[0].doc.roots.clone());
    loop {
        let nexts: Vec<&Loaded> = docs
            .iter()
            .filter(|m| m.doc.supersedes.as_deref() == Some(current_id.as_str()))
            .filter(|m| current_roots.iter().any(|r| *r == m.author))
            .collect();
        match nexts.len() {
            0 => return Ok(Some((current_id, current_roots))),
            1 => {
                let m = nexts[0];
                current_id = m.id.clone();
                current_roots = m.doc.roots.clone();
            }
            _ => {
                return Err(format!(
                    "manifest split after {current_id}: {} different continuations exist (by {}) - resolve the dispute before publishing",
                    nexts.len(),
                    nexts.iter().map(|m| m.author[..8.min(m.author.len())].to_string()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
}

/// This node's full, non-failing answer about a mesh's governance: does a
/// chain verify, and can its currency be justified? (design §H)
///
/// `Current` needs an *independent* checkpoint - one signed by a key other
/// than the head manifest's author and dated at or after it - because a
/// manifest nothing else has ever referenced may already have been replaced
/// by one this node never received. That is the honest limit of an offline
/// node, and it is reported rather than papered over.
pub fn status(
    store: &Store,
    network_id: &str,
    pinned_roots: &[String],
) -> Result<ManifestStatus, String> {
    status_impl(store, network_id, Some(pinned_roots))
}

/// Freshness of the chain this node holds, without checking it against a pin:
/// "is my view current?" for a node that has already accepted its chain.
pub fn status_unpinned(store: &Store, network_id: &str) -> Result<ManifestStatus, String> {
    status_impl(store, network_id, None)
}

fn status_impl(
    store: &Store,
    network_id: &str,
    pinned: Option<&[String]>,
) -> Result<ManifestStatus, String> {
    let docs = load_docs(store, network_id)?;
    let mut st = ManifestStatus {
        freshness: Freshness::Unverified,
        reason: String::new(),
        manifest_id: None,
        author: None,
        published_ms: None,
        roots: Vec::new(),
        chain_ids: Vec::new(),
        corroborated_by: None,
        missing_predecessors: Vec::new(),
        conflicts: Vec::new(),
    };

    // Evidence that a newer chain exists somewhere this node cannot reach: a
    // manifest naming a predecessor this node does not hold.
    let held: BTreeSet<&str> = docs.valid.iter().map(|m| m.id.as_str()).collect();
    for m in &docs.valid {
        if let Some(prev) = &m.doc.supersedes {
            if !held.contains(prev.as_str()) && !st.missing_predecessors.contains(prev) {
                st.missing_predecessors.push(prev.clone());
            }
        }
    }

    let compiled = match compile_impl(store, network_id, pinned) {
        Ok(c) => c,
        Err(e) => {
            let split = e.contains("split");
            st.freshness = if split {
                Freshness::Conflicted
            } else {
                Freshness::Unverified
            };
            st.reason = e;
            if split {
                st.conflicts = competing_claims(&docs.valid, pinned);
            }
            return Ok(st);
        }
    };

    let Some(c) = compiled else {
        st.reason = match docs.unsupported.first() {
            Some((id, v)) => format!(
                "manifest {} carries policy version {v}, which this build cannot evaluate",
                &id[..8.min(id.len())]
            ),
            None => "no manifest authored by the pinned root - nothing verifies".into(),
        };
        return Ok(st);
    };

    st.manifest_id = Some(c.manifest_id.clone());
    st.chain_ids = c.chain.iter().map(|(id, _, _)| id.clone()).collect();
    let head_entry = docs.valid.iter().find(|m| m.id == c.manifest_id);
    st.author = head_entry.map(|m| m.author.clone());
    st.published_ms = head_entry.map(|m| m.timestamp_ms);
    st.roots = c.doc.roots.clone();

    // Staleness by positive evidence: a manifest from a future of this chain,
    // or a policy version this build cannot read.
    if let Some((id, v)) = docs.unsupported.first() {
        st.freshness = Freshness::Stale;
        st.reason = format!(
            "this node holds a manifest ({}) carrying policy version {v} it cannot evaluate - a newer governance act exists that it cannot apply",
            &id[..8.min(id.len())]
        );
        return Ok(st);
    }
    if !st.missing_predecessors.is_empty() {
        st.freshness = Freshness::Stale;
        st.reason = format!(
            "this node holds a manifest naming predecessor {} as superseded, but not that predecessor - the mesh has moved past this view",
            &st.missing_predecessors[0][..8.min(st.missing_predecessors[0].len())]
        );
        return Ok(st);
    }

    // Staleness by absent evidence: nothing independent ever confirmed that
    // this manifest outlived its own publication.
    let (author, published) = match (&st.author, st.published_ms) {
        (Some(a), Some(t)) => (a.clone(), t),
        _ => (String::new(), 0),
    };
    let witness = store
        .all_checkpoints()
        .map_err(|e| format!("cannot read checkpoints: {e}"))?
        .into_iter()
        .find(|c| c.body.signer != author && c.body.timestamp_ms >= published);
    match witness {
        Some(c) => {
            st.corroborated_by = Some(c.body.signer.clone());
            st.freshness = Freshness::Current;
            st.reason = format!(
                "checkpoint by {} at {} is independent of this manifest's author and not older than it",
                &c.body.signer[..8.min(c.body.signer.len())],
                c.body.timestamp_ms
            );
        }
        None => {
            st.freshness = Freshness::Stale;
            st.reason = "no independent checkpoint at or after this manifest - freshness cannot be established, and a newer manifest may exist that this node has not received".into();
        }
    }
    Ok(st)
}

/// Does `author` satisfy the pin? No pin means "no check to make".
fn author_pinned(author: &str, pinned: Option<&[String]>) -> bool {
    pinned.map_or(true, |roots| roots.iter().any(|r| r == author))
}

/// The competing claims behind a split, for reporting. Best effort: it is
/// only called once `compile` has already refused to choose.
fn competing_claims(docs: &[Loaded], pinned: Option<&[String]>) -> Vec<(String, String)> {
    let geneses: Vec<&Loaded> = docs
        .iter()
        .filter(|m| m.doc.supersedes.is_none() && author_pinned(&m.author, pinned))
        .collect();
    if geneses.len() > 1 {
        return geneses
            .iter()
            .map(|m| (m.id.clone(), m.author.clone()))
            .collect();
    }
    // A continuation split: report every continuation of any manifest that has
    // more than one authorized claimant.
    let mut out = Vec::new();
    for m in docs {
        let mut claimants: Vec<&Loaded> = docs
            .iter()
            .filter(|n| n.doc.supersedes.as_deref() == Some(m.id.as_str()))
            .filter(|n| m.doc.roots.iter().any(|r| *r == n.author))
            .collect();
        claimants.sort_by(|a, b| a.id.cmp(&b.id));
        if claimants.len() > 1 {
            out.extend(claimants.iter().map(|n| (n.id.clone(), n.author.clone())));
        }
    }
    out
}
