//! Writer policy: the gate for who may write to gated namespaces.
//!
//! This is a *government-grade* admission control that keeps the network
//! permissionless to run:
//!
//! - **Observers stay free**: with no policy file, a node accepts everything
//!   (open mirror mode). Anyone can run a node, sync, read, and witness -
//!   no gate, ever.
//! - **Gated namespaces** (e.g. `gov.*`, `identity.attest`): only admitted
//!   writers may land entries there. Admission is:
//!     1. the author is a configured trust root (attestor) or explicit
//!        writer, **or**
//!     2. the author holds a valid attestation *from a configured
//!        attestor*, optionally with `min_cosigners` independent cosignatures.
//! - **Read-only mode** (`readonly: true`) accepts no writes at all - a pure
//!   view/witness mirror.
//!
//! The policy is *local node policy*, not a global permission: it is
//! enforced by each node on every transport (HTTP submission, p2p pull,
//! delta merge, bundle import), and it is rooted in the attestation graph -
//! the same keys whose signatures make entries attributable. A rogue writer
//! cannot enter gated namespaces on any policy-abiding node; their entries
//! still verify and remain attributable elsewhere (open mirrors keep them),
//! so nothing is censored - it just never counts as official.

use datu_core::parties::SignedDocument;
use datu_core::Entry;
use crate::{Store, StoreError, StoreResult};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WritePolicy {
    pub version: u8,
    /// Reject every write (pure observer/witness mirror).
    #[serde(default)]
    pub readonly: bool,
    /// Namespace patterns under which only admitted writers may write.
    /// `gov.*` matches every `gov.` namespace; a pattern without `*` is an
    /// exact match.
    #[serde(default)]
    pub gated: Vec<String>,
    /// Explicitly admitted author keys (hex Ed25519).
    #[serde(default)]
    pub writers: Vec<String>,
    /// Trust roots: their attestations vouch for other writers. Authors in
    /// this list may also write gated namespaces directly.
    #[serde(default)]
    pub attestors: Vec<String>,
    /// Minimum distinct cosigners required on an attestation for it to
    /// admit its subject (0 = the attestor's signature alone suffices).
    #[serde(default)]
    pub min_cosigners: usize,
    /// Party-consent roles that every gated entry MUST carry as verified
    /// party signatures (see `datu_core::parties`), e.g. `["holder"]` for
    /// land titles: the citizen the record is about must have signed it.
    /// `rules` adds per-namespace refinements on top of this global list.
    #[serde(default)]
    pub required_roles: Vec<String>,
    /// Per-namespace party rules. Each rule whose `ns` pattern matches the
    /// entry adds role requirements for that namespace only - so titles can
    /// demand a `holder` while bids demand a `bidder`, in one policy.
    #[serde(default)]
    pub rules: Vec<NamespaceRule>,
    /// Namespaces admitted **even when gated** (pattern match like `gated`).
    /// One use: governance bootstrap. A node that pins a manifest root but has
    /// not received the chain yet must still be able to fetch the chain and
    /// nothing else, so it runs with `gated: ["*"], allow: [chain-ns]` until
    /// the chain verifies and the real policy takes over.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// One party requirement inside a namespace rule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RoleRule {
    /// Role that must carry a verified party signature, e.g. "holder".
    pub role: String,
    /// If set, the signing party's key must be exactly this key (hex) -
    /// e.g. only the registry's own key may sign `registrar`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// If set, the signing party's key must equal the value of this
    /// top-level document field (hex string). This is self-binding: the
    /// `holder_key` named inside the document must be the key that signed
    /// the `holder` role - whoever the record is about, and only them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_field: Option<String>,
}

/// Party requirements that apply to one namespace pattern (glob like
/// `gov.titles.*`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NamespaceRule {
    pub ns: String,
    #[serde(default)]
    pub require: Vec<RoleRule>,
    /// Fields that must be **encrypted** (a `datu-sealed-*` object) whenever
    /// they appear in the document. Personal data is never written to the
    /// public ledger in plaintext: the holder's name must be ciphertext for
    /// the parties who may read it. A missing field is fine (nothing to
    /// leak); a present field that is not sealed is denied.
    #[serde(default)]
    pub require_sealed: Vec<String>,
    /// If set, an author may have at most this many entries in this exact
    /// namespace (a glob rule caps every namespace it matches separately -
    /// the count is per namespace, not across the pattern). `1` =
    /// one-per-author: one ballot per voter, one claim per parcel. Duplicates
    /// are denied at admission, not just caught by recounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries_per_author: Option<u32>,
}

pub const POLICY_VERSION: u8 = 1;

impl WritePolicy {
    /// A policy that rejects everything (used by `--read-only` flags).
    pub fn readonly() -> WritePolicy {
        WritePolicy {
            version: POLICY_VERSION,
            readonly: true,
            ..Default::default()
        }
    }

    pub fn from_json(text: &str) -> Result<WritePolicy, String> {
        let policy: WritePolicy =
            serde_json::from_str(text).map_err(|e| format!("bad policy JSON: {e}"))?;
        if policy.version != POLICY_VERSION {
            return Err(format!(
                "unsupported policy version {} (expected {POLICY_VERSION})",
                policy.version
            ));
        }
        Ok(policy)
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    fn namespace_gated(&self, namespace: &str) -> bool {
        if self.allow.iter().any(|pattern| ns_matches(pattern, namespace)) {
            return false;
        }
        self.gated.iter().any(|pattern| ns_matches(pattern, namespace))
    }

    /// The policy a node runs while it holds a pin but no verifiable chain:
    /// the governance namespace is the only thing it may ingest, so evidence
    /// acquisition can bootstrap governance without admitting any data.
    pub fn bootstrap(chain_namespace: &str) -> WritePolicy {
        WritePolicy {
            version: POLICY_VERSION,
            gated: vec!["*".into()],
            allow: vec![chain_namespace.to_string()],
            ..Default::default()
        }
    }
}

fn ns_matches(pattern: &str, namespace: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => namespace.starts_with(prefix),
        None => namespace == pattern,
    }
}

fn required_roles_summary(required: &[RoleRule]) -> String {
    required
        .iter()
        .map(|rule| rule.role.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Store {
    /// Admission decision for an entry under this store's policy.
    /// `None` policy (open observer mode) admits everything.
    ///
    /// For a gated namespace an entry must pass every bar:
    /// 1. the author is admitted (trust root / explicit writer / attested
    ///    by a trust root, with `min_cosigners` independent cosignatures),
    /// 2. if `required_roles` / `rules[].require` is set, the payload is a
    ///    [`datu_core::parties`] signed document carrying a *verified*
    ///    signature for every role - the citizen the record is about must
    ///    have consented,
    /// 3. if `rules[].require_sealed` is set, personal fields are never
    ///    published in plaintext: each listed field that is present must be
    ///    a `datu-sealed-*` object (the holder's name is ciphertext for the
    ///    registry office and the holder - nobody else).
    /// 4. if `rules[].max_entries_per_author` is set, an author over the cap
    ///    in that namespace is denied - one ballot per voter, at admission.
    pub fn gate(&self, entry: &Entry) -> StoreResult<()> {
        let policy = match &self.policy {
            Some(p) => p,
            None => return Ok(()),
        };
        if policy.readonly {
            return Err(StoreError::Denied(
                "this node is read-only (observer/witness mirror)".into(),
            ));
        }
        if !policy.namespace_gated(&entry.body.namespace) {
            return Ok(());
        }
        if !policy.attestors.contains(&entry.body.author)
            && !policy.writers.contains(&entry.body.author)
            && !self.attested_by_root(entry, policy)?
        {
            return Err(StoreError::Denied(format!(
                "namespace '{}' is gated by this node's policy: author {} is not an admitted writer (needs an attestation from a configured attestor - see `datu policy`)",
                entry.body.namespace,
                &entry.body.author[..16.min(entry.body.author.len())]
            )));
        }
        let matching: Vec<&NamespaceRule> = policy
            .rules
            .iter()
            .filter(|rule| ns_matches(&rule.ns, &entry.body.namespace))
            .collect();
        let required: Vec<RoleRule> = policy
            .required_roles
            .iter()
            .map(|role| RoleRule {
                role: role.clone(),
                key: None,
                bind_field: None,
            })
            .chain(matching.iter().flat_map(|rule| rule.require.iter().cloned()))
            .collect();
        let sealed_fields: Vec<&String> = matching
            .iter()
            .flat_map(|rule| rule.require_sealed.iter())
            .collect();
        // The strictest per-author cap among matching rules wins.
        let cap = matching
            .iter()
            .filter_map(|rule| rule.max_entries_per_author)
            .min();
        if required.is_empty() && sealed_fields.is_empty() && cap.is_none() {
            return Ok(());
        }
        let document = match SignedDocument::from_payload(&entry.body.payload) {
            Some(document) => Some(document),
            None => None,
        };
        if !required.is_empty() {
            let document = match &document {
                Some(document) => document,
                None => {
                    return Err(StoreError::Denied(format!(
                        "namespace '{}' requires party signatures ({}) but the payload is not a party-signed document (see `datu parties`)",
                        entry.body.namespace,
                        required_roles_summary(&required)
                    )))
                }
            };
            let parties = match document.verify() {
                Ok(parties) => parties,
                Err(e) => {
                    return Err(StoreError::Denied(format!(
                        "party signatures on this '{}' document do not verify: {e}",
                        document.kind
                    )))
                }
            };
            for rule in &required {
                let satisfied = parties.iter().any(|(role, key)| {
                    role == &rule.role
                        && rule.key.as_ref().map(|k| k == key).unwrap_or(true)
                        && rule
                            .bind_field
                            .as_ref()
                            .map(|field| {
                                document.doc.get(field).and_then(|v| v.as_str())
                                    == Some(key.as_str())
                            })
                            .unwrap_or(true)
                });
                if !satisfied {
                    let mut need = format!("a verified '{}' party signature", rule.role);
                    if let Some(key) = &rule.key {
                        need.push_str(&format!(
                            " by key {} (the only key admitted for this role)",
                            &key[..16.min(key.len())]
                        ));
                    }
                    if let Some(field) = &rule.bind_field {
                        need.push_str(&format!(
                            " whose key equals the document's '{field}' field (the record must be signed by the party it is about)"
                        ));
                    }
                    return Err(StoreError::Denied(format!(
                        "namespace '{}' requires {need} (see `datu policy`)",
                        entry.body.namespace
                    )));
                }
            }
        }
        if !sealed_fields.is_empty() {
            let body = match &document {
                Some(document) => &document.doc,
                None => {
                    return Err(StoreError::Denied(format!(
                        "namespace '{}' requires encrypted fields ({}) but the payload is not a document (see `datu wallet seal`)",
                        entry.body.namespace,
                        sealed_fields
                            .iter()
                            .map(|f| f.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )))
                }
            };
            for field in &sealed_fields {
                if let Some(value) = body.get(field.as_str()) {
                    let sealed = value
                        .get("sealed")
                        .and_then(|s| s.as_str())
                        .map(|s| s.starts_with("datu-sealed-") || s.starts_with("dag-sealed-"))
                        .unwrap_or(false);
                    if !sealed {
                        return Err(StoreError::Denied(format!(
                            "namespace '{}' requires personal field '{field}' to be encrypted: the ledger stores ciphertext only - seal it first with `datu wallet seal`"
                        , entry.body.namespace)));
                    }
                }
            }
        }
        if let Some(cap) = cap {
            let already =
                self.count_by_author_in_namespace(&entry.body.namespace, &entry.body.author)?;
            if already >= u64::from(cap) {
                return Err(StoreError::Denied(format!(
                    "namespace '{}' admits at most {cap} entries per author: {} already has {already} - one ballot per voter, duplicates are denied at admission instead of being left to recounts",
                    entry.body.namespace,
                    &entry.body.author[..16.min(entry.body.author.len())]
                )));
            }
        }
        Ok(())
    }

    /// Is `subject` (a node or writer key) vouched for by any of `attestors`
    /// through on-ledger attestations? This is also the **network admission**
    /// check: membership granted by trust roots, carried by the ledger
    /// itself. (Ignores `min_cosigners`, which refines writer admission
    /// only - joining is a lighter bar than writing.)
    pub fn key_attested_by(&self, subject: &str, attestors: &[String]) -> StoreResult<bool> {
        let entries = self.all_entries()?;
        for (attestation, _doc) in
            datu_core::attest::attestations_for(entries.iter(), subject)
        {
            if attestors.contains(&attestation.body.author) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Is this entry's author vouched for by a configured trust root,
    /// honouring `min_cosigners`?
    fn attested_by_root(&self, entry: &Entry, policy: &WritePolicy) -> StoreResult<bool> {
        let entries = self.all_entries()?;
        for (attestation, _doc) in
            datu_core::attest::attestations_for(entries.iter(), &entry.body.author)
        {
            if !policy.attestors.contains(&attestation.body.author) {
                continue;
            }
            if policy.min_cosigners > 0 {
                let id = attestation.id().map_err(StoreError::Core)?;
                let cosigners = datu_core::attest::cosigners_for(entries.iter(), &id);
                if cosigners.len() < policy.min_cosigners {
                    continue;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
}
