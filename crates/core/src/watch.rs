//! Watching an identity chain: two snapshots of `/v1/identity/{key}` in,
//! the events between them out.
//!
//! A citizen whose key was revoked, or a registry whose attestation was
//! revoked by someone it trusts, has no reason to find out by luck. This
//! module is the honest core of `datu watch`: parse the chain JSON into
//! comparable facts, diff two snapshots into ordered events, and let the
//! caller decide what an event means. Signatures were verified by the node
//! that served the chain; nothing here invents a verdict.

use serde_json::Value;
use std::collections::BTreeMap;

/// Who revoked something, with their optional reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoker {
    pub by: String,
    pub reason: Option<String>,
}

/// One attestation, reduced to the facts a watcher cares about.
#[derive(Clone, Debug, PartialEq)]
pub struct AttestationView {
    pub id: String,
    pub by: String,
    pub label: Option<String>,
    pub claims: Value,
    /// Distinct cosigner count (the chain only exposes their keys; the
    /// count is what changes weight).
    pub cosigners: usize,
    /// The enrollment ceremony that produced this attestation, when present.
    pub enroll: Option<String>,
    /// Set when a revocation statement names this attestation.
    pub revoked_by: Option<Revoker>,
}

/// The facts of one `/v1/identity` answer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChainSnapshot {
    pub attestations: BTreeMap<String, AttestationView>,
    /// Set when a revocation names the watched key directly.
    pub key_revoker: Option<Revoker>,
}

fn revoker(value: &Value) -> Option<Revoker> {
    let by = value.get("by")?.as_str()?.to_string();
    Some(Revoker {
        by,
        reason: value
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Parse a chain answer into a snapshot. Errors name the field, because a
/// watcher that misreads a chain is worse than one that refuses to.
pub fn snapshot(chain: &Value) -> Result<ChainSnapshot, String> {
    let attestations = chain
        .get("attestations")
        .and_then(Value::as_array)
        .ok_or_else(|| "identity chain has no attestations array".to_string())?;
    let mut out = BTreeMap::new();
    for (i, a) in attestations.iter().enumerate() {
        let id = a
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("attestation {i} has no id"))?
            .to_string();
        let by = a
            .get("by")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("attestation {id} has no by"))?
            .to_string();
        let cosigners = a
            .get("cosigners")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        out.insert(
            id.clone(),
            AttestationView {
                id,
                by,
                label: a.get("label").and_then(Value::as_str).map(str::to_string),
                claims: a.get("claims").cloned().unwrap_or(Value::Null),
                cosigners,
                enroll: a.get("enroll").and_then(Value::as_str).map(str::to_string),
                revoked_by: a
                    .get("revoked_by")
                    .filter(|v| !v.is_null())
                    .and_then(revoker),
            },
        );
    }
    Ok(ChainSnapshot {
        attestations: out,
        key_revoker: chain
            .get("revoked_by_key")
            .filter(|v| !v.is_null())
            .and_then(revoker),
    })
}

/// Something that happened between two snapshots, in the order a human
/// reads it: what gained weight first, then what was taken away.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    AttestationAdded {
        id: String,
        by: String,
        label: Option<String>,
        claims: Value,
        cosigners: usize,
        enroll: Option<String>,
    },
    CosignersGained {
        id: String,
        by: String,
        cosigners: usize,
    },
    AttestationRevoked {
        id: String,
        by: String,
        reason: Option<String>,
    },
    KeyRevoked {
        by: String,
        reason: Option<String>,
    },
}

/// The events between `prev` and `next`. Identical snapshots yield none;
/// events never repeat, because each is a state transition.
pub fn diff(prev: &ChainSnapshot, next: &ChainSnapshot) -> Vec<Event> {
    let mut added = Vec::new();
    let mut gained = Vec::new();
    let mut revoked = Vec::new();
    for (id, a) in &next.attestations {
        match prev.attestations.get(id) {
            None => added.push(Event::AttestationAdded {
                id: id.clone(),
                by: a.by.clone(),
                label: a.label.clone(),
                claims: a.claims.clone(),
                cosigners: a.cosigners,
                enroll: a.enroll.clone(),
            }),
            Some(before) => {
                if a.cosigners > before.cosigners {
                    gained.push(Event::CosignersGained {
                        id: id.clone(),
                        by: a.by.clone(),
                        cosigners: a.cosigners,
                    });
                }
                if before.revoked_by.is_none() {
                    if let Some(r) = &a.revoked_by {
                        revoked.push(Event::AttestationRevoked {
                            id: id.clone(),
                            by: r.by.clone(),
                            reason: r.reason.clone(),
                        });
                    }
                }
            }
        }
    }
    let mut out = added;
    out.extend(gained);
    out.extend(revoked);
    if prev.key_revoker.is_none() {
        if let Some(r) = &next.key_revoker {
            out.push(Event::KeyRevoked {
                by: r.by.clone(),
                reason: r.reason.clone(),
            });
        }
    }
    out
}

/// True when the key itself is revoked: the terminal state a watcher exits on.
pub fn key_revoked(snapshot: &ChainSnapshot) -> bool {
    snapshot.key_revoker.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain(attestations: Value, key_revoke: Value) -> Value {
        json!({
            "key": "aa",
            "attestations": attestations,
            "revoked_by_key": key_revoke,
            "counts": {"attestations": 0, "distinct_cosigners": 0, "revoked": 0},
            "verified": true,
            "note": "statements, not a verdict",
        })
    }

    fn att(id: &str, cosigners: usize, revoked: Value) -> Value {
        json!({
            "id": id,
            "by": "d53ad911",
            "label": "Acme Ltd",
            "claims": {"role": "clerk"},
            "cosigners": vec!["k1"; cosigners],
            "enroll": null,
            "revoked": !revoked.is_null(),
            "revoked_by": revoked,
        })
    }

    #[test]
    fn parse_and_diff_a_new_attestation() {
        let before = snapshot(&chain(json!([]), Value::Null)).unwrap();
        let after = snapshot(&chain(json!([att("a1", 1, Value::Null)]), Value::Null)).unwrap();
        let events = diff(&before, &after);
        assert_eq!(
            events,
            vec![Event::AttestationAdded {
                id: "a1".into(),
                by: "d53ad911".into(),
                label: Some("Acme Ltd".into()),
                claims: json!({"role": "clerk"}),
                cosigners: 1,
                enroll: None,
            }]
        );
        assert!(!key_revoked(&after));
    }

    #[test]
    fn cosigners_and_revocations_are_transitions_not_repeats() {
        let base = snapshot(&chain(json!([att("a1", 0, Value::Null)]), Value::Null)).unwrap();
        let more = snapshot(&chain(json!([att("a1", 2, Value::Null)]), Value::Null)).unwrap();
        assert_eq!(
            diff(&base, &more),
            vec![Event::CosignersGained {
                id: "a1".into(),
                by: "d53ad911".into(),
                cosigners: 2
            }]
        );
        assert!(diff(&more, &more).is_empty(), "no change, no events");

        let kill = json!({"by": "d53ad911", "reason": "left the registry"});
        let revoked = snapshot(&chain(json!([att("a1", 2, kill)]), Value::Null)).unwrap();
        assert_eq!(
            diff(&more, &revoked),
            vec![Event::AttestationRevoked {
                id: "a1".into(),
                by: "d53ad911".into(),
                reason: Some("left the registry".into())
            }]
        );
        // A second snapshot with the same revocation repeats nothing.
        assert!(diff(&revoked, &revoked).is_empty());
    }

    #[test]
    fn key_revocation_is_reported_once() {
        let base = snapshot(&chain(json!([]), Value::Null)).unwrap();
        let kill = json!({"by": "d53ad911", "reason": "key compromised"});
        let revoked = snapshot(&chain(json!([]), kill)).unwrap();
        assert!(key_revoked(&revoked));
        assert_eq!(
            diff(&base, &revoked),
            vec![Event::KeyRevoked {
                by: "d53ad911".into(),
                reason: Some("key compromised".into())
            }]
        );
        assert!(diff(&revoked, &revoked).is_empty());
    }

    #[test]
    fn malformed_chains_are_refused() {
        assert!(snapshot(&json!({})).unwrap_err().contains("attestations"));
        let bad = chain(json!([{"by": "x"}]), Value::Null);
        assert!(snapshot(&bad).unwrap_err().contains("no id"));
        let bad = chain(json!([{"id": "a1"}]), Value::Null);
        assert!(snapshot(&bad).unwrap_err().contains("no by"));
    }
}
