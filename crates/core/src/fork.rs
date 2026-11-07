//! Fork evidence analysis: proving that a signer served contradictory
//! histories.
//!
//! A single checkpoint proves nothing by itself - the power comes from
//! *comparing* checkpoint streams collected from independent sources. If the
//! same signer signed two different checkpoints at the same height, at least
//! one of the two histories is fabricated, and the pair of signed records is
//! evidence that stands on its own.

use crate::checkpoint::Checkpoint;
use crate::error::Result;
use std::collections::{BTreeMap, HashSet};

pub const KIND_SAME_HEIGHT_FORK: &str = "same-height-fork";
pub const KIND_CHAIN_BREAK: &str = "chain-break";

/// One independently-verifiable piece of fork evidence. Every checkpoint in
/// `checkpoints` carries its own hybrid signature, so the evidence file can be
/// re-verified by anyone with no other context.
#[derive(Debug, Clone)]
pub struct ForkEvidence {
    pub kind: &'static str,
    pub signer: String,
    pub height: u64,
    pub description: String,
    pub checkpoints: Vec<Checkpoint>,
}

/// Compare two checkpoint streams (each typically collected from a different
/// source). Verifies every signature first; then detects:
///
/// - `same-height-fork`: the same signer has two different checkpoints at the
///   same height (across streams, or duplicated within one stream) - proof
///   that at least one history is fabricated;
/// - `chain-break`: within one stream, a signer's checkpoint does not chain to
///   its predecessor - proof of rewriting or splicing.
pub fn analyze(stream_a: &[Checkpoint], stream_b: &[Checkpoint]) -> Result<Vec<ForkEvidence>> {
    for cp in stream_a.iter().chain(stream_b.iter()) {
        cp.verify()?;
    }

    let mut evidence: Vec<ForkEvidence> = Vec::new();

    internal_scan(stream_a, "stream A", &mut evidence)?;
    internal_scan(stream_b, "stream B", &mut evidence)?;

    let mut index_a: BTreeMap<(&str, u64), &Checkpoint> = BTreeMap::new();
    for cp in stream_a {
        index_a.insert((cp.body.signer.as_str(), cp.body.height), cp);
    }
    for cp in stream_b {
        if let Some(other) = index_a.get(&(cp.body.signer.as_str(), cp.body.height)) {
            if other.id()? != cp.id()? {
                evidence.push(ForkEvidence {
                    kind: KIND_SAME_HEIGHT_FORK,
                    signer: cp.body.signer.clone(),
                    height: cp.body.height,
                    description: format!(
                        "signer {} signed two different checkpoints at height {} ({} vs {}): at least one history is fabricated",
                        short(&cp.body.signer),
                        cp.body.height,
                        hex::encode(other.id()?),
                        hex::encode(cp.id()?)
                    ),
                    checkpoints: vec![(*other).clone(), cp.clone()],
                });
            }
        }
    }

    dedup(evidence)
}

fn internal_scan(
    stream: &[Checkpoint],
    label: &str,
    evidence: &mut Vec<ForkEvidence>,
) -> Result<()> {
    let mut seen: BTreeMap<(String, u64), &Checkpoint> = BTreeMap::new();
    for cp in stream {
        let key = (cp.body.signer.clone(), cp.body.height);
        match seen.get(&key) {
            Some(existing) => {
                if existing.id()? != cp.id()? {
                    evidence.push(ForkEvidence {
                        kind: KIND_SAME_HEIGHT_FORK,
                        signer: cp.body.signer.clone(),
                        height: cp.body.height,
                        description: format!(
                            "signer {} has two different checkpoints at height {} within {label}: at least one history is fabricated",
                            short(&cp.body.signer),
                            cp.body.height
                        ),
                        checkpoints: vec![(*existing).clone(), cp.clone()],
                    });
                }
            }
            None => {
                seen.insert(key, cp);
            }
        }
    }

    let mut by_signer: BTreeMap<&str, Vec<&Checkpoint>> = BTreeMap::new();
    for cp in stream {
        by_signer
            .entry(cp.body.signer.as_str())
            .or_default()
            .push(cp);
    }
    for (signer, mut cps) in by_signer {
        cps.sort_by_key(|c| c.body.height);
        for pair in cps.windows(2) {
            let (prev, cur) = (pair[0], pair[1]);
            if cur.body.height == prev.body.height + 1 && cur.body.prev != Some(prev.id()?) {
                evidence.push(ForkEvidence {
                    kind: KIND_CHAIN_BREAK,
                    signer: signer.to_string(),
                    height: cur.body.height,
                    description: format!(
                        "signer {} height {} does not chain to its height {}: checkpoint history was rewritten or spliced",
                        short(signer),
                        cur.body.height,
                        prev.body.height
                    ),
                    checkpoints: vec![(*prev).clone(), (*cur).clone()],
                });
            }
        }
    }
    Ok(())
}

fn dedup(evidence: Vec<ForkEvidence>) -> Result<Vec<ForkEvidence>> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for ev in evidence {
        let mut ids: Vec<String> = ev
            .checkpoints
            .iter()
            .map(|c| c.id().map(hex::encode))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.sort();
        let key = format!("{}|{}|{}|{}", ev.kind, ev.signer, ev.height, ids.join(","));
        if seen.insert(key) {
            out.push(ev);
        }
    }
    Ok(out)
}

fn short(s: &str) -> &str {
    &s[..8.min(s.len())]
}
