/// Order-independent Merkle root over a set of 32-byte ids.
///
/// The input is sorted first, so the root identifies a *set*, not a sequence.
/// Internal nodes hash the 64-byte concatenation of their two children; an
/// odd trailing node is duplicated. The empty set hashes to a fixed sentinel.
pub fn merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() {
        return *blake3::hash(b"datu-empty-set").as_bytes();
    }
    let mut sorted: Vec<[u8; 32]> = items.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut level: Vec<[u8; 32]> = sorted
        .iter()
        .map(|id| *blake3::hash(id).as_bytes())
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_pair(pair[0], right));
        }
        level = next;
    }
    level[0]
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left);
    buf[32..].copy_from_slice(&right);
    *blake3::hash(&buf).as_bytes()
}

/// Sibling path for `id` under the set root computed by [`merkle_root`],
/// leaf level first. `None` when the id is not in the set.
pub fn merkle_proof(items: &[[u8; 32]], id: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
    let mut sorted: Vec<[u8; 32]> = items.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut index = sorted.iter().position(|item| item == id)?;
    let mut level: Vec<[u8; 32]> = sorted
        .iter()
        .map(|item| *blake3::hash(item).as_bytes())
        .collect();
    let mut proof = Vec::new();
    while level.len() > 1 {
        // The odd trailing node is its own sibling (duplicated), matching
        // the root computation exactly.
        let sibling = if index % 2 == 0 {
            level.get(index + 1).copied().unwrap_or(level[index])
        } else {
            level[index - 1]
        };
        proof.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_pair(pair[0], right));
        }
        index /= 2;
        level = next;
    }
    Some(proof)
}

/// Recompute the root that leaf `id` at `index` in a sorted set of `count`
/// ids supports with `proof` (leaf level first). Pure and total: mirrors
/// [`merkle_root`] exactly, and returns `None` when the path cannot
/// describe that position (index out of range, truncated or overlong
/// proof) - a wrong root is not a malformed proof.
pub fn merkle_root_from_proof(
    id: &[u8; 32],
    index: usize,
    count: usize,
    proof: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if count == 0 || index >= count {
        return None;
    }
    let mut node = *blake3::hash(id).as_bytes();
    let mut index = index;
    let mut len = count;
    let mut taken = 0usize;
    while len > 1 {
        let sibling = *proof.get(taken)?;
        taken += 1;
        node = if index % 2 == 1 {
            hash_pair(sibling, node)
        } else {
            hash_pair(node, sibling)
        };
        index /= 2;
        len = len.div_ceil(2);
    }
    (taken == proof.len()).then_some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8 + 1; 32]).collect()
    }

    #[test]
    fn proof_roundtrips_for_every_size_and_leaf() {
        for n in 1..=9 {
            let set = ids(n);
            let root = merkle_root(&set);
            for (index, id) in set.iter().enumerate() {
                let proof = merkle_proof(&set, id).expect("id is in the set");
                assert_eq!(
                    merkle_root_from_proof(id, index, n, &proof),
                    Some(root),
                    "n={n} index={index}"
                );
            }
        }
    }

    #[test]
    fn tampered_proofs_do_not_reach_the_root() {
        let set = ids(5);
        let root = merkle_root(&set);
        let id = set[2];
        let proof = merkle_proof(&set, &id).unwrap();

        assert_ne!(
            merkle_root_from_proof(&id, 1, 5, &proof),
            Some(root),
            "wrong index"
        );
        let mut bad = proof.clone();
        bad[0][0] ^= 1;
        assert_ne!(
            merkle_root_from_proof(&id, 2, 5, &bad),
            Some(root),
            "tampered sibling"
        );
        assert_eq!(
            merkle_root_from_proof(&id, 2, 5, &proof[..proof.len() - 1]),
            None,
            "truncated proof is malformed"
        );
        let mut long = proof.clone();
        long.push([0u8; 32]);
        assert_eq!(
            merkle_root_from_proof(&id, 2, 5, &long),
            None,
            "overlong proof is malformed"
        );
        // A count that changes the tree height is malformed (the path has
        // the wrong length). Counts that only differ in a duplicated
        // trailing node can legitimately share the computed path - which
        // is why the checkpoint-side check pins `count` to the signed
        // `entries_count` and the reached root to `entry_ids_root`.
        assert_eq!(
            merkle_root_from_proof(&id, 2, 4, &proof),
            None,
            "shorter tree cannot consume the path"
        );
        assert_eq!(
            merkle_root_from_proof(&id, 2, 9, &proof),
            None,
            "taller tree needs a longer path"
        );
    }

    /// Deterministic pseudo-random sets: proofs roundtrip for every member,
    /// and a proof for one member never verifies for a different leaf at the
    /// same position.
    #[test]
    fn random_sets_roundtrip_and_do_not_cross_verify() {
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..64 {
            let n = 1 + (next() % 48) as usize;
            let set: Vec<[u8; 32]> = (0..n)
                .map(|_| {
                    let mut id = [0u8; 32];
                    for chunk in id.chunks_mut(4) {
                        chunk.copy_from_slice(&next().to_le_bytes());
                    }
                    id
                })
                .collect();
            let root = merkle_root(&set);
            let mut sorted = set.clone();
            sorted.sort_unstable();
            sorted.dedup();
            for (index, id) in sorted.iter().enumerate() {
                let proof = merkle_proof(&set, id).expect("member has a proof");
                assert_eq!(
                    merkle_root_from_proof(id, index, sorted.len(), &proof),
                    Some(root),
                    "n={} index={index}",
                    sorted.len()
                );
                let mut swapped = *id;
                swapped[0] ^= 0xFF;
                assert_ne!(
                    merkle_root_from_proof(&swapped, index, sorted.len(), &proof),
                    Some(root),
                    "a different leaf cannot ride the same path"
                );
            }
        }
    }

    #[test]
    fn absent_ids_have_no_proof() {
        assert!(merkle_proof(&ids(3), &[99u8; 32]).is_none());
        assert!(merkle_proof(&[], &[1u8; 32]).is_none());
    }

    #[test]
    fn single_leaf_needs_an_empty_proof() {
        let set = [[7u8; 32]];
        assert_eq!(
            merkle_proof(&set, &[7u8; 32]).unwrap(),
            Vec::<[u8; 32]>::new()
        );
        assert_eq!(
            merkle_root_from_proof(&[7u8; 32], 0, 1, &[]),
            Some(merkle_root(&set))
        );
        assert_eq!(merkle_root_from_proof(&[7u8; 32], 0, 0, &[]), None);
    }
}
