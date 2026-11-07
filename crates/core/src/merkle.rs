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
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            next.push(*blake3::hash(&buf).as_bytes());
        }
        level = next;
    }
    level[0]
}
