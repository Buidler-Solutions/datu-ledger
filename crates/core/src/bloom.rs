//! A Bloom filter for set-reconciliation sync.
//!
//! During anti-entropy a node sends a Bloom filter of the entry ids it
//! already has; the peer replies with only the entries (probably) missing.
//! False positives merely defer an entry to a later sync - they never lose
//! data, which is why a plain Bloom filter (not an IBLT) is the right first
//! tool at this scale.

/// A fixed-size Bloom filter over arbitrary byte items.
///
/// Positions use double hashing (Kirsch–Mitzenmacher) derived from one
/// BLAKE3 digest: `pos_i = (h1 + i·h2) mod m`.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    bits: Vec<u64>,
    /// Number of hash functions.
    k: u32,
    /// Number of bits.
    m: u64,
}

impl BloomFilter {
    /// Size the filter for `expected` items at the target false-positive
    /// rate `fpr` (e.g. `0.001` for 0.1%).
    pub fn new_for(expected: usize, fpr: f64) -> BloomFilter {
        let n = expected.max(16) as f64;
        let ln2 = std::f64::consts::LN_2;
        let m = ((-(n * fpr.ln()) / (ln2 * ln2)).ceil() as u64).max(64);
        let k = (((m as f64 / n) * ln2).round() as u32).clamp(1, 30);
        BloomFilter {
            bits: vec![0u64; (m as usize + 63) / 64],
            k,
            m,
        }
    }

    pub fn from_parts(m: u64, k: u32, bit_bytes: &[u8]) -> Option<BloomFilter> {
        if m == 0 || k == 0 || k > 30 {
            return None;
        }
        let words = (m as usize + 63) / 64;
        if bit_bytes.len() != words * 8 {
            return None;
        }
        let mut bits = Vec::with_capacity(words);
        for chunk in bit_bytes.chunks_exact(8) {
            bits.push(u64::from_le_bytes(chunk.try_into().ok()?));
        }
        Some(BloomFilter { bits, k, m })
    }

    pub fn bit_count(&self) -> u64 {
        self.m
    }

    pub fn hash_count(&self) -> u32 {
        self.k
    }

    /// Raw bit array, little-endian words - pair with `bit_count`/`hash_count`.
    pub fn bit_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.bits.len() * 8);
        for word in &self.bits {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn hashes(item: &[u8]) -> (u64, u64) {
        let digest = blake3::hash(item);
        let bytes = digest.as_bytes();
        let h1 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        (h1, h2)
    }

    fn positions(&self, item: &[u8]) -> Vec<u64> {
        let (h1, h2) = Self::hashes(item);
        (0..self.k as u64)
            .map(|i| (h1.wrapping_add(i.wrapping_mul(h2))) % self.m)
            .collect()
    }

    pub fn insert(&mut self, item: &[u8]) {
        for pos in self.positions(item) {
            self.bits[(pos / 64) as usize] |= 1u64 << (pos % 64);
        }
    }

    /// Probably-contains: false negatives are impossible, false positives
    /// occur at the configured rate.
    pub fn contains(&self, item: &[u8]) -> bool {
        self.positions(item)
            .iter()
            .all(|pos| self.bits[(pos / 64) as usize] & (1u64 << (pos % 64)) != 0)
    }
}
