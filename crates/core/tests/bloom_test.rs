use datu_core::bloom::BloomFilter;

#[test]
fn no_false_negatives_and_low_false_positives() {
    let n = 1000;
    let mut filter = BloomFilter::new_for(n, 0.001);
    let present: Vec<[u8; 32]> = (0..n as u64)
        .map(|i| blake3::hash(&i.to_le_bytes()).as_bytes().clone())
        .collect();
    for id in &present {
        filter.insert(id);
    }
    for id in &present {
        assert!(filter.contains(id), "false negative - impossible by design");
    }
    let absent: Vec<[u8; 32]> = (10_000..20_000u64)
        .map(|i| blake3::hash(&i.to_le_bytes()).as_bytes().clone())
        .collect();
    let fp = absent
        .iter()
        .filter(|id| filter.contains(id.as_slice()))
        .count();
    let rate = fp as f64 / absent.len() as f64;
    assert!(rate < 0.01, "false-positive rate {rate} far above target");
}

#[test]
fn wire_format_roundtrip() {
    let mut filter = BloomFilter::new_for(500, 0.001);
    for i in 0..500u64 {
        filter.insert(blake3::hash(i.to_le_bytes().as_slice()).as_bytes());
    }
    let bytes = filter.bit_bytes();
    let restored =
        BloomFilter::from_parts(filter.bit_count(), filter.hash_count(), &bytes).unwrap();
    for i in 0..500u64 {
        assert!(restored.contains(blake3::hash(i.to_le_bytes().as_slice()).as_bytes()));
    }
    assert!(restored.contains(&[9u8; 32]) == filter.contains(&[9u8; 32]));
}

#[test]
fn rejects_malformed_parts() {
    let filter = BloomFilter::new_for(100, 0.01);
    assert!(BloomFilter::from_parts(0, 4, &filter.bit_bytes()).is_none());
    assert!(BloomFilter::from_parts(filter.bit_count(), 0, &filter.bit_bytes()).is_none());
    assert!(BloomFilter::from_parts(filter.bit_count(), 99, &filter.bit_bytes()).is_none());
    assert!(BloomFilter::from_parts(filter.bit_count(), filter.hash_count(), &[0u8; 3]).is_none());
}
