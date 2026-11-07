use crate::entry::Entry;
use crate::error::{Error, Result};

/// Verify that a slice of entries, already ordered by seq, forms a contiguous
/// valid chain for a single author: sequential seq numbers and each `prev`
/// equal to the previous entry's id.
pub fn verify_feed_order(entries: &[Entry]) -> Result<()> {
    for pair in entries.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        if a.body.author != b.body.author {
            return Err(Error::Chain("feed slice mixes authors".into()));
        }
        if b.body.seq != a.body.seq + 1 {
            return Err(Error::Chain(format!(
                "seq gap: {} -> {}",
                a.body.seq, b.body.seq
            )));
        }
        if b.body.prev != Some(a.id()?) {
            return Err(Error::Chain(format!(
                "broken prev link at seq {}",
                b.body.seq
            )));
        }
    }
    Ok(())
}
