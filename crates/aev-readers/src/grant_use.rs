//! Reader for the `grant-use/v1` corpus.
//!
//! Not ported yet: [`judge`] returns the `unimplemented` verdict for every record.

use serde_json::Value;

use crate::common::Verdict;

/// Derive the verdict for one record. `record` is the parsed `record.json`
/// and `record_bytes` the exact bytes it was parsed from.
#[must_use]
pub fn judge(_record: &Value, _record_bytes: &[u8]) -> Verdict {
    Verdict::unimplemented()
}
