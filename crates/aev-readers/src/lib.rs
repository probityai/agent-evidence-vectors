//! Readers for the v2 evidence corpora.
//!
//! Each family module exposes `judge(record, record_bytes) -> Verdict`, which
//! derives the decision and reason from one case's record.json alone. The
//! manifest's expected answer is never consulted. [`verdict_lines`] runs a whole
//! corpus directory and is what the `aev-verdicts` binary prints.

pub mod approval_binding_v2;
pub mod attenuated_delegation;
pub mod common;
pub mod decision_client;
pub mod durable_history;
pub mod grant_use;
pub mod revocation_epoch;

use std::path::Path;

pub use common::{ReaderError, Verdict};

/// A family's derivation: the parsed record and the exact bytes it came from.
pub type JudgeFn = fn(&serde_json::Value, &[u8]) -> Verdict;

/// The suites this crate reads, each with its family's `judge`.
pub const SUITES: [(&str, JudgeFn); 6] = [
    ("attenuated-delegation/v1", attenuated_delegation::judge),
    ("grant-use/v1", grant_use::judge),
    ("revocation-epoch/v1", revocation_epoch::judge),
    ("durable-history/v1", durable_history::judge),
    ("approval-binding/v2", approval_binding_v2::judge),
    ("decision-client-failure-modes/v1", decision_client::judge),
];

/// The derivation for a suite named by a manifest's `suite` member.
#[must_use]
pub fn judge_for(suite: &str) -> Option<JudgeFn> {
    SUITES
        .iter()
        .find(|(name, _)| *name == suite)
        .map(|(_, judge)| *judge)
}

/// One `<id>\t<decision>\t<reason>` line per manifest vector, in manifest order.
///
/// # Errors
///
/// Returns [`ReaderError`] when the manifest or any record.json cannot be read
/// or parsed, or the manifest names a suite this crate does not read.
pub fn verdict_lines(dir: &Path) -> Result<Vec<String>, ReaderError> {
    let manifest = common::load_manifest(dir)?;
    let judge = judge_for(&manifest.suite)
        .ok_or_else(|| ReaderError::new(format!("unknown suite {:?}", manifest.suite)))?;
    let mut lines = Vec::with_capacity(manifest.vectors.len());
    for vector in &manifest.vectors {
        let (record, bytes) = common::read_record(&dir.join(&vector.path))?;
        let verdict = judge(&record, &bytes);
        lines.push(format!(
            "{}\t{}\t{}",
            vector.id, verdict.decision, verdict.reason
        ));
    }
    Ok(lines)
}
