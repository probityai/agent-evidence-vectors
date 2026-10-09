//! The reader over the committed corpus and the published emitter run.

use std::path::PathBuf;
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_w3c-report-rs"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("the binary did not start: {e}"));
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn every_committed_member_behaves_as_declared() {
    let dir = repo().join("vectors-w3c-report");
    let (status, text) = run(&[dir.to_str().unwrap_or_default()]);
    assert_eq!(status, 0, "{text}");
    // The member count is the manifest's, never a literal that goes stale
    // the next time the generator adds a member.
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("MANIFEST.json")).unwrap_or_else(|e| panic!("MANIFEST.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("MANIFEST.json does not parse: {e}"));
    let members = manifest["vectors"].as_array().map_or(0, Vec::len);
    let head = format!("suite: w3c-report-v01-conformance\nmembers: {members}\n");
    assert!(members > 0 && text.starts_with(&head), "{text}");
    assert!(
        text.ends_with("verdict: every member behaves as MANIFEST.json declares\n"),
        "{text}"
    );
}

#[test]
fn the_published_emitter_run_validates_and_rewrites_byte_for_byte() {
    let path = repo().join("vectors-w3c-report/observed/aee-v0.12.0/report.json");
    let (status, text) = run(&["--report", path.to_str().unwrap_or_default()]);
    assert_eq!(status, 0, "{text}");
    assert!(
        text.contains("ok   check-set leaf-count: declared 272, measured 272"),
        "{text}"
    );
    assert!(text.contains("byte-identical to the file"), "{text}");
}

#[test]
fn a_bad_invocation_is_refused() {
    let (status, _) = run(&[]);
    assert_eq!(status, 2);
}
