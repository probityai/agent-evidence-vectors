//! The crate reads every case of the six v2 corpora, in manifest order, and
//! refuses what it cannot read. The verdicts themselves are held to the other
//! readers by the cross-language agreement test, not here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::Command;

use aev_readers::common::{load_manifest, read_record};
use aev_readers::{judge_for, verdict_lines, SUITES};

const CORPORA: [&str; 6] = [
    "vectors-attenuated-delegation",
    "vectors-grant-use",
    "vectors-revocation-epoch",
    "vectors-durable-history",
    "vectors-approval-binding-v2",
    "vectors-decision-client-failure-modes",
];

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpora")
        .join(name)
}

#[test]
fn every_record_of_every_corpus_is_admissible_and_listed_in_order() {
    for name in CORPORA {
        let dir = corpus(name);
        let manifest = load_manifest(&dir).unwrap();
        assert!(judge_for(&manifest.suite).is_some(), "{name}: {}", manifest.suite);
        assert!(!manifest.vectors.is_empty(), "{name}");
        for vector in &manifest.vectors {
            read_record(&dir.join(&vector.path)).unwrap();
        }
        let lines = verdict_lines(&dir).unwrap();
        assert_eq!(lines.len(), manifest.vectors.len(), "{name}");
        for (line, vector) in lines.iter().zip(&manifest.vectors) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "{line}");
            assert_eq!(fields[0], vector.id);
        }
    }
}

#[test]
fn every_suite_name_is_a_corpus_suite() {
    let mut declared: Vec<String> = CORPORA
        .iter()
        .map(|name| load_manifest(&corpus(name)).unwrap().suite)
        .collect();
    let mut known: Vec<String> = SUITES.iter().map(|(name, _)| (*name).to_owned()).collect();
    declared.sort();
    known.sort();
    assert_eq!(declared, known);
}

#[test]
fn an_unreadable_corpus_and_an_unknown_suite_are_refused() {
    assert!(verdict_lines(Path::new("/nonexistent-corpus-dir")).is_err());
    let dir = std::env::temp_dir().join(format!("aev-readers-unknown-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("MANIFEST.json"), br#"{"suite":"nope/v1","vectors":[]}"#).unwrap();
    let error = verdict_lines(&dir).unwrap_err().to_string();
    assert!(error.contains("unknown suite"), "{error}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_cli_prints_one_line_per_vector_and_exits_2_when_it_cannot_read() {
    let binary = env!("CARGO_BIN_EXE_aev-verdicts");
    let dir = corpus(CORPORA[1]);
    let output = Command::new(binary).arg(&dir).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let manifest = load_manifest(&dir).unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), manifest.vectors.len());

    let failed = Command::new(binary).arg("/nonexistent-corpus-dir").output().unwrap();
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    let usage = Command::new(binary).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
