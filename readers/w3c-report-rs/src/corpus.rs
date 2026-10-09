//! Judging a whole corpus directory against its MANIFEST.json.
//!
//! The printed lines are the one interface this reader shares with the Go and
//! Python readers: the wording and order were learned by running those readers
//! as black boxes over the committed corpus and over mutated copies, never by
//! reading their source. Everything that decides a line is computed here.

use crate::json::{self, ReadError};
use crate::report::{self, Judgement};
use crate::tree::sha256_hex;
use crate::{arm, lcd};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// The suite name this reader judges.
pub const SUITE: &str = "w3c-report-v01-conformance";

/// Fields the manifest entry and the member file must agree on, in the order
/// a disagreement is reported.
const AGREE: [&str; 6] = [
    "kind",
    "family",
    "requirements",
    "expected",
    "specVersion",
    "subjectType",
];

/// The members that make up a member's identifier: the manifest's
/// identifierPolicy says an identifier is minted from the member, and these
/// are the members whose digest reproduces every committed identifier.
const ID_FIELDS: [&str; 6] = [
    "expected",
    "family",
    "kind",
    "requirements",
    "subject",
    "subjectType",
];

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn list(items: &[String]) -> String {
    format!("[{}]", items.join(", "))
}

fn str_items(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| x.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The identifier a member's own bytes give, or the encoder's refusal.
pub fn identifier(member: &Map<String, Value>) -> Result<String, String> {
    let mut obj = Map::new();
    for k in ID_FIELDS {
        obj.insert(k.to_string(), member.get(k).cloned().unwrap_or(Value::Null));
    }
    obj.insert(
        "resolves".into(),
        member.get("resolves").cloned().unwrap_or(Value::Null),
    );
    let value = Value::Object(obj);
    if let Some(f) = json::first_float(&value) {
        return Err(format!(
            "corpora: {f} is a JSON float, and this encoder refuses one rather than guess whether CPython's repr and Go's strconv agree on it"
        ));
    }
    let bytes = json::canonical(&value)?;
    Ok(format!("v{}", &sha256_hex(&bytes)[..16]))
}

/// Judge a subject by its declared type.
pub fn judge(subject_type: &str, member: &Map<String, Value>) -> Option<Judgement> {
    let subject = member.get("subject").unwrap_or(&Value::Null);
    match subject_type {
        "report" => Some(report::judge(
            subject,
            member.get("resolves").and_then(Value::as_object),
        )),
        "agent-run-metrics" => Some(arm::judge(subject)),
        "llm-context-discovery" => Some(lcd::judge(subject)),
        _ => None,
    }
}

struct Out {
    lines: Vec<String>,
    members_failed: usize,
    corpus_failed: usize,
}

impl Out {
    fn corpus(&mut self, msg: String) {
        self.lines.push(format!("FAIL corpus: {msg}"));
        self.corpus_failed += 1;
    }
}

/// Run the corpus; returns the printed text and the exit status.
pub fn run(dir: &Path) -> (String, i32) {
    let manifest_bytes = match fs::read(dir.join("MANIFEST.json")) {
        Ok(b) => b,
        Err(e) => {
            return (
                format!("cannot read {}: {e}\n", dir.join("MANIFEST.json").display()),
                2,
            )
        }
    };
    let manifest = match json::read(&manifest_bytes) {
        Ok(Value::Object(m)) => m,
        Ok(_) => return ("MANIFEST.json is not a JSON object\n".into(), 2),
        Err(ReadError::Syntax(e) | ReadError::Inadmissible(e)) => {
            return (format!("MANIFEST.json is not readable JSON: {e}\n"), 2)
        }
    };
    let suite = s(manifest.get("suite")).unwrap_or("");
    if suite != SUITE {
        return (format!("corpus '{suite}' is not the suite this reader judges ('{SUITE}'), so nothing was judged\n"), 2);
    }
    let empty = Vec::new();
    let entries: Vec<&Map<String, Value>> = manifest
        .get("vectors")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_object)
        .collect();
    let spec_version = manifest.get("specVersion");
    let requirements: Vec<&Map<String, Value>> = manifest
        .get("requirements")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_object)
        .collect();
    let req_ids: BTreeSet<&str> = requirements.iter().filter_map(|r| s(r.get("id"))).collect();

    let n_accept = entries
        .iter()
        .filter(|e| s(e.get("kind")) == Some("accept"))
        .count();
    let n_reject = entries
        .iter()
        .filter(|e| s(e.get("kind")) == Some("reject"))
        .count();
    let mut out = Out {
        lines: Vec::new(),
        members_failed: 0,
        corpus_failed: 0,
    };
    out.lines.push(format!("suite: {suite}"));
    out.lines.push(format!("members: {}", entries.len()));
    out.lines.push(format!("  accept: {n_accept}"));
    out.lines.push(format!("  reject: {n_reject}"));

    let mut seen = BTreeSet::new();
    let mut digest_input: Vec<u8> = Vec::new();
    for e in &entries {
        let id = s(e.get("id")).unwrap_or("").to_string();
        let mut fails = Vec::new();
        if !seen.insert(id.clone()) {
            fails.push("duplicate identifier".to_string());
        }
        let file = s(e.get("file")).unwrap_or("");
        match fs::read(dir.join(file)) {
            Err(_) => fails.push("the manifest names a vector file that does not exist".into()),
            Ok(bytes) => {
                digest_input.extend_from_slice(&bytes);
                member(e, &bytes, spec_version, &req_ids, &mut fails);
            }
        }
        if !fails.is_empty() {
            out.members_failed += 1;
            out.lines
                .extend(fails.into_iter().map(|f| format!("FAIL {id}: {f}")));
        }
    }

    corpus_checks(
        dir,
        &manifest,
        &entries,
        &requirements,
        &req_ids,
        &digest_input,
        (n_accept, n_reject),
        &mut out,
    );

    if out.members_failed == 0 && out.corpus_failed == 0 {
        out.lines
            .push("verdict: every member behaves as MANIFEST.json declares".into());
    } else {
        out.lines.push(format!(
            "verdict: {} member(s) and {} corpus-level claim(s) do not hold",
            out.members_failed, out.corpus_failed
        ));
    }
    let status = i32::from(out.members_failed + out.corpus_failed > 0);
    (out.lines.join("\n") + "\n", status)
}

fn member(
    e: &Map<String, Value>,
    bytes: &[u8],
    spec_version: Option<&Value>,
    req_ids: &BTreeSet<&str>,
    fails: &mut Vec<String>,
) {
    let doc = match json::read(bytes) {
        Err(ReadError::Syntax(m)) => {
            fails.push(format!("the vector file does not parse: {m}"));
            return;
        }
        Err(ReadError::Inadmissible(m)) => {
            fails.push(format!("the vector file is not admissible JSON: {m}"));
            return;
        }
        Ok(d) => d,
    };
    let Some(doc) = doc.as_object() else {
        fails.push("the vector file is not a JSON object".into());
        return;
    };
    let kind = s(e.get("kind"));
    let expected = e.get("expected").and_then(Value::as_object);
    let rejects = str_items(expected.and_then(|x| x.get("rejects")));
    let cited = str_items(e.get("requirements"));
    if e.get("specVersion") != spec_version {
        fails.push("declares a specification version the manifest does not pin".into());
    }
    if s(expected.and_then(|x| x.get("verdict"))) != kind {
        fails.push("expects a verdict that is not its kind".into());
    }
    if kind == Some("reject") && rejects.len() != 1 {
        fails.push("is a reject member that does not name exactly one row".into());
    }
    for r in &cited {
        if !req_ids.contains(r.as_str()) {
            fails.push(format!("cites requirement {r} the manifest does not carry"));
        }
    }
    for r in &rejects {
        if !req_ids.contains(r.as_str()) {
            fails.push(format!(
                "expects rejection under {r}, which the manifest does not carry"
            ));
        } else if !cited.contains(r) {
            fails.push(format!("expects rejection under {r} and does not cite it"));
        }
    }
    for f in AGREE {
        if doc.get(f) != e.get(f) {
            fails.push(format!(
                "the vector file and the manifest disagree about {f}"
            ));
        }
    }
    let id = s(e.get("id"));
    if s(doc.get("id")) != id {
        fails.push("the vector file carries a different identifier".into());
    }
    match identifier(doc) {
        Err(msg) => fails.push(msg),
        Ok(computed) if Some(computed.as_str()) != id => {
            fails.push("identifier does not recompute from the member's own bytes".into())
        }
        Ok(_) => {}
    }
    let subject_type = s(e.get("subjectType")).unwrap_or("");
    match judge(subject_type, doc) {
        None => fails.push(format!(
            "names subject type {subject_type}, which this reader has no validator for"
        )),
        Some(Judgement::Shape(errs)) => fails.push(format!(
            "the subject is not the shape its definition gives: {}",
            errs.join("; ")
        )),
        Some(Judgement::Rows(rows)) => {
            let got: Vec<String> = rows.into_iter().collect();
            let mut want = rejects.clone();
            want.sort();
            if got != want {
                fails.push(format!(
                    "the validator rejects under {} and the manifest expects {}",
                    list(&got),
                    list(&rejects)
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn corpus_checks(
    dir: &Path,
    manifest: &Map<String, Value>,
    entries: &[&Map<String, Value>],
    requirements: &[&Map<String, Value>],
    req_ids: &BTreeSet<&str>,
    digest_input: &[u8],
    measured: (usize, usize),
    out: &mut Out,
) {
    // Each requirement is bound to a sentence of the vendored text by digest.
    for r in requirements {
        let rid = s(r.get("id")).unwrap_or("");
        let path = s(r.get("vendored")).unwrap_or("");
        let Ok(text) = fs::read_to_string(dir.join(path)) else {
            out.corpus(format!(
                "{rid}: names a vendored file {path} that is not here"
            ));
            continue;
        };
        let sentence = s(r.get("sentence")).unwrap_or("");
        if Some(sha256_hex(sentence.as_bytes()).as_str()) != s(r.get("sentenceDigest")) {
            out.corpus(format!(
                "{rid}: the pinned sentence digest does not recompute from the sentence"
            ));
        }
        match text.find(sentence) {
            None => out.corpus(format!(
                "{rid}: quotes a sentence the vendored copy no longer carries"
            )),
            Some(at) => {
                let line = text[..at].matches('\n').count() as i64 + 1;
                let recorded = report::count(r.get("line"));
                if recorded != Some(line) {
                    let shown = r
                        .get("line")
                        .map(Value::to_string)
                        .unwrap_or_else(|| "none".into());
                    out.corpus(format!(
                        "{rid}: records line {shown} and the sentence sits on line {line}"
                    ));
                }
            }
        }
    }
    // Every family both accepts and rejects; every minted row and family is carried.
    let mut kinds: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut cited: BTreeSet<String> = BTreeSet::new();
    for e in entries {
        kinds
            .entry(s(e.get("family")).unwrap_or(""))
            .or_default()
            .insert(s(e.get("kind")).unwrap_or(""));
        cited.extend(str_items(e.get("requirements")));
    }
    let only_reject: Vec<String> = kinds
        .iter()
        .filter(|(_, k)| k.contains("reject") && !k.contains("accept"))
        .map(|(f, _)| f.to_string())
        .collect();
    if !only_reject.is_empty() {
        out.corpus(format!(
            "families that reject and never accept: {}",
            list(&only_reject)
        ));
    }
    let uncited: Vec<String> = req_ids
        .iter()
        .filter(|r| !cited.contains(**r))
        .map(|r| r.to_string())
        .collect();
    if !uncited.is_empty() {
        out.corpus(format!(
            "requirements minted and cited by no member: {}",
            list(&uncited)
        ));
    }
    let mut uncarried: Vec<String> = manifest
        .get("families")
        .and_then(Value::as_object)
        .map(|f| {
            f.keys()
                .filter(|k| !kinds.contains_key(k.as_str()))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    uncarried.sort();
    if !uncarried.is_empty() {
        out.corpus(format!(
            "families declared and carried by no member: {}",
            list(&uncarried)
        ));
    }
    // The vendored text is pinned by sha256.
    for (key, pin) in manifest
        .get("specVendored")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let path = s(pin.get("path")).unwrap_or("");
        match fs::read(dir.join(path)) {
            Err(_) => out.corpus(format!("the vendored file for {key} {path} is missing")),
            Ok(b) if Some(sha256_hex(&b).as_str()) != s(pin.get("sha256")) => out.corpus(format!(
                "the vendored file for {key} {path} does not match its pinned digest"
            )),
            Ok(_) => {}
        }
    }
    // The reference emitter's published run: present, pinned, and accepted.
    for run in manifest
        .get("referenceEmitterRuns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        emitter_run(dir, run, out);
    }
    let pinned = manifest.get("counts").and_then(Value::as_object);
    let (pa, pr) = (
        pinned.and_then(|c| report::count(c.get("accept"))),
        pinned.and_then(|c| report::count(c.get("reject"))),
    );
    if pa != Some(measured.0 as i64) || pr != Some(measured.1 as i64) {
        let show = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_else(|| "None".into());
        out.corpus(format!(
            "counts disagree: manifest {{accept={}, reject={}}}, measured {{accept={}, reject={}}}",
            show(pa),
            show(pr),
            measured.0,
            measured.1
        ));
    }
    if Some(sha256_hex(digest_input).as_str()) != s(manifest.get("corpusDigest")) {
        out.corpus("corpusDigest does not match the vector files on disk".into());
    }
}

fn emitter_run(dir: &Path, run: &Value, out: &mut Out) {
    let path = s(run.get("path")).unwrap_or("");
    match fs::read(dir.join(path)) {
        Err(_) => out.corpus(format!("referenceEmitterRuns: {path} is missing")),
        Ok(b) if Some(sha256_hex(&b).as_str()) != s(run.get("sha256")) => out.corpus(format!(
            "referenceEmitterRuns: {path} does not match its pinned digest"
        )),
        Ok(b) => match json::read(&b) {
            Err(ReadError::Syntax(m) | ReadError::Inadmissible(m)) => out.corpus(format!(
                "referenceEmitterRuns: {path} is not readable JSON: {m}"
            )),
            Ok(doc) => match report::judge(&doc, None) {
                Judgement::Shape(errs) => out.corpus(format!(
                    "referenceEmitterRuns: {path} is not a v0.1 report: {}",
                    errs.join("; ")
                )),
                Judgement::Rows(rows) if !rows.is_empty() => {
                    let rows: Vec<String> = rows.into_iter().collect();
                    out.corpus(format!(
                        "referenceEmitterRuns: {path} is rejected under {}",
                        list(&rows)
                    ))
                }
                Judgement::Rows(_) => {}
            },
        },
    }
    for key in ["conformanceReport", "run"] {
        let Some(pin) = run.get(key).and_then(Value::as_object) else {
            continue;
        };
        let p = s(pin.get("path")).unwrap_or("");
        match fs::read(dir.join(p)) {
            Err(_) => out.corpus(format!("referenceEmitterRuns: {p} is missing")),
            Ok(b) if Some(sha256_hex(&b).as_str()) != s(pin.get("sha256")) => out.corpus(format!(
                "referenceEmitterRuns: {p} does not match its pinned digest"
            )),
            Ok(_) => {}
        }
    }
}
