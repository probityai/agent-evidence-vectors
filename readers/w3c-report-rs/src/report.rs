//! The v0.1 per-check report, judged row by row.
//!
//! Every rule below names the place in the vendored v0.1 text
//! (`spec-vendored/0087-arsentev-2026-09-30-v01.txt`) or in message `0001`
//! that it comes from; `docs/research/w3c-reader-independence.md` carries the
//! same mapping as a table. Field names and object shapes are read off the
//! corpus members, which are the shared input every reader judges.

use crate::json;
use crate::tree;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Section 1.1: the five states.
const STATES: [&str; 5] = ["pass", "fail", "not-exercised", "inconclusive", "void"];
/// Section 1: the two verdict states; the other three are non-verdict.
const VERDICT: [&str; 2] = ["pass", "fail"];
/// Section 1.2: the eight CAP-1 dispositions plus the four values added on the
/// list and the one added in the comment window.
const CAUSES: [&str; 13] = [
    "not_applicable",
    "disabled_by_policy",
    "unsupported_input",
    "resource_exhausted",
    "failed",
    "unavailable",
    "out_of_scope",
    "withheld",
    "evidence-does-not-hold",
    "integrity-failure",
    "availability-failure",
    "precondition-unsatisfiable",
    "confinement-failed-during-check",
];
/// Section 1: the other-verdict values.
const OTHER_VERDICT: [&str; 4] = [
    "unknown",
    "possible-not-demonstrated",
    "demonstrated",
    "foreclosed",
];
/// Section 1: the discrimination values.
const DISCRIMINATION: [&str; 2] = ["unknown", "demonstrated"];
/// Section 2: the changed slot.
const CHANGED: [&str; 3] = ["input artifact", "checker rule", "constraint"];
/// Section 7.1 names verdict and the fired-rule list as projections of the
/// error list; those three are the slots a compared or moved set may name.
const SLOTS: [&str; 3] = ["verdict", "fired-rule list", "error list"];
/// Section 5.4: the three fillings plus shown-by-run, the branch where the
/// counts already show a fail.
const NEGATIVE_CAPABLE: [&str; 4] = [
    "shown-by-run",
    "control-failed",
    "prior-discriminating-run",
    "nothing",
];
/// Section 5.2: the three ways a completeness claim may be reported.
const CLAIMS: [&str; 3] = ["satisfied", "not-satisfied", "not-claimable"];
/// The format identifier the corpus's reports carry.
pub const FORMAT: &str = "public-agent-conformance/report/v0.1";

/// The outcome of judging one report: either a shape refusal (the object is
/// not a report at all) or the set of rows that fire.
pub enum Judgement {
    Shape(Vec<String>),
    Rows(BTreeSet<String>),
}

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn has(map: &Map<String, Value>, key: &str) -> bool {
    map.contains_key(key)
}

/// A count read the way the emitters write it: an integer, or a float with an
/// integral value (a count of 1.0 is still one).
pub fn count(v: Option<&Value>) -> Option<i64> {
    let n = v?.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i);
    }
    let f = n.as_f64()?;
    if f.fract() == 0.0 && f.abs() < 9.0e15 {
        Some(f as i64)
    } else {
        None
    }
}

fn str_list(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_string))
        .collect()
}

/// What a resolved or carried observation holds: its verdict and fired rules.
#[derive(PartialEq)]
struct Observed {
    verdict: Option<Value>,
    rules: Option<Value>,
}

enum Reading {
    /// Section 3 line 1: carried, or resolved with matching digests.
    Read(Observed),
    /// Section 3 line 2: resolved, digests differ.
    Mismatch,
    /// Section 3 line 3: did not resolve.
    Unchecked,
}

fn read_observation(obs: &Value, store: Option<&Map<String, Value>>) -> Reading {
    let Some(obs) = obs.as_object() else {
        return Reading::Unchecked;
    };
    if let Some(carried) = obs.get("carried").and_then(Value::as_object) {
        return Reading::Read(Observed {
            verdict: carried.get("verdict").cloned(),
            rules: carried.get("rules").cloned(),
        });
    }
    let Some(reference) = obs.get("reference").and_then(Value::as_object) else {
        return Reading::Unchecked;
    };
    let (Some(store), Some(key)) = (store, s(reference.get("vector"))) else {
        return Reading::Unchecked;
    };
    let Some(entry) = store.get(key).and_then(Value::as_object) else {
        return Reading::Unchecked;
    };
    // A reference with no digest is row 14's (form) to refuse; with nothing to
    // compare against, the reader cannot tell a match from a mismatch.
    if s(reference.get("sha256")).is_none() {
        return Reading::Unchecked;
    }
    if s(entry.get("sha256")) != s(reference.get("sha256")) {
        return Reading::Mismatch;
    }
    Reading::Read(Observed {
        verdict: entry.get("verdict").cloned(),
        rules: entry.get("rules").cloned(),
    })
}

/// Section 2: moved recomputed over two observations, or None when either did
/// not read (the rows reading moved then degrade).
fn recompute_moved(
    ev: &Map<String, Value>,
    store: Option<&Map<String, Value>>,
    rows: &mut BTreeSet<String>,
) -> Option<BTreeSet<&'static str>> {
    let observations = ev.get("observations").and_then(Value::as_array)?;
    let mut read = Vec::new();
    let mut complete = true;
    for obs in observations {
        match read_observation(obs, store) {
            Reading::Read(o) => read.push(o),
            Reading::Mismatch => {
                // Section 3, line 2: an integrity failure.
                rows.insert("W3C-R-020".into());
                complete = false;
            }
            Reading::Unchecked => complete = false,
        }
    }
    if !complete || read.len() != 2 {
        return None;
    }
    let mut moved = BTreeSet::new();
    if read[0].verdict != read[1].verdict {
        moved.insert("verdict");
    }
    if read[0].rules != read[1].rules {
        moved.insert("fired-rule list");
    }
    Some(moved)
}

fn shape(subject: &Value) -> Result<&Map<String, Value>, Vec<String>> {
    use crate::shape::{Shape, Ty};
    let Some(report) = subject.as_object() else {
        return Err(vec!["the report is not a JSON object".into()]);
    };
    let mut sh = Shape::default();
    if s(report.get("format")) != Some(FORMAT) {
        sh.errors
            .push(format!("the report does not name the format {FORMAT}"));
    }
    // Section 1: the record. Section 2: the evidence object and the run-level
    // domain. Section 5: the roll-up. Types only; values are the rows' to read.
    sh.need(subject, "", "checks", Ty::Array);
    sh.each(subject, "", "checks", Ty::Object);
    sh.need(subject, "", "roll-up", Ty::Object);
    sh.may(subject, "", "evidence", Ty::Array);
    sh.each(subject, "", "evidence", Ty::Object);
    // Section 2: the domain is a declared object, declared once at run level.
    sh.need(subject, "", "domain", Ty::Object);
    sh.may(subject, "", "check-set", Ty::Object);
    sh.may(subject, "", "fixed", Ty::Object);
    sh.may(subject, "", "coverage", Ty::Object);
    if let Some(d) = report.get("domain").filter(|d| d.is_object()) {
        sh.need(d, "domain", "id", Ty::Str);
    }
    for (i, c) in report
        .get("checks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if !c.is_object() {
            continue;
        }
        let path = format!("checks[{i}]");
        sh.need(c, &path, "check", Ty::Str);
        sh.need(c, &path, "state", Ty::Str);
        sh.may(c, &path, "declared-exclusion", Ty::Bool);
        for (key, ty) in [
            ("cause", "code"),
            ("other-verdict", "value"),
            ("discrimination", "value"),
        ] {
            sh.may(c, &path, key, Ty::Object);
            if let Some(q) = c.get(key).filter(|q| q.is_object()) {
                let qp = format!("{path}.{key}");
                sh.need(q, &qp, ty, Ty::Str);
                for arg in ["ref", "constraint-set", "domain", "detail"] {
                    if !(key == "other-verdict" && arg == "domain") {
                        sh.may(q, &qp, arg, Ty::Str);
                    }
                }
            }
        }
    }
    for (i, ev) in report
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if !ev.is_object() {
            continue;
        }
        let path = format!("evidence[{i}]");
        sh.need(ev, &path, "id", Ty::Str);
        // Section 2: changed is one of the five slots, which object varied.
        sh.need(ev, &path, "changed", Ty::Str);
        for key in ["compared", "moved"] {
            sh.may(ev, &path, key, Ty::Array);
            sh.each(ev, &path, key, Ty::Str);
        }
        sh.may(ev, &path, "fixed", Ty::Object);
        sh.may(ev, &path, "delta", Ty::Object);
        if let Some(d) = ev.get("delta").filter(|d| d.is_object()) {
            sh.may(d, &format!("{path}.delta"), "changes", Ty::Array);
            sh.each(d, &format!("{path}.delta"), "changes", Ty::Object);
        }
        sh.may(ev, &path, "observations", Ty::Array);
        sh.each(ev, &path, "observations", Ty::Object);
        for (j, o) in ev
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let op = format!("{path}.observations[{j}]");
            sh.may(o, &op, "carried", Ty::Object);
            sh.may(o, &op, "reference", Ty::Object);
        }
    }
    if let Some(ru) = report.get("roll-up").filter(|r| r.is_object()) {
        sh.may(ru, "roll-up", "negative-capable", Ty::Object);
        sh.may(ru, "roll-up", "completeness", Ty::Object);
        if let Some(nc) = ru.get("negative-capable").filter(|n| n.is_object()) {
            sh.may(nc, "roll-up.negative-capable", "control", Ty::Object);
            sh.may(nc, "roll-up.negative-capable", "reference", Ty::Object);
            sh.may(nc, "roll-up.negative-capable", "check-identity", Ty::Array);
        }
        if let Some(cl) = ru.get("completeness").and_then(Value::as_object) {
            for (k, v) in cl {
                if !v.is_object() {
                    sh.errors
                        .push(format!("roll-up.completeness.{k} is not an object"));
                }
            }
        }
    }
    sh.finish().map(|()| report)
}

/// Judge one report against an optional resolution store.
pub fn judge(subject: &Value, store: Option<&Map<String, Value>>) -> Judgement {
    let report = match shape(subject) {
        Ok(r) => r,
        Err(errs) => return Judgement::Shape(errs),
    };
    let mut rows = BTreeSet::new();
    let empty = Vec::new();
    let checks: Vec<&Map<String, Value>> = report
        .get("checks")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_object)
        .collect();
    let evidence: Vec<&Map<String, Value>> = report
        .get("evidence")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
        .iter()
        .filter_map(Value::as_object)
        .collect();
    let by_id: BTreeMap<&str, &Map<String, Value>> = evidence
        .iter()
        .filter_map(|e| s(e.get("id")).map(|id| (id, *e)))
        .collect();
    let run_domain = report
        .get("domain")
        .and_then(Value::as_object)
        .and_then(|d| s(d.get("id")));

    // Section 2, recomputed moved per evidence object (also fires row 20 on a mismatch).
    let mut moved_of: BTreeMap<&str, Option<BTreeSet<&'static str>>> = BTreeMap::new();
    for ev in &evidence {
        let recomputed = recompute_moved(ev, store, &mut rows);
        if let Some(id) = s(ev.get("id")) {
            moved_of.insert(id, recomputed.clone());
        }
        evidence_rows(ev, recomputed.as_ref(), run_domain, &mut rows);
    }

    for c in &checks {
        check_rows(c, &by_id, &moved_of, &mut rows);
    }
    check_set_rows(report, &checks, &mut rows);
    if let Some(ru) = report.get("roll-up").and_then(Value::as_object) {
        roll_up_rows(report, ru, &checks, &evidence, &mut rows);
    }
    if let Some(cov) = report.get("coverage") {
        coverage_rows(cov, &mut rows);
    }
    Judgement::Rows(rows)
}

fn check_rows(
    c: &Map<String, Value>,
    by_id: &BTreeMap<&str, &Map<String, Value>>,
    moved_of: &BTreeMap<&str, Option<BTreeSet<&'static str>>>,
    rows: &mut BTreeSet<String>,
) {
    let state = s(c.get("state")).unwrap_or("");
    let mut add = |r: &str| {
        rows.insert(r.to_string());
    };
    // Section 1.2: free text is refused in place of a disposition; the same
    // closed-vocabulary rule applies to every enumerated cell.
    if !STATES.contains(&state) {
        add("W3C-R-019");
    }
    let verdict = VERDICT.contains(&state);
    let non_verdict = STATES.contains(&state) && !verdict;
    let cause = c.get("cause");
    let code = cause
        .and_then(Value::as_object)
        .and_then(|m| s(m.get("code")));
    if cause.is_some() && !code.is_some_and(|k| CAUSES.contains(&k)) {
        add("W3C-R-019");
    }
    // Section 4 rows 1 to 7.
    if non_verdict && cause.is_none() {
        add("W3C-R-001");
    }
    if state == "void" && matches!(code, Some("not_applicable" | "out_of_scope" | "withheld")) {
        add("W3C-R-002");
    }
    if state == "not-exercised" && code == Some("integrity-failure") {
        add("W3C-R-003");
    }
    if code == Some("confinement-failed-during-check") && STATES.contains(&state) && state != "void"
    {
        add("W3C-R-004");
    }
    if c.get("declared-exclusion") == Some(&Value::Bool(true)) && state != "not-exercised" {
        add("W3C-R-005");
    }
    if non_verdict && (has(c, "other-verdict") || has(c, "discrimination")) {
        add("W3C-R-006");
    }
    if verdict && cause.is_some() {
        add("W3C-R-007");
    }
    // Section 1.3: unknown on both qualifiers is the default.
    let ov = c.get("other-verdict").and_then(Value::as_object);
    let dv = c.get("discrimination").and_then(Value::as_object);
    let ov_value = ov.and_then(|m| s(m.get("value"))).unwrap_or("unknown");
    let dv_value = dv.and_then(|m| s(m.get("value"))).unwrap_or("unknown");
    if (c.get("other-verdict").is_some() && !(ov.is_some() && OTHER_VERDICT.contains(&ov_value)))
        || (c.get("discrimination").is_some()
            && !(dv.is_some() && DISCRIMINATION.contains(&dv_value)))
    {
        add("W3C-R-019");
    }
    if ov_value == "foreclosed" && dv_value == "demonstrated" {
        add("W3C-R-008");
    }
    if dv_value == "demonstrated" && matches!(ov_value, "unknown" | "possible-not-demonstrated") {
        add("W3C-R-009");
    }
    if ov_value == "foreclosed" {
        if let Some(ov) = ov {
            if !(has(ov, "constraint-set") && has(ov, "domain")) {
                add("W3C-R-010");
            }
        }
    }
    // Row 11: an asserted value is read against its reference, and the
    // reference against the report's own evidence list.
    let ov_ref = ov
        .and_then(|m| s(m.get("ref")))
        .and_then(|r| by_id.get(r).map(|e| (r, *e)));
    let dv_ref = dv
        .and_then(|m| s(m.get("ref")))
        .and_then(|r| by_id.get(r).map(|e| (r, *e)));
    if (matches!(ov_value, "demonstrated" | "foreclosed") && ov_ref.is_none())
        || (dv_value == "demonstrated" && dv_ref.is_none())
    {
        add("W3C-R-011");
    }
    if dv_value == "demonstrated" {
        if let Some((_, ev)) = dv_ref {
            // Row 12: changed is the checker, which is attribution.
            if s(ev.get("changed")) == Some("checker rule") {
                add("W3C-R-012");
            }
            // Section 1.3: discrimination demonstrated means two observations
            // from the same pinned checker, under the same constraints and
            // domain, on two inputs related by a stated delta. Anything less is
            // not a delta-related pair.
            if !delta_related_pair(ev) {
                add("W3C-R-024");
            }
        }
    }
    // Row 13 (evidence class): degrades when moved could not be recomputed.
    if ov_value == "demonstrated" {
        if let Some((id, _)) = ov_ref {
            if let Some(Some(moved)) = moved_of.get(id) {
                if !moved.contains("verdict") {
                    add("W3C-R-025");
                }
            }
        }
    }
}

fn delta_related_pair(ev: &Map<String, Value>) -> bool {
    let two = ev
        .get("observations")
        .and_then(Value::as_array)
        .is_some_and(|o| o.len() == 2);
    let fixed = ev.get("fixed").and_then(Value::as_object).is_some_and(|f| {
        // "fixed: named, not implied" (section 2).
        ["checker", "constraint-set", "domain"]
            .iter()
            .all(|k| s(f.get(*k)).is_some_and(|v| !v.is_empty()))
    });
    let delta = ev
        .get("delta")
        .and_then(Value::as_object)
        .and_then(|d| d.get("changes"))
        .and_then(Value::as_array)
        .is_some_and(|a| {
            !a.is_empty()
                && a.iter()
                    .all(|c| c.get("field").is_some_and(Value::is_string))
        });
    two && fixed && delta
}

fn evidence_rows(
    ev: &Map<String, Value>,
    recomputed: Option<&BTreeSet<&'static str>>,
    run_domain: Option<&str>,
    rows: &mut BTreeSet<String>,
) {
    let mut add = |r: &str| {
        rows.insert(r.to_string());
    };
    let compared = str_list(ev.get("compared")).unwrap_or_default();
    let moved = str_list(ev.get("moved"));
    if ev.get("changed").is_some() && !s(ev.get("changed")).is_some_and(|c| CHANGED.contains(&c)) {
        add("W3C-R-019");
    }
    if compared
        .iter()
        .chain(moved.iter().flatten())
        .any(|x| !SLOTS.contains(&x.as_str()))
    {
        add("W3C-R-019");
    }
    // Section 2: an object whose moved is not contained in compared is rejected.
    if let Some(m) = &moved {
        if m.iter().any(|x| !compared.contains(x)) {
            add("W3C-R-016");
        }
    }
    // Row 14 (form): moved asserted on an object that neither carries both
    // observations nor references them with digests.
    if moved.as_ref().is_some_and(|m| !m.is_empty()) {
        let obs = ev.get("observations").and_then(Value::as_array);
        let backed = obs.is_some_and(|o| {
            o.len() == 2
                && o.iter().all(|x| {
                    let x = x.as_object();
                    x.and_then(|m| m.get("carried"))
                        .is_some_and(Value::is_object)
                        || x.and_then(|m| m.get("reference"))
                            .and_then(Value::as_object)
                            .is_some_and(|r| s(r.get("sha256")).is_some())
                })
        });
        if !backed {
            add("W3C-R-026");
        }
    }
    // Section 2: moved is recomputed, not declared. Each comparable slot of the
    // compared set is in moved exactly when it differs.
    if let (Some(rec), Some(m)) = (recomputed, &moved) {
        for slot in ["verdict", "fired-rule list"] {
            if compared.iter().any(|c| c == slot)
                && m.iter().any(|x| x == slot) != rec.contains(slot)
            {
                add("W3C-R-021");
            }
        }
    }
    // Section 2: arity is not a slot; it is recomputed from the delta.
    if ev
        .get("delta")
        .and_then(Value::as_object)
        .is_some_and(|d| d.contains_key("arity"))
    {
        add("W3C-R-027");
    }
    // Section 2: the domain is declared once at run level and referenced by
    // identifier; no slot restates it.
    if let Some(fixed) = ev.get("fixed").and_then(Value::as_object) {
        // The fixed slot names the run's domain by identifier: absent, it is
        // not named; an object, it is restated; another string, it is not the
        // run's.
        match fixed.get("domain") {
            Some(Value::String(d)) if run_domain.is_none_or(|r| r == d) => {}
            _ => add("W3C-R-028"),
        }
    }
}

fn leaves(checks: &[&Map<String, Value>]) -> Result<Vec<Vec<u8>>, String> {
    checks
        .iter()
        .map(|c| json::canonical(&Value::Object((*c).clone())))
        .collect()
}

/// Section 3.1: the count bound and the shape declared from the closed set,
/// then (reading table) the digest recomputed.
fn set_binding_ok(set: &Map<String, Value>) -> bool {
    count(set.get("leaf-count")).is_some()
        && s(set.get("tree-shape")).is_some_and(|t| tree::SHAPES.contains(&t))
}

fn check_set_rows(
    report: &Map<String, Value>,
    checks: &[&Map<String, Value>],
    rows: &mut BTreeSet<String>,
) {
    // A report MUST declare which tree shape its digest over the set uses, so a
    // report with no check-set, or a set with no digest, declares nothing.
    let Some(set) = report.get("check-set").and_then(Value::as_object) else {
        rows.insert("W3C-R-015".into());
        return;
    };
    if !set_binding_ok(set)
        || s(set.get("sha256")).is_none()
        || count(set.get("leaf-count")) != Some(checks.len() as i64)
    {
        rows.insert("W3C-R-015".into());
        return;
    }
    let shape = s(set.get("tree-shape")).unwrap_or("");
    let root = leaves(checks).ok().and_then(|l| tree::root(shape, &l));
    if root.as_deref() != s(set.get("sha256")) {
        rows.insert("W3C-R-020".into());
    }
}

fn roll_up_rows(
    report: &Map<String, Value>,
    ru: &Map<String, Value>,
    checks: &[&Map<String, Value>],
    evidence: &[&Map<String, Value>],
    rows: &mut BTreeSet<String>,
) {
    let mut add = |r: &str| {
        rows.insert(r.to_string());
    };
    let n_state = |st: &str| {
        checks
            .iter()
            .filter(|c| s(c.get("state")) == Some(st))
            .count() as i64
    };
    let declared = checks.len() as i64;
    let fails = n_state("fail");
    let voids = n_state("void");
    // Section 5.1: never emitted without its complete denominator, and an
    // aggregate counts exercised checks only.
    let expected = [
        ("declared", declared),
        ("exercised", declared - n_state("not-exercised")),
        ("pass", n_state("pass")),
        ("fail", fails),
        ("inconclusive", n_state("inconclusive")),
        ("not-exercised", n_state("not-exercised")),
        ("void", voids),
    ];
    if expected.iter().any(|(k, n)| count(ru.get(*k)) != Some(*n)) {
        add("W3C-R-017");
    }
    // Section 5.3: carried against referenced recomputes from the evidence.
    let mut carried = 0i64;
    let mut referenced = 0i64;
    for ev in evidence {
        for obs in ev
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let o = obs.as_object();
            if o.is_some_and(|m| m.contains_key("carried")) {
                carried += 1;
            } else if o.is_some_and(|m| m.contains_key("reference")) {
                referenced += 1;
            }
        }
    }
    if count(ru.get("carried")) != Some(carried) || count(ru.get("referenced")) != Some(referenced)
    {
        add("W3C-R-018");
    }
    // Section 5.4: the roll-up states whether its checks could have gone negative.
    let declared_ids: BTreeSet<&str> = checks.iter().filter_map(|c| s(c.get("check"))).collect();
    match ru.get("negative-capable").and_then(Value::as_object) {
        None => add("W3C-R-013"),
        Some(nc) => {
            // "Nothing" is a permitted answer; silence is not. An absent kind
            // is silence (row 13); a kind outside the set is free text (19).
            let kind = s(nc.get("kind")).unwrap_or("");
            if !nc.get("kind").is_some_and(Value::is_string) {
                add("W3C-R-013");
            } else if !NEGATIVE_CAPABLE.contains(&kind) {
                add("W3C-R-019");
            }
            match kind {
                // "Fail" here is the state fail: a non-pass is not enough.
                "shown-by-run" if fails == 0 => add("W3C-R-013"),
                "control-failed" => {
                    let control = nc.get("control").and_then(Value::as_object);
                    let state_fail = control.is_some_and(|c| s(c.get("state")) == Some("fail"));
                    // The control is the run's declared checks, not a check beside them.
                    let over_declared = control
                        .and_then(|c| str_list(c.get("checks")))
                        .is_some_and(|l| {
                            !l.is_empty() && l.iter().all(|x| declared_ids.contains(x.as_str()))
                        });
                    if !state_fail || !over_declared {
                        add("W3C-R-013");
                    }
                    // The control runs under the same checker and constraints.
                    let cf = control
                        .and_then(|c| c.get("fixed"))
                        .and_then(Value::as_object);
                    let rf = report.get("fixed").and_then(Value::as_object);
                    if let (Some(cf), Some(rf)) = (cf, rf) {
                        if cf.get("checker") != rf.get("checker")
                            || cf.get("constraint-set") != rf.get("constraint-set")
                        {
                            add("W3C-R-029");
                        }
                    }
                }
                "prior-discriminating-run" => {
                    // A prior run only counts where check identity survives.
                    let ids = str_list(nc.get("check-identity"));
                    if !ids.is_some_and(|l| {
                        !l.is_empty() && l.iter().all(|x| declared_ids.contains(x.as_str()))
                    }) {
                        add("W3C-R-014");
                    }
                    // Where the prior run names a set of observations, 3.1 applies.
                    if !nc
                        .get("reference")
                        .and_then(Value::as_object)
                        .is_some_and(set_binding_ok)
                    {
                        add("W3C-R-015");
                    }
                }
                _ => {}
            }
        }
    }
    // Section 5.2: each claim carries the size of its population; an empty
    // population is not claimable; no-void is satisfied iff no void record.
    if let Some(cl) = ru.get("completeness").and_then(Value::as_object) {
        let verdicts = n_state("pass") + fails;
        for (name, claim) in cl {
            let population = match name.as_str() {
                "accounting" | "execution" | "no-void" => declared,
                "evidence" => verdicts,
                _ => continue,
            };
            let claim = claim.as_object();
            let pop = claim.and_then(|c| count(c.get("population")));
            let value = claim.and_then(|c| s(c.get("claim")));
            if value.is_some_and(|v| !CLAIMS.contains(&v)) {
                add("W3C-R-019");
            }
            let wrong = pop != Some(population)
                || (population == 0 && value != Some("not-claimable"))
                || (name == "no-void"
                    && population > 0
                    && value
                        != Some(if voids == 0 {
                            "satisfied"
                        } else {
                            "not-satisfied"
                        }));
            if wrong {
                add("W3C-R-023");
            }
        }
    }
}

/// Message 0001 (proposed, not in v0.1): the coverage block in controlled
/// fields, with the count of scannable files recorded before the per-repo cap.
fn coverage_rows(cov: &Value, rows: &mut BTreeSet<String>) {
    let ok = cov.as_object().is_some_and(|c| {
        let text = |k: &str| s(c.get(k)).is_some_and(|v| !v.is_empty());
        let boolean = |k: &str| c.get(k).is_some_and(Value::is_boolean);
        text("surface")
            && text("scan-depth")
            && text("point-in-time")
            && text("linked-repo")
            && boolean("live-observed")
            && boolean("sampled")
            && count(c.get("scannable-files")).is_some_and(|n| n >= 0)
            && c.get("snapshots")
                .and_then(Value::as_array)
                .is_some_and(|snaps| {
                    !snaps.is_empty()
                        && snaps.iter().all(|x| {
                            x.as_object().is_some_and(|m| {
                                s(m.get("name")).is_some_and(|v| !v.is_empty())
                                    && s(m.get("date")).is_some_and(|v| !v.is_empty())
                            })
                        })
                })
    });
    if !ok {
        rows.insert("W3C-R-022".into());
    }
}

/// What the report-file mode measured about one emitted report.
pub struct SetMeasure {
    pub leaf_count_declared: Option<i64>,
    pub leaf_count_measured: usize,
    pub shape: Option<String>,
    pub sha256_declared: Option<String>,
    pub sha256_recomputed: Option<String>,
}

/// Recompute the check-set digest and count of a report, independently of the rows.
pub fn measure_set(subject: &Value) -> Option<SetMeasure> {
    let report = subject.as_object()?;
    let checks: Vec<&Map<String, Value>> = report
        .get("checks")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .collect();
    let set = report.get("check-set").and_then(Value::as_object);
    let shape = set.and_then(|x| s(x.get("tree-shape"))).map(str::to_string);
    let recomputed = shape
        .as_deref()
        .and_then(|sh| leaves(&checks).ok().and_then(|l| tree::root(sh, &l)));
    Some(SetMeasure {
        leaf_count_declared: set.and_then(|x| count(x.get("leaf-count"))),
        leaf_count_measured: checks.len(),
        shape,
        sha256_declared: set.and_then(|x| s(x.get("sha256"))).map(str::to_string),
        sha256_recomputed: recomputed,
    })
}
