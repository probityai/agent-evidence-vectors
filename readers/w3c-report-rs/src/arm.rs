//! The Run object of draft-arsentev-agent-run-metrics-00, judged by the
//! draft's own sentences (vendored as
//! `spec-vendored/draft-arsentev-agent-run-metrics-00.txt`). Section numbers
//! below are the draft's.

use crate::report::{count, Judgement};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Section 3.1, Table 1: the members of a Run.
const RUN_MEMBERS: [&str; 18] = [
    "version",
    "run_id",
    "parent_run_id",
    "root_run_id",
    "start",
    "end",
    "status",
    "termination_reason",
    "agent",
    "models",
    "step_count",
    "steps",
    "totals",
    "subtree_totals",
    "cost",
    "derived",
    "trace_id",
    "labels",
];
/// Section 3.1: REQUIRED members, in table order.
const REQUIRED: [&str; 6] = [
    "version",
    "run_id",
    "start",
    "status",
    "step_count",
    "totals",
];
/// Section 3.1: the closed status enumeration.
const STATUS: [&str; 4] = ["running", "completed", "failed", "aborted"];
/// Section 3.4: the counters of a Usage object.
const COUNTERS: [&str; 5] = [
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
];

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// Section 5: an RFC 3339 date-time in the Z offset, as a sortable key
/// (seconds since a fixed epoch scaled to nanoseconds), or None.
fn timestamp(text: &str) -> Option<i128> {
    let b = text.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i128> {
        let part = text.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut rest = &text[19..];
    let mut nanos: i128 = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let padded = format!("{:0<9}", &digits[..digits.len().min(9)]);
        nanos = padded.parse().ok()?;
        rest = &frac[digits.len()..];
    }
    if rest != "Z" {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo)
        || d < 1
        || d > mdays[(mo - 1) as usize]
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se) * 1_000_000_000) + nanos)
}

/// Section 3.7: amount = [ "-" ] 1*DIGIT [ "." 1*DIGIT ]
fn amount_ok(text: &str) -> bool {
    let body = text.strip_prefix('-').unwrap_or(text);
    let (int, frac) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    digits(int) && frac.is_none_or(digits)
}

/// Section 5: identifiers are non-empty strings of at most 128 characters.
fn identifier_ok(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|t| !t.is_empty() && t.chars().count() <= 128)
}

fn usages(run: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    let mut out = Vec::new();
    for key in ["totals", "subtree_totals"] {
        if let Some(u) = run.get(key).and_then(Value::as_object) {
            out.push(u);
        }
    }
    for step in run
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(u) = step.get("usage").and_then(Value::as_object) {
            out.push(u);
        }
    }
    out
}

/// Judge one Run object.
pub fn judge(subject: &Value) -> Judgement {
    let Some(run) = subject.as_object() else {
        return Judgement::Shape(vec!["the Run is not a JSON object".into()]);
    };
    let missing: Vec<String> = REQUIRED
        .iter()
        .filter(|k| !run.contains_key(**k))
        .map(|k| format!("the Run carries no {k} member"))
        .collect();
    if !missing.is_empty() {
        return Judgement::Shape(missing);
    }
    {
        use crate::shape::{Shape, Ty};
        // Section 3.1 and 3.2: member types. Values are the rows' to read.
        let mut sh = Shape::default();
        sh.need(subject, "", "step_count", Ty::Int);
        sh.need(subject, "", "totals", Ty::Object);
        sh.may(subject, "", "steps", Ty::Array);
        sh.each(subject, "", "steps", Ty::Object);
        sh.may(subject, "", "subtree_totals", Ty::Object);
        sh.may(subject, "", "cost", Ty::Object);
        sh.may(subject, "", "agent", Ty::Object);
        for (i, st) in run
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if st.is_object() {
                let p = format!("steps[{i}]");
                sh.need(st, &p, "index", Ty::Int);
                sh.need(st, &p, "kind", Ty::Str);
            }
        }
        for key in ["totals", "subtree_totals"] {
            if let Some(u) = run.get(key).filter(|u| u.is_object()) {
                sh.may(u, key, "cache_writes", Ty::Array);
                sh.each(u, key, "cache_writes", Ty::Object);
            }
        }
        for (i, st) in run
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            if let Some(u) = st.get("usage").filter(|u| u.is_object()) {
                let p = format!("steps[{i}].usage");
                sh.may(u, &p, "cache_writes", Ty::Array);
                sh.each(u, &p, "cache_writes", Ty::Object);
            }
        }
        if let Err(errs) = sh.finish() {
            return Judgement::Shape(errs);
        }
    }
    let mut rows = BTreeSet::new();
    let mut add = |r: &str| {
        rows.insert(r.to_string());
    };
    let steps: Vec<&Map<String, Value>> = run
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .collect();

    // 5.1: Reporter MUST emit "1".
    if s(run.get("version")) != Some("1") {
        add("ARM-R-001");
    }
    // 3.1: end present iff terminal, and never before start.
    let status = s(run.get("status")).unwrap_or("");
    let has_end = run.contains_key("end");
    if (matches!(status, "completed" | "failed" | "aborted") && !has_end)
        || (status == "running" && has_end)
    {
        add("ARM-R-002");
    }
    if let (Some(a), Some(b)) = (
        s(run.get("start")).and_then(timestamp),
        s(run.get("end")).and_then(timestamp),
    ) {
        if b < a {
            add("ARM-R-003");
        }
    }
    if !STATUS.contains(&status) {
        add("ARM-R-004");
    }
    // 3.1: step_count is at least the length of steps.
    if run.contains_key("steps")
        && count(run.get("step_count")).is_none_or(|n| n < steps.len() as i64)
    {
        add("ARM-R-005");
    }
    // 3.2: index unique and assigned in the order Steps began.
    let idx: Vec<Option<i64>> = steps.iter().map(|st| count(st.get("index"))).collect();
    let unique =
        idx.iter().flatten().collect::<BTreeSet<_>>().len() == idx.iter().flatten().count();
    // Order is read off the start instants; a start that is not a timestamp
    // is row 19's, and leaves the order unestablished rather than wrong.
    let starts: Option<Vec<i128>> = steps
        .iter()
        .map(|st| s(st.get("start")).and_then(timestamp))
        .collect();
    let in_order = starts.is_none_or(|starts| {
        let mut order: Vec<(i128, usize)> = starts.into_iter().zip(0..).collect();
        order.sort();
        order.windows(2).all(|w| match (idx[w[0].1], idx[w[1].1]) {
            (Some(a), Some(b)) => w[0].0 == w[1].0 || a < b,
            _ => true,
        })
    });
    if !unique || !in_order || idx.iter().any(Option::is_none) {
        add("ARM-R-006");
    }
    for st in &steps {
        match s(st.get("kind")) {
            // 3.2, 3.4, 3.8, 3.11: usage, model and tool are objects when present.
            Some("model_invocation")
                if !(st.get("usage").is_some_and(Value::is_object)
                    && st.get("model").is_some_and(Value::is_object)) =>
            {
                add("ARM-R-007")
            }
            Some("tool_call")
                if !st.get("tool").is_some_and(Value::is_object) || st.contains_key("usage") =>
            {
                add("ARM-R-008")
            }
            _ => {}
        }
    }
    // 3.4 and 3.5, per Usage object.
    for u in usages(run) {
        for (k, v) in u {
            if k == "cache_writes" {
                continue;
            }
            if count(Some(v)).is_none_or(|n| n < 0) {
                add("ARM-R-009");
            }
        }
        // The subset rows read well-typed counters only: a counter that is not
        // a non-negative integer is row 9's, and the partition of row 11
        // presupposes that each part is a subset (row 10 for the reads).
        let c = |k: &str| count(u.get(k)).filter(|n| *n >= 0);
        if let (Some(r), Some(i)) = (c("cache_read_tokens"), c("input_tokens")) {
            if r > i {
                add("ARM-R-010");
            }
            if let Some(w) = c("cache_write_tokens") {
                if r <= i && w <= i && r + w > i {
                    add("ARM-R-011");
                }
            }
        }
        if let (Some(r), Some(o)) = (c("reasoning_tokens"), c("output_tokens")) {
            if r > o {
                add("ARM-R-022");
            }
        }
        if let Some(ledger) = u.get("cache_writes").and_then(Value::as_array) {
            let lifetimes: Vec<&str> = ledger.iter().filter_map(|e| s(e.get("lifetime"))).collect();
            if lifetimes.iter().collect::<BTreeSet<_>>().len() != lifetimes.len() {
                add("ARM-R-013");
            }
            // A ledger element without integer tokens cannot sum to anything.
            let tokens: Option<Vec<i64>> = ledger
                .iter()
                .map(|e| count(e.get("tokens")).filter(|n| *n >= 0))
                .collect();
            // An absent aggregate counts as zero, so a ledger beside no
            // cache_write_tokens must itself sum to zero; a mistyped one is row 9's.
            let total = match u.get("cache_write_tokens") {
                None => Some(0),
                Some(_) => c("cache_write_tokens"),
            };
            if let Some(total) = total {
                if tokens.is_none_or(|t| t.iter().sum::<i64>() != total) {
                    add("ARM-R-014");
                }
            }
        }
    }
    // 3.4: totals are, member by member, the sum over every Step's Usage.
    // Only checkable when the array holds every Step (3.1 lets it omit some)
    // and every counter read is a well-typed counter (row 9 owns the rest).
    let complete =
        run.contains_key("steps") && count(run.get("step_count")) == Some(steps.len() as i64);
    if let (Some(totals), true) = (run.get("totals").and_then(Value::as_object), complete) {
        let read = |u: Option<&Map<String, Value>>, k: &str| -> Option<i64> {
            match u.and_then(|u| u.get(k)) {
                None => Some(0),
                Some(v) => count(Some(v)).filter(|n| *n >= 0),
            }
        };
        for k in COUNTERS {
            let parts: Option<Vec<i64>> = steps
                .iter()
                .map(|st| read(st.get("usage").and_then(Value::as_object), k))
                .collect();
            // A totals member that is not a counter cannot be the sum.
            if let Some(parts) = parts {
                if read(Some(totals), k) != Some(parts.iter().sum::<i64>()) {
                    add("ARM-R-012");
                }
            }
        }
    }
    // 3.3: no two Steps with the same invocation_id.
    let inv: Vec<&str> = steps
        .iter()
        .filter_map(|st| s(st.get("invocation_id")))
        .collect();
    if inv.iter().collect::<BTreeSet<_>>().len() != inv.len() {
        add("ARM-R-015");
    }
    // 3.6: a parentless Run that emits root_run_id names itself.
    if run.contains_key("root_run_id")
        && !run.contains_key("parent_run_id")
        && run.get("root_run_id") != run.get("run_id")
    {
        add("ARM-R-016");
    }
    // 3.7: the amount ABNF.
    if let Some(cost) = run.get("cost") {
        if !cost
            .get("amount")
            .and_then(Value::as_str)
            .is_some_and(amount_ok)
        {
            add("ARM-R-017");
        }
    }
    // 3.12: labels are an object of string values.
    if let Some(labels) = run.get("labels") {
        if !labels
            .as_object()
            .is_some_and(|m| m.values().all(Value::is_string))
        {
            add("ARM-R-018");
        }
    }
    // 5: timestamps in RFC 3339 with the Z offset.
    let mut stamps: Vec<&Value> = ["start", "end"]
        .iter()
        .filter_map(|k| run.get(*k))
        .collect();
    for st in &steps {
        stamps.extend(["start", "end"].iter().filter_map(|k| st.get(*k)));
    }
    if stamps
        .iter()
        .any(|v| v.as_str().and_then(timestamp).is_none())
    {
        add("ARM-R-019");
    }
    // 5: identifier members.
    let mut ids: Vec<&Value> = ["run_id", "parent_run_id", "root_run_id"]
        .iter()
        .filter_map(|k| run.get(*k))
        .collect();
    if let Some(agent) = run.get("agent").and_then(Value::as_object) {
        ids.extend(agent.get("name"));
    }
    for st in &steps {
        ids.extend(
            ["invocation_id", "child_run_id"]
                .iter()
                .filter_map(|k| st.get(*k)),
        );
        if let Some(tool) = st.get("tool").and_then(Value::as_object) {
            ids.extend(tool.get("name"));
        }
    }
    if ids.iter().any(|v| !identifier_ok(v)) {
        add("ARM-R-020");
    }
    // 5.1: an unprefixed member is used only for its defined purpose.
    if run
        .keys()
        .any(|k| !RUN_MEMBERS.contains(&k.as_str()) && !k.starts_with("x-"))
    {
        add("ARM-R-021");
    }
    Judgement::Rows(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_need_the_z_offset() {
        assert!(timestamp("2026-09-18T10:00:00.000Z").is_some());
        assert!(timestamp("2026-09-18T10:00:00Z").is_some());
        assert!(timestamp("2026-09-18T12:00:00+02:00").is_none());
        assert!(timestamp("2026-02-30T00:00:00Z").is_none());
        assert!(timestamp("2026-09-18T09:00:00Z") < timestamp("2026-09-18T10:00:00Z"));
    }

    #[test]
    fn amount_follows_the_abnf() {
        assert!(amount_ok("1.5"));
        assert!(amount_ok("-12"));
        assert!(!amount_ok("1,5"));
        assert!(!amount_ok("1."));
        assert!(!amount_ok(".5"));
        assert!(!amount_ok(""));
    }
}
