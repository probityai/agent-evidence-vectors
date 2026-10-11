//! The discovery snapshot of draft-arsentev-llm-context-discovery-00, judged
//! by the draft's own sentences (vendored as
//! `spec-vendored/draft-arsentev-llm-context-discovery-00.txt`). Section
//! numbers below are the draft's.

use crate::report::{count, Judgement};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Section 4.1: the redirect statuses.
const REDIRECTS: [i64; 4] = [301, 302, 307, 308];
/// Section 4.1 registers this well-known suffix.
const WELL_KNOWN: &str = "/.well-known/llm-context";

fn s(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

/// RFC 3986 section 3.1: an absolute URI starts with a scheme and a colon.
fn absolute(uri: &str) -> bool {
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The origin (scheme, host, port) of an absolute http(s) URI, and its path.
fn split(uri: &str) -> Option<(String, String)> {
    let (scheme, rest) = uri.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    Some((
        format!(
            "{}://{}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase()
        ),
        path.to_string(),
    ))
}

fn origin_of(uri: &str) -> Option<String> {
    split(uri).map(|(o, _)| o)
}

/// RFC 9309: a path is excluded when a disallow rule is a prefix of it.
fn excluded(uri: &str, origin: &str, disallow: &[&str]) -> bool {
    match split(uri) {
        Some((o, path)) if o == origin => disallow
            .iter()
            .any(|d| !d.is_empty() && path.starts_with(d)),
        _ => false,
    }
}

/// Judge one discovery snapshot.
pub fn judge(subject: &Value) -> Judgement {
    let Some(snap) = subject.as_object() else {
        return Judgement::Shape(vec!["the snapshot is not a JSON object".into()]);
    };
    let missing: Vec<String> = ["origin", "robots", "consumer", "resources"]
        .iter()
        .filter(|k| !snap.contains_key(**k))
        .map(|k| format!("the snapshot carries no {k} member"))
        .collect();
    if !missing.is_empty() {
        return Judgement::Shape(missing);
    }
    {
        use crate::shape::{Shape, Ty};
        // Member types of the snapshot; values are the rows' to read.
        let mut sh = Shape::default();
        sh.need(subject, "", "origin", Ty::Str);
        sh.may(subject, "", "well-known", Ty::Object);
        sh.need(subject, "", "robots", Ty::Object);
        sh.need(subject, "", "consumer", Ty::Object);
        sh.need(subject, "", "resources", Ty::Object);
        sh.may(subject, "", "link", Ty::ObjectOrNull);
        if let Some(r) = snap.get("robots").filter(|r| r.is_object()) {
            sh.may(r, "robots", "disallow", Ty::Array);
            sh.each(r, "robots", "disallow", Ty::Str);
            sh.may(r, "robots", "records", Ty::Array);
            sh.each(r, "robots", "records", Ty::Object);
        }
        if let Some(c) = snap.get("consumer").filter(|c| c.is_object()) {
            sh.may(c, "consumer", "retrieved", Ty::Array);
            sh.each(c, "consumer", "retrieved", Ty::Str);
        }
        if let Some(w) = snap.get("well-known").filter(|w| w.is_object()) {
            sh.may(w, "well-known", "location", Ty::StrOrNull);
            sh.may(w, "well-known", "content-type", Ty::StrOrNull);
        }
        if let Some(res) = snap.get("resources").and_then(Value::as_object) {
            for (u, r) in res {
                if !r.is_object() {
                    sh.errors.push(format!("resources.{u} is not an object"));
                }
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
    let empty = Map::new();
    let origin = s(snap.get("origin"))
        .and_then(origin_of)
        .unwrap_or_default();
    let wk = snap
        .get("well-known")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let robots = snap
        .get("robots")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let consumer = snap
        .get("consumer")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let resources = snap
        .get("resources")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let role = |u: &str| resources.get(u).and_then(|r| s(r.get("role")));
    let disallow: Vec<&str> = robots
        .get("disallow")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let records: Vec<&str> = robots
        .get("records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| s(r.get("name")).is_some_and(|n| n.eq_ignore_ascii_case("llm-context")))
        .map(|r| s(r.get("value")).unwrap_or(""))
        .collect();
    let status = count(wk.get("status"));
    let location = s(wk.get("location"));
    // A redirect counts only with a Location that is an absolute URI.
    let redirect = status.is_some_and(|c| REDIRECTS.contains(&c)) && location.is_some_and(absolute);
    let served = status.is_some_and(|c| (200..300).contains(&c));
    let link = snap
        .get("link")
        .and_then(Value::as_object)
        .and_then(|l| s(l.get("target")));

    // 3.1: a context file is never served as text/html.
    if let Some(ct) = s(wk.get("content-type")) {
        let media = ct
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if media == "text/html" {
            add("LCD-R-001");
        }
    }
    // 4.1: the well-known request returns the index (2xx) or a redirect to it;
    // a 404 advertises nothing and is not an error.
    if snap.contains_key("well-known") && !(served || redirect || status == Some(404)) {
        add("LCD-R-003");
    }
    // 3.2: every mechanism points at an index resource.
    let mut targets: Vec<&str> = records.clone();
    if redirect {
        targets.extend(location);
    }
    targets.extend(link);
    if targets.iter().any(|t| role(t) == Some("detail")) {
        add("LCD-R-002");
    }
    // 4.3: the record's value is an absolute URI, and not one the same
    // robots.txt disallows.
    if records.iter().any(|v| !absolute(v)) {
        add("LCD-R-004");
    }
    if records.iter().any(|v| excluded(v, &origin, &disallow)) {
        add("LCD-R-005");
    }
    // 4.4: precedence, highest first: Link, well-known, robots record.
    let well_known_target = if redirect {
        location.map(str::to_string)
    } else if served {
        Some(format!("{origin}{WELL_KNOWN}"))
    } else {
        None
    };
    let chosen = link
        .map(str::to_string)
        .or(well_known_target)
        .or(records.first().map(|v| v.to_string()));
    // A consumer that resolved something other than what the precedence
    // picks (or something no mechanism advertised) did not apply it.
    let resolved = s(consumer.get("resolved"));
    if let Some(r) = consumer.get("resolved").filter(|v| !v.is_null()) {
        if chosen.as_deref() != r.as_str() {
            add("LCD-R-006");
        }
    }
    let retrieved: Vec<&str> = consumer
        .get("retrieved")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // 4.4: at most one index resource per origin per cycle.
    let mut per_origin: BTreeMap<String, usize> = BTreeMap::new();
    for u in &retrieved {
        if role(u) == Some("index") {
            *per_origin
                .entry(origin_of(u).unwrap_or_default())
                .or_default() += 1;
        }
    }
    if per_origin.values().any(|n| *n > 1) {
        add("LCD-R-007");
    }
    // 4.4: robots exclusion is evaluated against the index URI before retrieval.
    if retrieved
        .iter()
        .any(|u| role(u) == Some("index") && excluded(u, &origin, &disallow))
    {
        add("LCD-R-011");
    }
    // 7.2: content is attributed to the origin that serves it.
    if let Some(served_by) = resolved.and_then(origin_of) {
        if s(consumer.get("attributed-to")).and_then(origin_of) != Some(served_by) {
            add("LCD-R-008");
        }
    }
    // 7.4: the consumer imposes its own ceiling.
    if count(consumer.get("ceiling-octets")).is_none_or(|n| n <= 0) {
        add("LCD-R-009");
    }
    // 3.3: a negotiated response carries Content-Language.
    if served
        && wk.get("negotiated") == Some(&Value::Bool(true))
        && s(wk.get("content-language")).is_none_or(str::is_empty)
    {
        add("LCD-R-010");
    }
    Judgement::Rows(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_needs_a_scheme() {
        assert!(absolute("https://example.invalid/llms.txt"));
        assert!(!absolute("/llms.txt"));
        assert!(!absolute("llms.txt"));
    }

    #[test]
    fn exclusion_is_a_path_prefix_on_the_same_origin() {
        let d = ["/private/"];
        assert!(excluded(
            "https://example.invalid/private/llms.txt",
            "https://example.invalid",
            &d
        ));
        assert!(!excluded(
            "https://example.invalid/llms.txt",
            "https://example.invalid",
            &d
        ));
        assert!(!excluded(
            "https://other.invalid/private/x",
            "https://example.invalid",
            &d
        ));
    }
}
