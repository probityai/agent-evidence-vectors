//! JSON intake and the two byte forms this reader writes.
//!
//! Intake goes through `jcs-admit` first, so a document with a repeated
//! member, nesting past 128 levels, a non-scalar string or a non-finite
//! number is refused on its raw bytes before any parse can collapse it.
//!
//! Three writers follow. `jcs_sha256` is RFC 8785 under the integer profile the
//! list proposed for a digest over a JSON value (2026Oct/0038, 0040, 0041): every
//! number an integer of magnitude below 2^53 by its exact value; it writes the
//! check-set leaves. `canonical` is RFC 8785 as written, numbers as IEEE 754
//! doubles; it writes member identifiers, so a member carrying a number the
//! profile refuses still has a name. `pretty` is
//! the layout the corpus and the reference emitter write files in: two-space
//! indent, keys sorted by code point, non-ASCII escaped, one trailing newline.
//! Neither writer is shared with the other readers; both are written here from
//! the RFC and from the bytes of the committed files.

use serde_json::{Map, Number, Value};
use std::fmt::Write as _;

/// Why a document could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// `jcs-admit` refused the bytes (duplicate member, depth, scalar, size).
    Inadmissible(String),
    /// The bytes are not JSON at all.
    Syntax(String),
}

/// Admit, then parse. Member order is preserved and number tokens keep the
/// exact text they were written with.
pub fn read(bytes: &[u8]) -> Result<Value, ReadError> {
    if let Err(err) = jcs_admit::admit(bytes) {
        let text = err.to_string();
        // A plain syntax error is reported as one, not as an admission refusal.
        return match serde_json::from_slice::<Value>(bytes) {
            Err(parse) => Err(ReadError::Syntax(parse.to_string())),
            Ok(_) => Err(ReadError::Inadmissible(text)),
        };
    }
    serde_json::from_slice(bytes).map_err(|e| ReadError::Syntax(e.to_string()))
}

/// True when a number token is not an integer token (it has a fraction or an
/// exponent), which is how a JSON float is told apart from an integer.
pub fn is_float_token(n: &Number) -> bool {
    let text = n.to_string();
    text.contains(['.', 'e', 'E'])
}

/// The shortest round-trip decimal of a float token, laid out the way the
/// corpus's own tools print one: exponent form below 1e-4 or from 1e16 up,
/// otherwise positional with at least one fractional digit.
pub fn float_repr(n: &Number) -> String {
    let parsed: f64 = n.to_string().parse().unwrap_or(f64::NAN);
    repr_f64(parsed)
}

fn repr_f64(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    // `{:e}` gives the shortest round-trip digits as d[.ddd]e<exp>.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = match sci.split_once('e') {
        Some((m, e)) => (m.to_string(), e.parse::<i32>().unwrap_or(0)),
        None => (sci.clone(), 0),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let sign = if x < 0.0 { "-" } else { "" };
    if !(-4..16).contains(&exp) {
        let mut m = String::new();
        m.push_str(&digits[..1]);
        if digits.len() > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{m}e{esign}{:02}", exp.abs());
    }
    let point = exp + 1; // digits before the decimal point
    let body = if point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else if (point as usize) >= digits.len() {
        format!("{}{}.0", digits, "0".repeat(point as usize - digits.len()))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    };
    format!("{sign}{body}")
}

/// A number the profile refuses: an exact value that is not an integer.
pub const NON_INTEGER: &str = "non-integer-number";
/// A number the profile refuses: an integer of magnitude 2^53 or more.
pub const OUTSIDE_SAFE_RANGE: &str = "integer-outside-safe-range";
/// A number RFC 8785 itself has no form for: no finite double.
pub const NOT_FINITE: &str = "number-not-finite";

/// A value with no form under an encoding: a cause code and the number token
/// it is about, as the token was written.
#[derive(Debug)]
pub struct Refusal {
    pub cause: &'static str,
    pub token: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.cause, self.token)
    }
}

fn refusal(err: jcs_admit::Error) -> Refusal {
    match err {
        jcs_admit::Error::NonIntegerNumber { token } => Refusal {
            cause: NON_INTEGER,
            token,
        },
        jcs_admit::Error::UnsafeInteger { token } => Refusal {
            cause: OUTSIDE_SAFE_RANGE,
            token,
        },
        jcs_admit::Error::NonFiniteNumber { token } => Refusal {
            cause: NOT_FINITE,
            token,
        },
        other => Refusal {
            cause: "inadmissible",
            token: other.to_string(),
        },
    }
}

/// RFC 8785 as written, numbers as IEEE 754 doubles, via `jcs-admit` (which also
/// admits the result): the bytes a member identifier names.
pub fn canonical(value: &Value) -> Result<Vec<u8>, Refusal> {
    let raw = serde_json::to_vec(value).map_err(|e| Refusal {
        cause: "inadmissible",
        token: e.to_string(),
    })?;
    jcs_admit::admit(&raw).map_err(refusal)
}

/// The bytes a jcs-sha256 digest is taken over: RFC 8785 under the integer
/// profile, decided by `jcs-admit` on each number token's exact value.
pub fn jcs_sha256(value: &Value) -> Result<Vec<u8>, Refusal> {
    let raw = serde_json::to_vec(value).map_err(|e| Refusal {
        cause: "inadmissible",
        token: e.to_string(),
    })?;
    let profile = jcs_admit::Options::rfc8785()
        .safe_integers(true)
        .integers_only(true);
    jcs_admit::admit_with(&raw, &profile).map_err(refusal)
}

/// The two-space, sorted-key, ASCII-escaped layout with a trailing newline.
pub fn pretty(value: &Value) -> String {
    let mut out = String::new();
    write_pretty(value, 0, &mut out);
    out.push('\n');
    out
}

fn write_pretty(value: &Value, level: usize, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if is_float_token(n) {
                out.push_str(&float_repr(n));
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_ascii_string(s, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(level + 1, out);
                write_pretty(item, level + 1, out);
            }
            newline(level, out);
            out.push(']');
        }
        Value::Object(map) => write_object(map, level, out),
    }
}

fn write_object(map: &Map<String, Value>, level: usize, out: &mut String) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    out.push('{');
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        newline(level + 1, out);
        write_ascii_string(key, out);
        out.push_str(": ");
        if let Some(v) = map.get(*key) {
            write_pretty(v, level + 1, out);
        }
    }
    newline(level, out);
    out.push('}');
}

fn newline(level: usize, out: &mut String) {
    out.push('\n');
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_ascii_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", unit);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(text: &str) -> Number {
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Number(n)) => n,
            other => panic!("not a number: {other:?}"),
        }
    }

    #[test]
    fn float_layout_matches_the_shortest_round_trip_rules() {
        assert_eq!(float_repr(&num("1.0")), "1.0");
        assert_eq!(float_repr(&num("2.50")), "2.5");
        assert_eq!(float_repr(&num("1e16")), "1e+16");
        assert_eq!(float_repr(&num("1.5e16")), "1.5e+16");
        assert_eq!(float_repr(&num("123456789012345.6")), "123456789012345.6");
        assert_eq!(float_repr(&num("0.0001")), "0.0001");
        assert_eq!(float_repr(&num("0.00001")), "1e-05");
        assert_eq!(float_repr(&num("-3E2")), "-300.0");
    }

    #[test]
    fn duplicate_members_are_refused_before_parsing() {
        assert!(matches!(
            read(br#"{"a":1,"a":2}"#),
            Err(ReadError::Inadmissible(_))
        ));
        assert!(matches!(read(b"{nope"), Err(ReadError::Syntax(_))));
    }

    #[test]
    fn pretty_layout_sorts_and_escapes() {
        let v: Value = serde_json::from_str(r#"{"b":[],"a":{"z":"\u00e9","y":{}},"c":[1,"x"]}"#)
            .unwrap_or(Value::Null);
        assert_eq!(
            pretty(&v),
            "{\n  \"a\": {\n    \"y\": {},\n    \"z\": \"\\u00e9\"\n  },\n  \"b\": [],\n  \"c\": [\n    1,\n    \"x\"\n  ]\n}\n"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The two W3C columns of the shared table: written from the Python reader
    /// by scripts/json-encoding-differential-test.py and held to the Go reader by
    /// corpusreaders/w3cjcs_test.go. This reader must write the same bytes, or refuse
    /// with the same cause and token, for every document. Each document is
    /// parsed without this reader's admission step, which refuses a number with
    /// no finite double before either encoder is reached. A refusal is compared
    /// by its cause: serde_json writes a token's exponent back as e+N.
    #[test]
    fn the_shared_encoding_table_holds() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpusreaders/testdata/json-encodings.json"
        );
        let raw = std::fs::read(path).unwrap_or_default();
        let table: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let cases = table["cases"].as_array().cloned().unwrap_or_default();
        assert!(
            !cases.is_empty(),
            "the shared table at {path} holds no cases"
        );
        type Encoder = fn(&Value) -> Result<Vec<u8>, Refusal>;
        let encoders: [(&str, Encoder); 2] = [("jcs-sha256", jcs_sha256), ("rfc8785", canonical)];
        let mut checked = 0;
        for case in &cases {
            let name = case["name"].as_str().unwrap_or_default();
            let doc = case["doc"].as_str().unwrap_or_default();
            let value: Value = match serde_json::from_str(doc) {
                Ok(v) => v,
                Err(e) => panic!("{name}: the document does not parse: {e}"),
            };
            for (column, encode) in encoders {
                let cell = &case[column];
                match encode(&value) {
                    Ok(bytes) => assert_eq!(
                        cell["hex"].as_str(),
                        Some(hex(&bytes).as_str()),
                        "{column} {name}: this reader wrote {:?}",
                        String::from_utf8_lossy(&bytes)
                    ),
                    // The cause only: serde_json respells a token's exponent.
                    Err(refused) => assert_eq!(
                        cell["refused"].as_str(),
                        Some(refused.cause),
                        "{column} {name}: this reader refused with {refused}"
                    ),
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 2 * cases.len());
    }

    #[test]
    fn canonical_is_rfc8785() {
        let v: Value =
            serde_json::from_str(r#"{"b":1,"a":[true,null,"x"]}"#).unwrap_or(Value::Null);
        assert_eq!(
            canonical(&v).ok(),
            Some(br#"{"a":[true,null,"x"],"b":1}"#.to_vec())
        );
    }
}
