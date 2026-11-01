//! The seam where admission hands off to canonicalization.
//!
//! This crate refuses; it does not serialize. `serde_json_canonicalizer` 0.3.2
//! implements RFC 8785 section 3.2.2.3 over `ryu_js`, which is the ECMAScript
//! `Number::toString` variant the section requires rather than a general float
//! formatter, and it had 5,259,528 recent downloads when this crate chose it
//! (crates.io API, 2026-09-19). Writing a third implementation of that algorithm
//! would add a way for the rails to disagree and nothing else.
//!
//! So the whole of this file is one `Serialize` impl. A [`Node`] that reached
//! here is already admitted: its members are unique, its strings are sequences of
//! Unicode scalar values, its nesting is inside the cap, and its number tokens
//! have finite doubles. What remains is laying out bytes, and that is the
//! delegate's job.
//!
//! # Why the number goes through `str::parse` here
//!
//! `Node::Number` holds the token exactly as it was written, and the double is
//! taken from it with `str::parse::<f64>`, which is correctly rounded. Routing
//! the token through a JSON library instead would put a second parser in the
//! path: `serde_json` reads `333333333.33333329` -- the number in the RFC's own
//! reference vectors -- one unit in the last place low unless its
//! `float_roundtrip` feature is on. The delegate does turn that feature on, so
//! both readings agree today (measured 2026-09-19: `pipe("333333333.33333329")`
//! returns `333333333.3333333`, and `str::parse` gives bits `0x41b3de4355555555`).
//! Parsing the token here does not depend on that staying true.

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

use crate::parse::Node;

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Str(s) => serializer.serialize_str(s),
            Self::Number(token) => {
                // Admission has already refused every token with no finite
                // double, so a token reaching here parses. `unwrap_or(f64::NAN)`
                // is not a fallback that could assert something false: the
                // delegate refuses a non-finite double, so a token that somehow
                // arrived unchecked becomes a serialization error rather than
                // silently canonicalizing as something else.
                serializer.serialize_f64(token.parse::<f64>().unwrap_or(f64::NAN))
            }
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(members) => {
                // Emitted as a map, so the delegate applies RFC 8785 section
                // 3.2.3 member ordering -- UTF-16 code-unit order, which is not
                // the UTF-8 byte order `str: Ord` gives once a name leaves the
                // BMP. Ordering is the delegate's, deduplication never happens
                // here: a repeat was refused at the bytes, which is the whole
                // point of this crate. The delegate's own object assembly is a
                // `BTreeSet`, so a repeat reaching it would be dropped rather
                // than reported -- measured 2026-09-19, and it keeps the FIRST
                // member where its other two entry points keep the LAST.
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (name, value) in members {
                    map.serialize_entry(name, value)?;
                }
                map.end()
            }
        }
    }
}
