//! RFC 8785 (JSON Canonicalization Scheme) test vectors as embedded files, so a
//! Rust test can check a canonicalizer against them with no download and no
//! network.
//!
//! The files are byte copies of two corpora in
//! <https://github.com/probityai/agent-evidence-vectors>: `vectors-a2a-jcs-v01`
//! (one file per vector, listed with its SHA-256 in `MANIFEST.json`) and
//! `jcs-byte-vectors` (`cases.json`). Every function checks each file it reads
//! against the SHA-256 recorded for it when the crate was generated, the
//! manifest and `cases.json` included, and each a2a vector against its manifest
//! digest too, before it returns anything. A file that changed after generation
//! is an error, never a silently different test.
//!
//! ```
//! # fn canonicalize(input: &[u8]) -> Result<Vec<u8>, ()> { Err(()) }
//! for vector in jcsvectors::canonical()? {
//!     let got = canonicalize(&vector.input);
//!     // `got` must equal `vector.canonical` byte for byte.
//! #   let _ = got;
//! }
//! for vector in jcsvectors::reject()? {
//!     // `canonicalize(&vector.input)` must refuse the input.
//! #   let _ = vector;
//! }
//! # Ok::<(), jcsvectors::Error>(())
//! ```
//!
//! The same files ship as the Go module
//! `github.com/probityai/agent-evidence-vectors/jcsvectors`, so a Rust and a Go
//! implementation tested with the two packages are held to the same bytes.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};

mod files;

/// The corpus of one vector per file, with its manifest.
pub const A2A_CORPUS: &str = "vectors-a2a-jcs-v01";
/// The corpus of cases in one `cases.json` file.
pub const BYTE_CORPUS: &str = "jcs-byte-vectors";
/// The nesting depth the corpus admits. Input nested one level deeper must be
/// refused by an admission gate with this cap.
pub const DEPTH_CAP: usize = 128;
/// The [`Drift::source`] of a drift case whose presented bytes are what Go's
/// `encoding/json` prints for the value.
pub const SOURCE_GO: &str = "go-encoding-json";

/// Every a2a vector that tests RFC 8785 itself carries a clause with this
/// prefix. The others test the A2A Agent Card rule that removes the
/// `signatures` member before canonicalizing, which is not RFC 8785.
const RFC8785_CLAUSE: &str = "RFC8785-";
const BYTE_FORMAT: &str = "jcs-byte-vectors/v1";

/// One RFC 8785 test case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    /// The case's identifier in its corpus.
    pub id: String,
    /// The corpus the case comes from: [`A2A_CORPUS`] or [`BYTE_CORPUS`].
    pub corpus: &'static str,
    /// The RFC 8785 clause the case tests, such as `RFC8785-3.2.3`. Empty for
    /// `jcs-byte-vectors` cases, which do not name one.
    pub clause: String,
    /// The JSON text to canonicalize.
    pub input: Vec<u8>,
    /// The RFC 8785 output for `input`, or `None` for a case a canonicalizer
    /// must refuse.
    pub canonical: Option<Vec<u8>>,
}

/// Bytes a producer printed and presented as the canonical form of a value,
/// which RFC 8785 does not print that way. A check that `presented` is
/// canonical must answer no, and canonicalizing `input` must give `canonical`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    /// The case's identifier, such as `drift-html-less-than`.
    pub id: String,
    /// `html-escape`, `non-ascii-escape` or `number-format`.
    pub family: String,
    /// The printer the bytes come from, such as [`SOURCE_GO`].
    pub source: String,
    /// The JSON text of the value.
    pub input: Vec<u8>,
    /// The drifted output, which is not canonical.
    pub presented: Vec<u8>,
    /// The RFC 8785 output for the value.
    pub canonical: Vec<u8>,
}

/// Why the embedded vectors could not be read. Any of these means the crate's
/// own files are damaged, so a test that sees one must fail, not skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A file the corpus lists is not embedded.
    Missing(String),
    /// A file or a case's canonical bytes do not hash to the recorded SHA-256.
    Digest {
        /// The file or case that failed.
        name: String,
        /// The SHA-256 of the bytes read, in lowercase hex.
        got: String,
        /// The SHA-256 the corpus records.
        want: String,
    },
    /// A file is not the JSON its corpus declares.
    Malformed {
        /// The file or case that failed.
        name: String,
        /// What was wrong with it.
        reason: String,
    },
    /// The number of RFC 8785 vectors read differs from what the manifest
    /// declares.
    Count {
        /// The number read.
        got: usize,
        /// The number the manifest declares.
        want: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "{name}: not embedded in this crate"),
            Self::Digest { name, got, want } => {
                write!(f, "{name}: sha256 {got}, the corpus records {want}")
            }
            Self::Malformed { name, reason } => write!(f, "{name}: {reason}"),
            Self::Count { got, want } => write!(
                f,
                "{A2A_CORPUS}: read {got} RFC 8785 vectors, the manifest declares {want}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Every case whose input a canonicalizer must accept, with the exact bytes RFC
/// 8785 requires for it, noncharacters included: RFC 8785 prints a Unicode
/// noncharacter as its UTF-8 bytes, although an I-JSON profile refuses it.
pub fn canonical() -> Result<Vec<Vector>, Error> {
    Ok(load()?.0)
}

/// Every case whose input a canonicalizer must refuse: duplicate members (also
/// spelled with an escape, or nested), lone surrogates, invalid UTF-8, numbers
/// with no finite IEEE 754 value, trailing content, malformed JSON and other
/// input with no RFC 8785 form. Some inputs are not UTF-8, so compare bytes.
pub fn reject() -> Result<Vec<Vector>, Error> {
    Ok(load()?.1)
}

/// Every drift case, each checked against its SHA-256.
pub fn drifts() -> Result<Vec<Drift>, Error> {
    let cases = byte_cases()?;
    cases
        .drift_cases
        .into_iter()
        .map(|c| {
            let canonical = canonical_bytes(&c.id, &c.canonical_hex, &c.sha256)?;
            Ok(Drift {
                id: c.id,
                family: c.family,
                source: c.source,
                input: c.input.into_bytes(),
                presented: c.presented.into_bytes(),
                canonical,
            })
        })
        .collect()
}

/// The cases nested past [`DEPTH_CAP`], which an admission gate with that cap
/// must refuse. They are not RFC 8785 refusals, so [`reject`] does not carry
/// them. A case nested exactly [`DEPTH_CAP`] deep is in [`depth_admitted`].
pub fn too_deep() -> Result<Vec<Vector>, Error> {
    Ok(depth_cases()?.0)
}

/// The cases nested exactly [`DEPTH_CAP`] deep, which an admission gate with
/// that cap must accept and canonicalize to their canonical bytes.
pub fn depth_admitted() -> Result<Vec<Vector>, Error> {
    Ok(depth_cases()?.1)
}

/// The embedded files, as `(path, bytes)` pairs at the paths the corpora
/// publish them under: `vectors-a2a-jcs-v01/MANIFEST.json`,
/// `vectors-a2a-jcs-v01/<group>/<id>.json` and `jcs-byte-vectors/cases.json`.
pub fn files() -> impl Iterator<Item = (&'static str, &'static [u8])> {
    files::FILES.iter().map(|(path, _, bytes)| (*path, *bytes))
}

#[derive(Deserialize)]
struct Manifest {
    vectors: Vec<ManifestEntry>,
    targets: Targets,
}

#[derive(Deserialize)]
struct ManifestEntry {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Targets {
    rfc8785: Target,
}

#[derive(Deserialize)]
struct Target {
    vectors: usize,
}

#[derive(Deserialize)]
struct A2aVector {
    id: String,
    clause: String,
    disposition: String,
    #[serde(default)]
    input: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    input_raw: Option<String>,
    #[serde(default)]
    expected: Option<Expected>,
}

#[derive(Deserialize)]
struct Expected {
    #[serde(default)]
    canonical_utf8_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ByteCases {
    format: String,
    canonical_cases: Vec<CanonicalCase>,
    reject_cases: Vec<RejectCase>,
    drift_cases: Vec<DriftCase>,
    depth_cases: Vec<DepthCase>,
    refusal_cases: Vec<RefusalCase>,
    #[serde(default)]
    invalid_input_cases: Vec<RefusalCase>,
    #[serde(default)]
    noncharacter_cases: Vec<CanonicalCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalCase {
    id: String,
    input: String,
    canonical_hex: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectCase {
    id: String,
    input: String,
    #[serde(default)]
    jcs_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriftCase {
    id: String,
    family: String,
    source: String,
    input: String,
    presented: String,
    canonical_hex: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepthCase {
    id: String,
    input: String,
    expect: String,
    #[serde(default)]
    canonical_hex: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
}

/// Input that is not one valid RFC 8785 input at all, which no profile excuses
/// a canonicalizer for printing. `input_hex` carries input that is not UTF-8.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefusalCase {
    id: String,
    expect: String,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    input_hex: Option<String>,
}

type Split = (Vec<Vector>, Vec<Vector>);

fn load() -> Result<Split, Error> {
    let (mut accept, mut reject) = load_a2a()?;
    let (byte_accept, byte_reject) = load_bytes()?;
    accept.extend(byte_accept);
    reject.extend(byte_reject);
    Ok((accept, reject))
}

fn load_a2a() -> Result<Split, Error> {
    let manifest: Manifest = read_json(&format!("{A2A_CORPUS}/MANIFEST.json"))?;
    let (mut accept, mut reject) = (Vec::new(), Vec::new());
    for entry in &manifest.vectors {
        let name = format!("{A2A_CORPUS}/{}", entry.path);
        let raw = file(&name)?;
        check_digest(&name, raw, &entry.sha256)?;
        let vector: A2aVector = parse(&name, raw)?;
        if !vector.clause.starts_with(RFC8785_CLAUSE) {
            continue;
        }
        let parsed = a2a_vector(&name, vector)?;
        if parsed.canonical.is_some() {
            accept.push(parsed);
        } else {
            reject.push(parsed);
        }
    }
    let got = accept.len() + reject.len();
    if got != manifest.targets.rfc8785.vectors {
        return Err(Error::Count {
            got,
            want: manifest.targets.rfc8785.vectors,
        });
    }
    Ok((accept, reject))
}

fn a2a_vector(name: &str, v: A2aVector) -> Result<Vector, Error> {
    let malformed = |reason: &str| Error::Malformed {
        name: name.to_owned(),
        reason: format!("vector {}: {reason}", v.id),
    };
    let (input, canonical) = match v.disposition.as_str() {
        "MUST-ACCEPT" => {
            let input = v.input.as_ref().ok_or_else(|| malformed("no input"))?;
            let hex_text = v
                .expected
                .as_ref()
                .and_then(|e| e.canonical_utf8_hex.as_deref())
                .ok_or_else(|| malformed("no canonical bytes"))?;
            let canonical = decode_hex(hex_text).ok_or_else(|| malformed("no canonical bytes"))?;
            (input.get().as_bytes().to_vec(), Some(canonical))
        }
        "MUST-REJECT" => {
            let raw = v
                .input_raw
                .as_ref()
                .ok_or_else(|| malformed("no input_raw"))?;
            (raw.as_bytes().to_vec(), None)
        }
        other => return Err(malformed(&format!("unknown disposition {other:?}"))),
    };
    Ok(Vector {
        id: v.id,
        corpus: A2A_CORPUS,
        clause: v.clause,
        input,
        canonical,
    })
}

fn byte_cases() -> Result<ByteCases, Error> {
    let name = format!("{BYTE_CORPUS}/cases.json");
    let cases: ByteCases = read_json(&name)?;
    if cases.format != BYTE_FORMAT {
        return Err(Error::Malformed {
            name,
            reason: format!("unknown format {:?}", cases.format),
        });
    }
    Ok(cases)
}

fn load_bytes() -> Result<Split, Error> {
    let cases = byte_cases()?;
    let mut accept = Vec::new();
    // A noncharacter is a Unicode scalar value, so RFC 8785 prints it; only an
    // I-JSON profile refuses it, which this crate does not model.
    for c in cases
        .canonical_cases
        .into_iter()
        .chain(cases.noncharacter_cases)
    {
        let canonical = canonical_bytes(&c.id, &c.canonical_hex, &c.sha256)?;
        accept.push(byte_vector(c.id, c.input, Some(canonical)));
    }
    // A case with no jcsError is refused only by an application profile that
    // admits safe integers alone, not by RFC 8785, so it is left out.
    let mut reject: Vec<Vector> = cases
        .reject_cases
        .into_iter()
        .filter(|c| c.jcs_error.as_deref().is_some_and(|e| !e.is_empty()))
        .map(|c| byte_vector(c.id, c.input, None))
        .collect();
    for c in cases
        .refusal_cases
        .into_iter()
        .chain(cases.invalid_input_cases)
    {
        reject.push(refusal_vector(c)?);
    }
    Ok((accept, reject))
}

fn refusal_vector(c: RefusalCase) -> Result<Vector, Error> {
    let malformed = |reason: &str| Error::Malformed {
        name: format!("{BYTE_CORPUS} case {}", c.id),
        reason: reason.to_owned(),
    };
    if c.expect != "reject" {
        return Err(malformed(&format!(
            "a refusal case expects {:?}, not reject",
            c.expect
        )));
    }
    let input = match (&c.input, &c.input_hex) {
        (Some(text), None) => text.as_bytes().to_vec(),
        (None, Some(hex_text)) => {
            decode_hex(hex_text).ok_or_else(|| malformed("inputHex is not hex"))?
        }
        _ => return Err(malformed("needs exactly one of input and inputHex")),
    };
    Ok(Vector {
        id: c.id,
        corpus: BYTE_CORPUS,
        clause: String::new(),
        input,
        canonical: None,
    })
}

fn depth_cases() -> Result<Split, Error> {
    let cases = byte_cases()?;
    let (mut reject, mut accept) = (Vec::new(), Vec::new());
    for c in cases.depth_cases {
        match c.expect.as_str() {
            "reject" => {
                reject.push(byte_vector(c.id, c.input, None));
                continue;
            }
            "accept" => {}
            other => {
                return Err(Error::Malformed {
                    name: format!("{BYTE_CORPUS} case {}", c.id),
                    reason: format!("unknown expect {other:?}"),
                })
            }
        }
        let canonical = canonical_bytes(
            &c.id,
            c.canonical_hex.as_deref().unwrap_or_default(),
            c.sha256.as_deref().unwrap_or_default(),
        )?;
        accept.push(byte_vector(c.id, c.input, Some(canonical)));
    }
    Ok((reject, accept))
}

fn byte_vector(id: String, input: String, canonical: Option<Vec<u8>>) -> Vector {
    Vector {
        id,
        corpus: BYTE_CORPUS,
        clause: String::new(),
        input: input.into_bytes(),
        canonical,
    }
}

fn canonical_bytes(id: &str, hex_text: &str, sha256: &str) -> Result<Vec<u8>, Error> {
    let name = format!("{BYTE_CORPUS} case {id}");
    let canonical = decode_hex(hex_text)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| Error::Malformed {
            name: name.clone(),
            reason: "no canonical bytes".to_owned(),
        })?;
    check_digest(&name, &canonical, sha256)?;
    Ok(canonical)
}

fn file(name: &str) -> Result<&'static [u8], Error> {
    let (_, want, bytes) = files::FILES
        .iter()
        .find(|(path, _, _)| *path == name)
        .ok_or_else(|| Error::Missing(name.to_owned()))?;
    check_digest(name, bytes, want)?;
    Ok(*bytes)
}

fn read_json<T: DeserializeOwned>(name: &str) -> Result<T, Error> {
    parse(name, file(name)?)
}

fn parse<T: DeserializeOwned>(name: &str, raw: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(raw).map_err(|e| Error::Malformed {
        name: name.to_owned(),
        reason: e.to_string(),
    })
}

fn check_digest(name: &str, data: &[u8], want: &str) -> Result<(), Error> {
    let got = encode_hex(&Sha256::digest(data));
    if got == want {
        Ok(())
    } else {
        Err(Error::Digest {
            name: name.to_owned(),
            got,
            want: want.to_owned(),
        })
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let nibble = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{check_digest, decode_hex, encode_hex, refusal_vector, RefusalCase};

    fn refusal(expect: &str, input: Option<&str>, input_hex: Option<&str>) -> RefusalCase {
        RefusalCase {
            id: "r".to_owned(),
            expect: expect.to_owned(),
            input: input.map(str::to_owned),
            input_hex: input_hex.map(str::to_owned),
        }
    }

    #[test]
    fn refusal_case_shape_is_enforced() {
        assert!(refusal_vector(refusal("reject", Some("[1,]"), Some("00"))).is_err());
        assert!(refusal_vector(refusal("reject", None, None)).is_err());
        assert!(refusal_vector(refusal("accept", Some("[1,]"), None)).is_err());
        assert!(refusal_vector(refusal("reject", None, Some("zz"))).is_err());
        let v = refusal_vector(refusal("reject", None, Some("5b22ff225d")));
        assert_eq!(v.map(|v| v.input), Ok(vec![0x5b, 0x22, 0xff, 0x22, 0x5d]));
    }

    #[test]
    fn every_embedded_file_hashes_to_its_recorded_digest() {
        for (name, want, bytes) in super::files::FILES {
            assert!(check_digest(name, bytes, want).is_ok(), "{name}");
        }
    }

    #[test]
    fn digest_mismatch_is_refused() {
        assert!(check_digest("x", b"{}", &"0".repeat(64)).is_err());
        assert!(check_digest(
            "x",
            b"{}",
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        )
        .is_ok());
    }

    #[test]
    fn hex_round_trips_and_refuses_odd_or_non_hex() {
        assert_eq!(
            decode_hex(&encode_hex(&[0, 0xab, 0xff])),
            Some(vec![0, 0xab, 0xff])
        );
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }
}
