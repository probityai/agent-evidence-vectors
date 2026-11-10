//! Helpers every family reader shares.
//!
//! - [`Verdict`]: the `(decision, reason)` a reader derives.
//! - [`load_manifest`] and [`read_record`]: read a corpus directory.
//! - [`parse_record`]: parse record.json bytes, refusing duplicate members.
//! - [`canonical_bytes`], [`digest`], [`sha256_hex`]: RFC 8785 bytes and the
//!   `sha256:`-prefixed digests the records carry.
//! - [`ed25519_verify`]: strict Ed25519 verification through the `dsse` crate.
//! - [`b64_decode_strict`]: base64 decoding as Python's `b64decode(validate=True)`.
//! - [`parse_instant_z`] and [`parse_rfc3339_micros`]: timestamps as the Python
//!   readers accept them.

use std::fmt;
use std::fs;
use std::path::Path;

use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The decision and reason a reader derives from one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// `allow`, `deny`, or `unimplemented` for a family not ported yet.
    pub decision: String,
    /// The reason code the corpus names, for example `authorized_use`.
    pub reason: String,
}

impl Verdict {
    /// An `allow` verdict with the given reason.
    #[must_use]
    pub fn allow(reason: &str) -> Self {
        Self {
            decision: "allow".to_owned(),
            reason: reason.to_owned(),
        }
    }

    /// A `deny` verdict with the given reason.
    #[must_use]
    pub fn deny(reason: &str) -> Self {
        Self {
            decision: "deny".to_owned(),
            reason: reason.to_owned(),
        }
    }

    /// The verdict of a family whose reader is not written yet. It never
    /// equals a manifest's expected answer, so an agreement check fails on it.
    #[must_use]
    pub fn unimplemented() -> Self {
        Self {
            decision: "unimplemented".to_owned(),
            reason: "reader_not_ported".to_owned(),
        }
    }
}

/// A corpus, manifest or record that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderError(String);

impl ReaderError {
    /// An error carrying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReaderError {}

/// One manifest row: the case identifier and its directory under the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorEntry {
    /// The manifest `id`.
    pub id: String,
    /// The manifest `path`, relative to the corpus directory.
    pub path: String,
}

/// The parts of MANIFEST.json a reader needs. The manifest's `expected`
/// answers are not loaded: a verdict is derived from record.json alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The `suite` member, for example `grant-use/v1`.
    pub suite: String,
    /// Every vector, in manifest order.
    pub vectors: Vec<VectorEntry>,
}

/// Read `MANIFEST.json` from a corpus directory.
///
/// # Errors
///
/// Returns [`ReaderError`] when the file is missing, is not JSON, or lacks a
/// string `suite` or a list of vectors each carrying a string `id` and `path`.
pub fn load_manifest(dir: &Path) -> Result<Manifest, ReaderError> {
    let path = dir.join("MANIFEST.json");
    let bytes = fs::read(&path)
        .map_err(|error| ReaderError::new(format!("cannot read {}: {error}", path.display())))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ReaderError::new(format!("{} does not parse: {error}", path.display())))?;
    let suite = value
        .get("suite")
        .and_then(Value::as_str)
        .ok_or_else(|| ReaderError::new(format!("{} has no string suite", path.display())))?
        .to_owned();
    let rows = value
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| ReaderError::new(format!("{} has no vectors list", path.display())))?;
    let mut vectors = Vec::with_capacity(rows.len());
    for row in rows {
        let field = |name: &str| row.get(name).and_then(Value::as_str).map(str::to_owned);
        let (Some(id), Some(path)) = (field("id"), field("path")) else {
            return Err(ReaderError::new(
                "a manifest vector lacks a string id or path",
            ));
        };
        vectors.push(VectorEntry { id, path });
    }
    Ok(Manifest { suite, vectors })
}

/// Parse record.json bytes into a value.
///
/// The bytes pass `jcs_admit::admit` first, which refuses a repeated object
/// member, a string that is not a sequence of Unicode scalar values, nesting
/// past the depth cap and a number with no finite double. A reader therefore
/// never sees a record whose meaning depends on which duplicate a parser kept.
///
/// # Errors
///
/// Returns [`ReaderError`] when admission or parsing fails.
pub fn parse_record(bytes: &[u8]) -> Result<Value, ReaderError> {
    jcs_admit::admit(bytes)
        .map_err(|error| ReaderError::new(format!("record.json is not admissible: {error}")))?;
    serde_json::from_slice(bytes)
        .map_err(|error| ReaderError::new(format!("record.json does not parse: {error}")))
}

/// Read and parse `record.json` in a case directory, returning the value and
/// the exact bytes.
///
/// # Errors
///
/// Returns [`ReaderError`] when the file cannot be read or [`parse_record`]
/// refuses it.
pub fn read_record(case_dir: &Path) -> Result<(Value, Vec<u8>), ReaderError> {
    let path = case_dir.join("record.json");
    let bytes = fs::read(&path)
        .map_err(|error| ReaderError::new(format!("cannot read {}: {error}", path.display())))?;
    let value = parse_record(&bytes)
        .map_err(|error| ReaderError::new(format!("{}: {error}", path.display())))?;
    Ok((value, bytes))
}

/// Lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// RFC 8785 canonical bytes of a value, through `jcs_admit`.
///
/// # Errors
///
/// Returns [`ReaderError`] when the value cannot be serialized or admitted.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, ReaderError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ReaderError::new(format!("cannot serialize value: {error}")))?;
    jcs_admit::admit(&bytes)
        .map_err(|error| ReaderError::new(format!("value is not canonicalizable: {error}")))
}

/// `sha256:` plus the hex SHA-256 of the value's canonical bytes. This is the
/// digest the Python readers' `digest(value)` returns.
///
/// # Errors
///
/// As [`canonical_bytes`].
pub fn digest(value: &Value) -> Result<String, ReaderError> {
    Ok(format!("sha256:{}", sha256_hex(&canonical_bytes(value)?)))
}

/// Whether `signature` is a valid Ed25519 signature of `message` under the
/// 32-byte `public_key`. Verification is strict: small-order keys and
/// non-canonical signature scalars are refused. A malformed key is `false`.
#[must_use]
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use dsse::Verifier;
    dsse::Ed25519Verifier::from_bytes(public_key)
        .is_ok_and(|verifier| verifier.verify(message, signature))
}

/// Decode standard-alphabet base64 as Python's `base64.b64decode(s,
/// validate=True)` does: characters outside the alphabet are refused, padding
/// must be exactly right, and non-zero trailing bits are accepted.
///
/// Returns `None` when Python would raise.
#[must_use]
pub fn b64_decode_strict(text: &str) -> Option<Vec<u8>> {
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    ENGINE.decode(text).ok()
}

fn digits(bytes: &[u8], start: usize, count: usize) -> Option<i64> {
    let slice = bytes.get(start..start.checked_add(count)?)?;
    slice.iter().try_fold(0_i64, |acc, byte| {
        byte.is_ascii_digit()
            .then(|| acc * 10 + i64::from(byte - b'0'))
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parse the one spelling the strict contracts take, `YYYY-MM-DDTHH:MM:SSZ`
/// (attenuated-delegation, grant-use), into seconds since the Unix epoch.
///
/// Mirrors the Python `_INSTANT` pattern followed by a datetime parse: the
/// shape is exact, and the date and time must exist (month 1 to 12, a real day,
/// hour under 24, minute and second under 60).
#[must_use]
pub fn parse_instant_z(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 || bytes.get(19) != Some(&b'Z') {
        return None;
    }
    parse_rfc3339_micros(text).map(|micros| micros / 1_000_000)
}

/// Parse an RFC 3339 timestamp, `YYYY-MM-DDTHH:MM:SS[.f{1,6}](Z|+HH:MM|-HH:MM)`,
/// into microseconds since the Unix epoch (UTC).
///
/// This is the subset of Python's `datetime.fromisoformat` that appears in the
/// v2 corpora: the `T` separator, an optional fraction of up to six digits, and
/// either `Z` or a numeric offset. Everything else returns `None`; a family
/// whose Python reader accepts a wider spelling extends this function against
/// the cases that need it.
#[must_use]
pub fn parse_rfc3339_micros(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let year = digits(bytes, 0, 4)?;
    if year < 1 {
        return None;
    }
    let month = digits(bytes, 5, 2)?;
    let day = digits(bytes, 8, 2)?;
    let hour = digits(bytes, 11, 2)?;
    let minute = digits(bytes, 14, 2)?;
    let second = digits(bytes, 17, 2)?;
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|&(at, want)| bytes.get(at) != Some(&want))
    {
        return None;
    }
    if !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut at = 19;
    let mut micros = 0_i64;
    if bytes.get(at) == Some(&b'.') {
        let width = bytes
            .get(at + 1..)?
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if !(1..=6).contains(&width) {
            return None;
        }
        let fraction = digits(bytes, at + 1, width)?;
        micros = fraction * 10_i64.pow(u32::try_from(6 - width).ok()?);
        at += 1 + width;
    }
    let offset_seconds = match bytes.get(at..)? {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), ..] if bytes.len() == at + 6 && bytes.get(at + 3) == Some(&b':') => {
            let (offset_hour, offset_minute) =
                (digits(bytes, at + 1, 2)?, digits(bytes, at + 4, 2)?);
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let magnitude = offset_hour * 3600 + offset_minute * 60;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    let local = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some((local - offset_seconds) * 1_000_000 + micros)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_bytes_matches_rfc8785_section_3_2_4() {
        let sample = br#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/","literals":[null,true,false]}"#;
        let value = parse_record(sample).unwrap();
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        assert_eq!(canonical_bytes(&value).unwrap(), expected.as_bytes());
    }

    #[test]
    fn canonical_bytes_sorts_members_and_digest_prefixes() {
        let value = parse_record(br#"{"b":1,"a":[true,"x"]}"#).unwrap();
        assert_eq!(
            canonical_bytes(&value).unwrap(),
            br#"{"a":[true,"x"],"b":1}"#
        );
        assert_eq!(
            digest(&value).unwrap(),
            format!("sha256:{}", sha256_hex(br#"{"a":[true,"x"],"b":1}"#))
        );
    }

    #[test]
    fn parse_record_refuses_duplicate_members() {
        assert!(parse_record(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_record(br#"{"a":{"b":1,"b":1}}"#).is_err());
        assert!(parse_record(b"{").is_err());
    }

    #[test]
    fn instants_parse_to_epoch_seconds() {
        assert_eq!(parse_instant_z("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_instant_z("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_instant_z("2024-02-29T23:59:59Z"), Some(1_709_251_199));
    }

    #[test]
    fn strict_instant_refuses_other_spellings() {
        for text in [
            "2026-02-30T00:00:00Z",
            "2026-11-09T24:00:00Z",
            "2026-11-09T00:60:00Z",
            "2026-11-09T00:00:60Z",
            "2026-13-09T00:00:00Z",
            "2026-11-09T00:00:00",
            "2026-11-09T00:00:00.5Z",
            "2026-11-09T00:00:00+00:00",
            "2026-11-09 00:00:00Z",
            "2026-11-09t00:00:00z",
            "",
        ] {
            assert_eq!(parse_instant_z(text), None, "{text}");
        }
        assert_eq!(parse_instant_z("2023-02-29T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_handles_fraction_and_offset() {
        assert_eq!(
            parse_rfc3339_micros("2000-03-01T01:00:00+01:00"),
            Some(951_868_800_000_000)
        );
        assert_eq!(
            parse_rfc3339_micros("2000-02-29T19:30:00-04:30"),
            Some(951_868_800_000_000)
        );
        assert_eq!(
            parse_rfc3339_micros("2000-03-01T00:00:00.25Z"),
            Some(951_868_800_250_000)
        );
        assert_eq!(parse_rfc3339_micros("2000-03-01T00:00:00.1234567Z"), None);
        assert_eq!(parse_rfc3339_micros("2000-03-01T00:00:00+0100"), None);
        assert_eq!(parse_rfc3339_micros("2000-03-01T00:00:00."), None);
    }

    #[test]
    fn base64_follows_python_validate() {
        assert_eq!(b64_decode_strict("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode_strict("aGVsbG9=").unwrap(), b"hello");
        assert!(b64_decode_strict("aGVsbG8").is_none());
        assert!(b64_decode_strict("aGVs bG8=").is_none());
        assert!(b64_decode_strict("aGVsbG8=\n").is_none());
        assert_eq!(b64_decode_strict("").unwrap(), b"");
    }

    #[test]
    fn ed25519_rfc8032_test_vector_1() {
        let public_key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(ed25519_verify(&public_key, b"", &signature));
        assert!(!ed25519_verify(&public_key, b"x", &signature));
        assert!(!ed25519_verify(&public_key[..31], b"", &signature));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }
}
