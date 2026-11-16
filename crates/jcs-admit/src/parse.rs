//! A JSON parser that works on raw bytes, because the faults that matter are
//! unobservable one layer later.
//!
//! An off-the-shelf decoder answers a different question than a canonicalizer
//! asks. It keeps the last of a repeated member, so a split view collapses into
//! a single reading before anything can refuse it; and a decoder that
//! substitutes U+FFFD for an unpaired surrogate leaves three distinct wire
//! strings canonicalizing to identical bytes. Neither is recoverable from the
//! decoded value, so both are refused here, on the bytes.

use crate::number;
use crate::{Error, Options};
use std::collections::HashSet;

/// One parsed JSON value.
///
/// Objects keep their members in a `Vec` rather than a map: order is what the
/// duplicate check reads, and collapsing to a map would answer the question by
/// discarding it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node {
    Null,
    Bool(bool),
    /// The number token exactly as written, serialized on the way out.
    Number(String),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

/// A cursor over the raw document.
pub(crate) struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    opts: &'a Options,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(bytes: &'a [u8], opts: &'a Options) -> Self {
        Self { bytes, at: 0, opts }
    }

    /// Parse exactly one JSON value and require the input to end there.
    pub(crate) fn document(&mut self) -> Result<Node, Error> {
        let node = self.value(0)?;
        self.skip_ws();
        if self.at != self.bytes.len() {
            return Err(Error::TrailingContent { offset: self.at });
        }
        Ok(node)
    }

    fn skip_ws(&mut self) {
        while let Some(&c) = self.bytes.get(self.at) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn syntax(&self, reason: &'static str) -> Error {
        Error::Syntax {
            offset: self.at,
            reason,
        }
    }

    fn refuse_string(&self, offset: usize, reason: &'static str) -> Error {
        Error::StringNotScalar { offset, reason }
    }

    /// Charge one nesting level for a container that is about to open.
    ///
    /// `depth` is the number of already-open containers, so the container about
    /// to open sits at level `depth + 1` and the cap is crossed when
    /// `depth >= limit`. Charging per open container rather than per parsed
    /// child is what keeps an *empty* container from slipping one level past the
    /// bound.
    fn enter(&self, depth: usize) -> Result<(), Error> {
        if depth >= self.opts.depth_limit() {
            return Err(Error::TooDeep {
                limit: self.opts.depth_limit(),
                offset: self.at,
            });
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Node, Error> {
        self.skip_ws();
        let Some(c) = self.peek() else {
            return Err(self.syntax("expected a JSON value, found end of input"));
        };
        match c {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Node::Str(self.string()?)),
            b't' => self.literal(b"true", Node::Bool(true)),
            b'f' => self.literal(b"false", Node::Bool(false)),
            b'n' => self.literal(b"null", Node::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.syntax("expected a JSON value")),
        }
    }

    fn literal(&mut self, word: &[u8], node: Node) -> Result<Node, Error> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(node)
        } else {
            Err(self.syntax("expected one of null, true, false"))
        }
    }

    fn array(&mut self, depth: usize) -> Result<Node, Error> {
        self.enter(depth)?;
        self.at += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Node::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Node::Array(items));
                }
                _ => return Err(self.syntax("expected ',' or ']' in array")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Node, Error> {
        self.enter(depth)?;
        self.at += 1;
        let mut members: Vec<(String, Node)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Node::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.syntax("object member name must be a string"));
            }
            let name_at = self.at;
            let name = self.string()?;
            // The comparison is on the DECODED name. Two spellings of one name
            // -- "a" and "\u0061", or a surrogate pair in either hex case --
            // are one member, and a raw-byte comparison would emit an object
            // carrying it twice.
            if !seen.insert(name.clone()) {
                return Err(Error::DuplicateMember {
                    name,
                    offset: name_at,
                });
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.syntax("expected ':' after an object member name"));
            }
            self.at += 1;
            let value = self.value(depth + 1)?;
            members.push((name, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Node::Object(members));
                }
                _ => return Err(self.syntax("expected ',' or '}' in object")),
            }
        }
    }

    /// Read one string literal, validating its bytes as it goes.
    fn string(&mut self) -> Result<String, Error> {
        let opened_at = self.at;
        self.at += 1;
        let mut out = String::new();
        loop {
            let run_start = self.at;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.at += 1;
            }
            if run_start != self.at {
                // A run stops only at '"', '\\' or a C0 byte, all of them
                // ASCII, and no UTF-8 continuation byte is ASCII -- so a run is
                // always whole-character aligned unless the bytes themselves are
                // ill-formed, which is exactly what `from_utf8` reports. It
                // rejects an overlong form and a surrogate encoded directly in
                // UTF-8 (CESU-8) along with a truncated sequence.
                // The offset is the first byte of the ill-formed sequence, not
                // the start of the run, so every refusal in this variant names
                // the byte it refused.
                //
                // The first fault in reading order is the one reported, as it is
                // across runs and on the Go rail: a noncharacter in the
                // well-formed prefix comes before ill-formed bytes after it, so
                // the prefix is searched before the UTF-8 fault is returned.
                let run = &self.bytes[run_start..self.at];
                let (chunk, ill_formed_at) = match core::str::from_utf8(run) {
                    Ok(chunk) => (chunk, None),
                    Err(e) => {
                        let valid = e.valid_up_to();
                        let prefix = core::str::from_utf8(&run[..valid])
                            .map_err(|_| self.refuse_string(run_start, "invalid UTF-8"))?;
                        (prefix, Some(run_start + valid))
                    }
                };
                if self.opts.wants_noncharacter_check() {
                    if let Some((at, _)) = chunk
                        .char_indices()
                        .find(|&(_, c)| is_noncharacter(c as u32))
                    {
                        return Err(self.refuse_string(run_start + at, NONCHARACTER));
                    }
                }
                if let Some(at) = ill_formed_at {
                    return Err(self.refuse_string(at, "invalid UTF-8"));
                }
                out.push_str(chunk);
            }
            match self.peek() {
                None => return Err(self.refuse_string(opened_at, "unterminated string literal")),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(c) if c < 0x20 => {
                    return Err(self.refuse_string(self.at, "raw control character in string"))
                }
                Some(_) => self.escape(&mut out)?,
            }
        }
    }

    /// Read one escape sequence. A `\u` escape naming a high surrogate consumes
    /// the low-surrogate escape that must follow, so the pair is validated as
    /// one unit and a lone half of either kind is refused.
    fn escape(&mut self, out: &mut String) -> Result<(), Error> {
        let start = self.at;
        self.at += 1;
        let Some(kind) = self.peek() else {
            return Err(self.refuse_string(start, "unterminated escape sequence"));
        };
        self.at += 1;
        let simple = match kind {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\u{a}'),
            b'r' => Some('\u{d}'),
            b't' => Some('\u{9}'),
            b'u' => None,
            _ => return Err(self.syntax("unknown escape sequence")),
        };
        if let Some(c) = simple {
            out.push(c);
            return Ok(());
        }
        let unit = self.hex4(start)?;
        let code = match unit {
            0xD800..=0xDBFF => {
                if self.peek() != Some(b'\\') || self.bytes.get(self.at + 1) != Some(&b'u') {
                    return Err(self.refuse_string(start, "unpaired high surrogate escape"));
                }
                self.at += 2;
                let low = self.hex4(start)?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.refuse_string(
                        start,
                        "high surrogate escape not followed by a low surrogate escape",
                    ));
                }
                0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => {
                return Err(self.refuse_string(start, "unpaired low surrogate escape"))
            }
            other => other,
        };
        if self.opts.wants_noncharacter_check() && is_noncharacter(code) {
            return Err(self.refuse_string(start, NONCHARACTER));
        }
        let ch = char::from_u32(code).ok_or_else(|| {
            self.refuse_string(start, "escape does not name a Unicode scalar value")
        })?;
        out.push(ch);
        Ok(())
    }

    fn hex4(&mut self, start: usize) -> Result<u32, Error> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.refuse_string(start, "truncated \\u escape"))?;
        let mut value = 0_u32;
        for &d in digits {
            let nibble = match d {
                b'0'..=b'9' => u32::from(d - b'0'),
                b'a'..=b'f' => u32::from(d - b'a' + 10),
                b'A'..=b'F' => u32::from(d - b'A' + 10),
                _ => return Err(self.refuse_string(start, "malformed \\u escape")),
            };
            value = value << 4 | nibble;
        }
        self.at += 4;
        Ok(value)
    }

    /// Read one number token, keeping its bytes verbatim.
    fn number(&mut self) -> Result<Node, Error> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.syntax("expected a digit in a number")),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.syntax("expected a digit after the decimal point"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.syntax("expected a digit in the exponent"));
            }
            self.digits();
        }
        let token = core::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| self.syntax("malformed number token"))?
            .to_owned();
        number::check(&token, self.opts)?;
        Ok(Node::Number(token))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
    }
}

/// The refusal reason for a Unicode noncharacter under the I-JSON profile.
///
/// A noncharacter is a Unicode scalar value, so the reason says what it is
/// rather than borrowing the wording of the surrogate and UTF-8 faults that
/// share its error variant.
const NONCHARACTER: &str = "Unicode noncharacter, a scalar value the I-JSON profile refuses";

/// Whether `code` is a Unicode noncharacter: U+FDD0..U+FDEF, or U+nFFFE and
/// U+nFFFF in any of the 17 planes.
///
/// RFC 7493 section 2.1 forbids these in the same sentence as surrogates. They
/// ARE valid scalar values, so nothing substitutes for them and every
/// implementation decodes them identically; the refusal exists so a verifier
/// reading the RFC 7493 label cannot refuse a document another accepts.
pub(crate) fn is_noncharacter(code: u32) -> bool {
    code & 0xFFFE == 0xFFFE || (0xFDD0..=0xFDEF).contains(&code)
}
