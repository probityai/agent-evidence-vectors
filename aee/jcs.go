package aee

// RFC 8785 (JCS) canonicalization and RFC 7493 (I-JSON) profile checks,
// implemented over the standard library only.
//
// Scope note: the conformance suite's serialization pin commits vector
// payloads with string, boolean, array, object, and I-JSON-safe integer
// values only. Integer serialization below is exact per RFC 8785. The
// non-integer (double) path implements the ES6 shortest-round-trip rules for
// the common range and is best-effort at the extreme exponent boundaries;
// any divergence there is a conservative payload-not-canonical, never a
// false accept of tampered bytes.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrDuplicateMember reports a JSON object with a repeated member name
// (rejected by RFC 7493).
var ErrDuplicateMember = errors.New("duplicate object member")

// ErrStringNotScalar reports a JSON string literal whose bytes do not denote a
// sequence of Unicode scalar values: an unpaired surrogate escape, a surrogate
// escape pair that is not high-then-low, a raw control character, or invalid
// UTF-8 (which includes an overlong form and a surrogate encoded directly in
// UTF-8). RFC 7493 (I-JSON) section 2.1 rejects all of these, and they are
// rejected here at the raw bytes, BEFORE any decode.
//
// The check exists because a decoder cannot report it after the fact. Go's
// encoding/json substitutes U+FFFD for every one of these faults while
// decoding (encoding/json/decode.go, unquoteBytes), so a downstream check
// reading the decoded Go string sees a legal BMP scalar and cannot recover
// what the bytes said. Two consequences follow, and both are unconstructible
// only if the fault is caught at the byte level:
//
//   - a false accept: "\ud800" inside an observationVocabulary entry decodes
//     to U+FFFD, which the BMP-only string profile accepts;
//   - a canonicalization collision: "\ud800", "\udc00", and a literal U+FFFD
//     are three distinct inputs that decode, and therefore canonicalize, to
//     identical bytes, so a sortedness or duplicate-member check reads two
//     distinct strings as one.
//
// The independent Rust rail rejects the same inputs at its parser, so this is
// also what keeps the rails byte-identical.
var ErrStringNotScalar = errors.New("JSON string is not a sequence of Unicode scalar values")

// ErrUnsafeInteger reports an integer with magnitude at or above 2^53
// (rejected by the predicate's I-JSON safe-integer profile, spec:req-wireprofile-toto-attestation-framework-plus-understanding@9b70dfbc01b9a3f6).
var ErrUnsafeInteger = errors.New("integer outside the I-JSON safe range")

// ErrNonIntegerNumber reports a JSON number with a fractional part. The
// specification pins a safe-integer profile (spec:req-wireprofile-toto-attestation-framework-plus-understanding@9b70dfbc01b9a3f6,req-fields-fields-divide-identity-whose-signature@80666d820c397ce5) and declares
// every numeric member it defines an integer, but states no rule against a
// fractional number in producer territory. The rails reject one anyway, so
// that cross-language float formatting can never split them (the Python rail
// rejects it identically as "non-integer number").
var ErrNonIntegerNumber = errors.New("non-integer number outside the integers-only profile")

const maxSafeInteger = int64(1) << 53 // exclusive bound: |i| must be < 2^53

// maxSafeIntBig is maxSafeInteger as a big.Int, for the exact integer-value
// magnitude comparison in checkSafeInteger.
var maxSafeIntBig = big.NewInt(maxSafeInteger)

// checkSafeInteger enforces the number profile the rails share for a JSON
// number token, in ANY notation: the safe-integer bound the specification pins
// (spec:req-wireprofile-toto-attestation-framework-plus-understanding@9b70dfbc01b9a3f6,req-fields-fields-divide-identity-whose-signature@80666d820c397ce5), tightened to integers only.
//   - a non-integer (1.5) is rejected: every numeric member the specification
//     defines is an integer, and rejecting non-integers keeps the two rails in
//     lockstep (the Python rail rejects all non-integers) without needing
//     cross-language float-format parity;
//   - an integer with magnitude at or above 2^53 is rejected, including one
//     written in exponent form (1e21) or with a decimal point (1.0e21) that a
//     notation-blind check would miss.
//
// Exact rational arithmetic is used deliberately so an exponent-notation
// integer such as 1e21 cannot slip past a float64 approximation of the bound --
// the divergence the two number paths otherwise hid, where "1e21" contains 'e'
// and was never range-checked. A safe integer written in exponent or
// decimal-point form (1e2, 100.0) passes here and canonicalizes to plain form.
func checkSafeInteger(s string) error {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		// Not parseable as a rational here; a json.Number is always valid JSON
		// number grammar, so this is unreachable for real input. Defer any
		// rejection to the surrounding parse rather than masking it.
		return nil
	}
	if !r.IsInt() {
		return fmt.Errorf("%w: %s", ErrNonIntegerNumber, s)
	}
	if new(big.Int).Abs(r.Num()).Cmp(maxSafeIntBig) >= 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeInteger, s)
	}
	return nil
}

// maxParseDepth bounds JSON nesting on untrusted input. It is set far below
// the native stack-overflow point (Go's own encoding/json uses 10000 only as
// a crash backstop): 128 matches the serde_json floor and is ~20x under any
// realistic attestation payload, so the counter trips with a normal error
// before the stack overflows. Without it a crafted deeply-nested corpus
// manifest or record payload crashes the verifier via uncatchable stack
// overflow, before any signature is checked.
const maxParseDepth = 128

// maxParseBytes bounds raw untrusted JSON size before parsing. A depth cap
// bounds the call stack; a size cap bounds the heap. Both are required (a
// depth limit alone leaves resource use proportional to input size).
const maxParseBytes = 20 << 20 // 20 MiB

// ErrInputTooDeep and ErrInputTooLarge report untrusted JSON exceeding the
// I-JSON resource bounds. Both are fail-closed rejections, never a crash.
var (
	ErrInputTooDeep  = errors.New("JSON nesting exceeds the maximum depth")
	ErrInputTooLarge = errors.New("JSON input exceeds the maximum size")
)

// jsonObject preserves member order for duplicate detection while allowing
// canonical (sorted) emission.
type jsonObject struct {
	keys   []string
	values map[string]any
}

// parseJSONValue decodes exactly one JSON value from raw, rejecting
// duplicate members, unsafe integers, strings that are not Unicode scalar
// sequences, and trailing content.
func parseJSONValue(raw []byte) (any, error) {
	if len(raw) > maxParseBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrInputTooLarge, len(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content after JSON value")
	}
	// String scalars are checked on the RAW bytes, after the decode has
	// established that raw is exactly one syntactically valid JSON value (so
	// every '"' the scan meets outside a literal opens one) and before any
	// caller reads a decoded string. The decoded values above are already
	// lossy where this check fails; only the bytes still carry the fault.
	if err := checkStringScalars(raw); err != nil {
		return nil, err
	}
	return v, nil
}

// checkStringScalars walks raw JSON bytes and applies checkStringLiteral to
// every string literal in the document, at any depth and in both member-name
// and value position. It requires raw to be syntactically valid JSON.
func checkStringScalars(raw []byte) error {
	for i := 0; i < len(raw); {
		if raw[i] != '"' {
			i++
			continue
		}
		n, err := checkStringLiteral(raw[i:])
		if err != nil {
			return err
		}
		i += n
	}
	return nil
}

// checkStringLiteral validates one JSON string literal beginning at b[0] ('"')
// and returns the number of bytes it spans, including both quotes. See
// ErrStringNotScalar for what it rejects.
func checkStringLiteral(b []byte) (int, error) {
	for i := 1; i < len(b); {
		switch c := b[i]; {
		case c == '"':
			return i + 1, nil
		case c == '\\':
			n, err := checkEscape(b[i:])
			if err != nil {
				return 0, err
			}
			i += n
		case c < 0x20:
			return 0, fmt.Errorf("%w: raw control character U+%04X in string", ErrStringNotScalar, c)
		case c < utf8.RuneSelf:
			i++
		default:
			// DecodeRune reports (RuneError, 1) for every ill-formed sequence,
			// including an overlong encoding and a surrogate encoded in UTF-8;
			// a genuine U+FFFD decodes with size 3 and is legal.
			r, size := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && size <= 1 {
				return 0, fmt.Errorf("%w: invalid UTF-8 at byte %d of string", ErrStringNotScalar, i)
			}
			if isNoncharacter(uint32(r)) { // #nosec G115 -- r is a decoded code point in [0, 0x10FFFF], never negative
				return 0, fmt.Errorf("%w: noncharacter U+%04X in string", ErrStringNotScalar, r)
			}
			i += size
		}
	}
	return 0, errors.New("unterminated string literal")
}

// checkEscape validates one escape sequence beginning at b[0] ('\\') and
// returns the number of bytes it spans. A \u escape naming a high surrogate
// spans the low-surrogate escape that MUST follow it, so the pair is validated
// and consumed as one unit and a lone surrogate of either half is rejected.
func checkEscape(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, errors.New("unterminated escape sequence")
	}
	if b[1] != 'u' {
		return 2, nil // \" \\ \/ \b \f \n \r \t: syntax already validated by the decode
	}
	hi, ok := hex4(b[2:])
	if !ok {
		return 0, fmt.Errorf("%w: malformed \\u escape", ErrStringNotScalar)
	}
	switch {
	case hi >= 0xD800 && hi < 0xDC00: // high surrogate: a low surrogate escape MUST follow
		const pair = 12 // \uXXXX\uXXXX
		if len(b) < pair || b[6] != '\\' || b[7] != 'u' {
			return 0, fmt.Errorf("%w: unpaired high surrogate \\u%04X", ErrStringNotScalar, hi)
		}
		lo, ok := hex4(b[8:])
		if !ok {
			return 0, fmt.Errorf("%w: malformed \\u escape after high surrogate \\u%04X", ErrStringNotScalar, hi)
		}
		if lo < 0xDC00 || lo >= 0xE000 {
			return 0, fmt.Errorf("%w: high surrogate \\u%04X followed by \\u%04X, which is not a low surrogate", ErrStringNotScalar, hi, lo)
		}
		if cp := uint32(0x10000) + (hi-0xD800)<<10 + (lo - 0xDC00); isNoncharacter(cp) {
			return 0, fmt.Errorf("%w: noncharacter U+%04X in string", ErrStringNotScalar, cp)
		}
		return pair, nil
	case hi >= 0xDC00 && hi < 0xE000:
		return 0, fmt.Errorf("%w: unpaired low surrogate \\u%04X", ErrStringNotScalar, hi)
	default:
		if isNoncharacter(hi) {
			return 0, fmt.Errorf("%w: noncharacter U+%04X in string", ErrStringNotScalar, hi)
		}
		return 6, nil
	}
}

// isNoncharacter reports whether r is a Unicode noncharacter: U+FDD0..U+FDEF, or
// U+nFFFE/U+nFFFF in any of the 17 planes. RFC 7493 section 2.1 forbids these in the
// same sentence as surrogates, so strict I-JSON rejects them wherever a string
// literal appears, at any depth and in both member-name and value position. They are
// valid Unicode scalar values, so nothing substitutes for them and every rail decodes
// identical bytes identically; the rejection exists so a from-spec verifier that reads
// the RFC 7493 label cannot reject a record another rail accepts.
func isNoncharacter(r uint32) bool {
	return r&0xFFFE == 0xFFFE || (r >= 0xFDD0 && r <= 0xFDEF)
}

// hex4 reads the four hex digits of a \u escape from the start of b.
func hex4(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v uint32
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint32(c-'a'+10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | uint32(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		// A container occupies its own nesting level, charged when it opens so
		// that an EMPTY container is counted too. depth is the number of enclosing
		// containers, so this container sits at open-container depth depth+1; reject
		// when depth+1 > maxParseDepth, i.e. depth >= maxParseDepth. Counting per
		// open container rather than per parsed child is what keeps this rail in
		// step with the bracket-counting rails: charging only on child recursion let
		// an empty-container leaf slip one level past the bound.
		if depth >= maxParseDepth {
			return nil, ErrInputTooDeep
		}
		switch t {
		case '{':
			obj := &jsonObject{values: map[string]any{}}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object member name is not a string")
				}
				if _, dup := obj.values[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateMember, key)
				}
				val, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, key)
				obj.values[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, err
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				val, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, err
			}
			if arr == nil {
				arr = []any{}
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
	case json.Number:
		if err := checkSafeNumber(t); err != nil {
			return nil, err
		}
		return t, nil
	default:
		return tok, nil // string, bool, nil
	}
}

func checkSafeNumber(n json.Number) error {
	return checkSafeInteger(string(n))
}

// Canonicalize parses raw (rejecting duplicate members and unsafe integers)
// and re-emits it in RFC 8785 canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := parseJSONValue(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckIJSON reports whether raw violates the I-JSON profile the predicate
// pins: duplicate members, integers outside the safe range, or a string that
// is not a sequence of Unicode scalar values. Other parse errors are returned
// as-is.
func CheckIJSON(raw []byte) error {
	_, err := parseJSONValue(raw)
	return err
}

func appendCanonical(buf *bytes.Buffer, v any, depth int) error {
	if depth > maxParseDepth {
		return ErrInputTooDeep
	}
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		appendJCSString(buf, t)
	case json.Number:
		s, err := es6Number(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, el, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case *jsonObject:
		keys := append([]string(nil), t.keys...)
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendJCSString(buf, k)
			buf.WriteByte(':')
			if err := appendCanonical(buf, t.values[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value type %T", v)
	}
	return nil
}

// appendJCSString emits s with RFC 8785 string serialization: the two-char
// escapes \" \\ \b \t \n \f \r, \u00XX for remaining control characters,
// and literal UTF-8 for everything else.
func appendJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// isBMPOnly reports whether every code point in s lies inside the Basic
// Multilingual Plane. The predicate's BMP-only string profile — the string
// half of the I-JSON safe-integer profile — restricts every sorted
// signed-surface string (object member names in covering record payloads,
// and the observationVocabulary labels/caught entries) to the BMP: within
// the BMP, UTF-16 code-unit order and Unicode code-point order coincide, so
// two conforming sort implementations cannot disagree on canonical form. A
// supplementary-plane string is rejected fail-closed, never re-ordered.
func isBMPOnly(s string) bool {
	for _, r := range s {
		if r > 0xFFFF {
			return false
		}
	}
	return true
}

// hasSupplementaryMemberName walks a parsed JSON value and reports whether
// any object member name, at any depth, carries a code point outside the
// BMP. Member values are unconstrained: only the sorted member names
// participate in RFC 8785 member ordering, so only they can split a UTF-16
// verifier from a code-point verifier.
func hasSupplementaryMemberName(v any) bool {
	switch t := v.(type) {
	case *jsonObject:
		for _, k := range t.keys {
			if !isBMPOnly(k) {
				return true
			}
		}
		for _, val := range t.values {
			if hasSupplementaryMemberName(val) {
				return true
			}
		}
	case []any:
		for _, el := range t {
			if hasSupplementaryMemberName(el) {
				return true
			}
		}
	}
	return false
}

// utf16Less orders member names by their UTF-16 code units, as RFC 8785
// section 3.2.3 requires.
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// es6Number serializes a number per RFC 8785 (ES6 Number::toString).
func es6Number(n json.Number) (string, error) {
	s := string(n)
	// Independently enforce the safe-integer profile so canonicalization can
	// never emit an unsafe integer even if reached without a prior CheckIJSON
	// pass (the same shared check the parse path runs, no forked logic).
	if err := checkSafeInteger(s); err != nil {
		return "", err
	}
	if !strings.ContainsAny(s, ".eE") {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrUnsafeInteger, s)
		}
		if i == 0 {
			return "0", nil // covers -0
		}
		return strconv.FormatInt(i, 10), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", err
	}
	return formatES6Float(f)
}

func formatES6Float(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("non-finite number")
	}
	if f == 0 {
		return "0", nil // covers -0
	}
	abs := math.Abs(f)
	if abs < 1e21 && abs >= 1e-6 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	// ES6 exponent form: shortest mantissa, "e+"/"e-", no zero-padded exponent.
	out := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exp, _ := strings.Cut(out, "e")
	sign := "+"
	if exp[0] == '+' || exp[0] == '-' {
		sign = string(exp[0])
		exp = exp[1:]
	}
	exp = strings.TrimLeft(exp, "0")
	if exp == "" {
		exp = "0"
	}
	return mantissa + "e" + sign + exp, nil
}
