package corpusreaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// pythonCompactJSON reproduces, byte for byte, what
// json.dumps(value, sort_keys=True, separators=(",", ":")) writes in CPython.
//
// It exists because two corpora name a member by the digest of exactly those
// bytes, so a Go re-derivation that differs anywhere -- in key order, in the
// escaping of a non-ASCII character, in the spelling of a number -- reports
// every member of those corpora as corrupt while the corpus is intact. The
// three places CPython differs from Go's encoder are all here: sort_keys
// compares Python strings, which is code-point order; ensure_ascii defaults to
// true, so every character above U+007F is escaped rather than emitted; and Go
// additionally escapes <, > and & by default, which CPython does not.
//
// A float refuses rather than guessing: CPython spells one with repr() and Go
// with strconv, the two disagree on several values, and no corpus in this
// repository puts a float inside a digested payload. A guess here would be a
// silent wrong digest, which is the exact defect this function exists to avoid.
func pythonCompactJSON(value any) ([]byte, error) {
	return pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: true})
}

// pyEncodeOpts selects between the two spellings this repository's corpora use.
// EnsureASCII is json.dumps's own default and escapes every character above
// U+007F; UTF16Order sorts member names by UTF-16 code unit, which is what
// RFC 8785 requires and what CPython's sort_keys does NOT do. The two orders
// agree on every BMP-only member name and part on a supplementary-plane one,
// which is the whole subject of one corpus's ok-013 / bad-116 pair.
type pyEncodeOpts struct {
	EnsureASCII bool
	UTF16Order  bool
}

func pythonCompactJSONOpts(value any, opts pyEncodeOpts) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodePythonOpts(&buf, value, opts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonNumberIsZero reports whether CPython reads a JSON number token as zero,
// which is what a Python reader's truth test of the parsed value asks. An
// integer token is read exactly, so -0 is zero; any other token is read as the
// double CPython parses it into, so 0.0, -0.0 and a token too small for a
// double are zero, and a token too large for one is infinity, which is not.
// Comparing the token's text with "0" read -0 and 0.0 as true where every
// Python reader reads them as false.
func jsonNumberIsZero(n json.Number) bool {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		i, ok := new(big.Int).SetString(s, 10)
		return ok && i.Sign() == 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return false
	}
	return f == 0
}

// decodeJSONNumbers parses raw JSON with numbers kept as json.Number, so a
// re-encoding can tell an integer from a float instead of routing both through
// float64 and printing 1 as 1.0.
//
// It refuses, before any field of the value is read, what the Python readers'
// strictjson refuses: bytes that are not UTF-8, a string or member name holding
// a lone surrogate escape (encoding/json folds each to U+FFFD, so two distinct
// names would read as one), a repeated member, and a number literal that
// overflows a double (UseNumber keeps the text and never converts it, so
// encoding/json's own refusal of one never fires).
func decodeJSONNumbers(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("corpora: the document is not valid UTF-8")
	}
	if err := refuseLoneSurrogates(raw); err != nil {
		return nil, err
	}
	if err := refuseRepeatedMembers(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if err := refuseOverflowingNumbers(value); err != nil {
		return nil, err
	}
	return value, nil
}

// refuseLoneSurrogates scans the string tokens of raw JSON for a \uD800-\uDFFF
// escape that is not half of a valid high-then-low pair. A backslash pair such
// as \\ud800 is a literal backslash followed by text, never an escape.
func refuseLoneSurrogates(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 < len(raw) && raw[i+1] == 'u' {
				unit, ok := hexUnit(raw, i+2)
				switch {
				case ok && unit >= 0xDC00 && unit <= 0xDFFF:
					return errLoneSurrogate
				case ok && unit >= 0xD800 && unit <= 0xDBFF:
					low, paired := uint16(0), false
					if i+11 < len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
						low, paired = hexUnit(raw, i+8)
					}
					if !paired || low < 0xDC00 || low > 0xDFFF {
						return errLoneSurrogate
					}
					i += 11
					continue
				}
			}
			i++ // the escaped character is never a closing quote
		}
	}
	return nil
}

var errLoneSurrogate = errors.New("corpora: a string holds a lone surrogate escape")

func hexUnit(raw []byte, at int) (uint16, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[at:at+4]), 16, 16)
	return uint16(n), err == nil
}

// refuseOverflowingNumbers walks a decoded value and refuses a float-shaped
// number that does not fit a double. Underflow to zero is accepted, as Python's
// float() accepts it; an integer literal of any size stays exact.
func refuseOverflowingNumbers(value any) error {
	switch v := value.(type) {
	case json.Number:
		if !strings.ContainsAny(v.String(), ".eE") {
			return nil
		}
		f, _ := strconv.ParseFloat(v.String(), 64)
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Errorf("corpora: number %s overflows a double", v.String())
		}
	case []any:
		for _, item := range v {
			if err := refuseOverflowingNumbers(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range v {
			if err := refuseOverflowingNumbers(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func encodePythonOpts(buf *bytes.Buffer, value any, opts pyEncodeOpts) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writePythonString(buf, v, opts.EnsureASCII)
	case json.Number:
		s := v.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("corpora: %s is a JSON float, and this encoder refuses one "+
				"rather than guess whether CPython's repr and Go's strconv agree on it", s)
		}
		// CPython reads an integer token into an int and writes that int back,
		// so the bytes are the integer's value in decimal, not the token as
		// written. The two differ on one valid JSON integer token, -0, which
		// CPython reads as 0 and writes as 0; every other integer has exactly
		// one spelling in the JSON grammar (no leading zero, no plus sign).
		// Copying the token wrote -0 where the Python readers write 0, so two
		// digests over one value differed by which reader computed them.
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("corpora: %s is not a JSON integer", s)
		}
		buf.WriteString(n.String())
	case float64:
		return fmt.Errorf("corpora: a float reached the CPython-compatible encoder; "+
			"decode with json.Number so integers stay integers (got %v)", v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodePythonOpts(buf, item, opts); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// CPython's sort_keys compares str, which compares code points. Go's
		// string comparison is bytewise over UTF-8, and the two orders are the
		// same for every valid UTF-8 string, so this is that comparison.
		if opts.UTF16Order {
			sort.SliceStable(keys, func(a, b int) bool { return utf16Less(keys[a], keys[b]) })
		} else {
			sort.Strings(keys)
		}
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writePythonString(buf, k, opts.EnsureASCII)
			buf.WriteByte(':')
			if err := encodePythonOpts(buf, v[k], opts); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("corpora: %T has no CPython json.dumps spelling here", value)
	}
	return nil
}

// writePythonString is CPython's py_encode_basestring_ascii: the six short
// escapes, \uXXXX for every other control character, and \uXXXX (a surrogate
// pair above the BMP) for everything above U+007F.
func writePythonString(buf *bytes.Buffer, s string, ensureASCII bool) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(buf, `\u%04x`, r)
			case r < 0x7f:
				buf.WriteRune(r)
			case !ensureASCII:
				buf.WriteRune(r)
			case r <= 0xffff:
				// A byte sequence that is not valid UTF-8 arrives here as
				// U+FFFD, which is what CPython's decoder would also have
				// produced for it. Nothing is invented: the caller sees a
				// digest that fails to match rather than one that silently does.
				fmt.Fprintf(buf, `\u%04x`, r)
			default:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16Less compares two member names by UTF-16 code unit, which is the order
// RFC 8785 Section 3.2.3 requires and the order CPython's sort_keys does not
// produce. It is restated here rather than reached for in aee/ because that
// package exports no comparator, and the two corpora that need this order need
// it against CPython's other spelling of the same document.
func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}
