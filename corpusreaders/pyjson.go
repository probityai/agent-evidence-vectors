package corpora

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
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
func decodeJSONNumbers(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
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
