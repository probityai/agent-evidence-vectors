package corpora

// Digests over a JSON value for the W3C report reader.
//
// The v0.1 text does not say which bytes enter a digest over a JSON value, and
// the list proposed RFC 8785 under the identifier jcs-sha256 (2026Oct/0038)
// with a numeric profile (0040, 0041). This file implements it for the Go
// reader; packaging/agent_evidence_vectors/w3creport.py implements it for the
// Python reader and readers/w3c-report-rs for the Rust one, and
// testdata/json-encodings.json holds the three to the same bytes.
//
//   - jcs-sha256: a report's own digests over JSON values, each check-set
//     leaf. The RFC 8785 canonical form, every number an integer of magnitude
//     below 2^53 by its exact value. A number outside that profile has no
//     jcs-sha256 form; the report is rejected under W3C-R-020 with the cause.
//   - rfc8785: a member identifier. RFC 8785 as written, numbers as IEEE 754
//     doubles, because a member rejected for carrying an out-of-profile number
//     still needs a name.
//
// The profile is decided on the token's exact decimal value, never on a double
// made from it: a token beyond double precision can round itself into the safe
// range on the way, and 0.99999999999999999 parses to 1.0. The decomposition
// below reads digits and exponent without materialising the value, so a token
// such as 1e999999999 costs no more than its length.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	w3cJCSSHA256           = "jcs-sha256"
	w3cDigestsDiffer       = "digests-differ"
	w3cNonInteger          = "non-integer-number"
	w3cOutsideSafeRange    = "integer-outside-safe-range"
	w3cUnsupportedEncoding = "unsupported-digest-encoding"
	w3cNotFinite           = "number-not-finite"
	// 2^53 in decimal: an integer of this magnitude or more has no exact double.
	w3cSafeBound = "9007199254740992"
)

var (
	// The closed set of digest encodings a set binding may declare (proposed,
	// not in v0.1). A binding that declares none is digested under jcs-sha256.
	w3cDigestEncodings = set(w3cJCSSHA256)
	// The causes a member's expected.cause may name.
	w3cCauseCodes = set(w3cDigestsDiffer, w3cNonInteger, w3cOutsideSafeRange, w3cUnsupportedEncoding)
)

// w3cDigestRefusal is a value with no form under an encoding: a cause code and
// the number token it is about, as the token was written.
type w3cDigestRefusal struct {
	cause string
	token string
}

func (r *w3cDigestRefusal) Error() string { return r.cause + ": " + r.token }

// jcsDecimal is a JSON number token as an exact digits * 10^exp10, digits
// carrying no leading and no trailing zero (empty for zero).
type jcsDecimal struct {
	negative bool
	digits   string
	exp10    int64
}

// saturatingExponent reads a JSON exponent, which is an unbounded digit string,
// saturating rather than failing: past int64 the value is beyond any bound
// this file compares against, and its sign is all that still matters.
func saturatingExponent(text string) int64 {
	negative := strings.HasPrefix(text, "-")
	text = strings.TrimLeft(text, "+-")
	var value int64
	for _, c := range text {
		digit := int64(c - '0')
		if value > (math.MaxInt64-digit)/10 {
			value = math.MaxInt64
			break
		}
		value = value*10 + digit
	}
	if negative {
		return -value
	}
	return value
}

func decomposeNumber(token string) jcsDecimal {
	d := jcsDecimal{negative: strings.HasPrefix(token, "-")}
	body := strings.TrimPrefix(token, "-")
	mantissa, exponent := body, ""
	if i := strings.IndexAny(body, "eE"); i >= 0 {
		mantissa, exponent = body[:i], body[i+1:]
	}
	intPart, fracPart, _ := strings.Cut(mantissa, ".")
	d.digits = intPart + fracPart
	d.exp10 = saturatingExponent(exponent)
	if frac := int64(len(fracPart)); d.exp10 > math.MinInt64+frac {
		d.exp10 -= frac
	} else {
		d.exp10 = math.MinInt64
	}
	d.digits = strings.TrimLeft(d.digits, "0")
	for strings.HasSuffix(d.digits, "0") {
		d.digits = d.digits[:len(d.digits)-1]
		if d.exp10 < math.MaxInt64 {
			d.exp10++
		}
	}
	return d
}

func (d jcsDecimal) isInteger() bool { return d.digits == "" || d.exp10 >= 0 }

// belowSafeBound reports whether an integer's magnitude is below 2^53,
// decided on the digit string so no rounding reaches the comparison. The
// integer is digits followed by exp10 zeros (exp10 >= 0 for an integer).
func (d jcsDecimal) belowSafeBound() bool {
	if d.digits == "" {
		return true
	}
	bound := int64(len(w3cSafeBound))
	if d.exp10 >= bound {
		return false
	}
	if width := int64(len(d.digits)) + d.exp10; width != bound {
		return width < bound
	}
	return d.digits+strings.Repeat("0", int(d.exp10)) < w3cSafeBound
}

// integerText is an integer below the safe bound in decimal: what RFC 8785
// writes for it, since every such integer is an exact double printed in full.
func (d jcsDecimal) integerText() string {
	if d.digits == "" {
		return "0"
	}
	text := d.digits + strings.Repeat("0", int(d.exp10))
	if d.negative {
		return "-" + text
	}
	return text
}

// jcsProfileNumber is a number under the jcs-sha256 profile.
func jcsProfileNumber(n json.Number) (string, error) {
	token := n.String()
	d := decomposeNumber(token)
	if !d.isInteger() {
		return "", &w3cDigestRefusal{cause: w3cNonInteger, token: token}
	}
	if !d.belowSafeBound() {
		return "", &w3cDigestRefusal{cause: w3cOutsideSafeRange, token: token}
	}
	return d.integerText(), nil
}

// jcsPlainNumber is a number under RFC 8785 as written: the double it parses
// to, written as ECMAScript's Number::toString writes it.
func jcsPlainNumber(n json.Number) (string, error) {
	token := n.String()
	f, err := strconv.ParseFloat(token, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return "", err
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", &w3cDigestRefusal{cause: w3cNotFinite, token: token}
	}
	return es6NumberString(f), nil
}

// es6NumberString is ECMAScript Number::toString of a finite double (RFC 8785
// section 3.2.2.3). strconv's shortest round-trip digits are the digits
// ECMAScript chooses; the layout around them is ECMAScript's.
func es6NumberString(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	e, _ := strconv.Atoi(exponent)
	k, n := len(digits), e+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	body := digits[:1]
	if k > 1 {
		body += "." + digits[1:]
	}
	if n-1 >= 0 {
		return sign + body + "e+" + strconv.Itoa(n-1)
	}
	return sign + body + "e-" + strconv.Itoa(1-n)
}

// writeJCSString is RFC 8785 section 3.2.2.2: the quote, the backslash and
// U+0000 to U+001F escaped (the five short forms where JSON has them), every
// other character written as itself in UTF-8, U+007F included.
func writeJCSString(buf *bytes.Buffer, s string) {
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

func appendW3CJCS(buf *bytes.Buffer, value any, profile bool) error {
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
		writeJCSString(buf, v)
	case json.Number:
		var text string
		var err error
		if profile {
			text, err = jcsProfileNumber(v)
		} else {
			text, err = jcsPlainNumber(v)
		}
		if err != nil {
			return err
		}
		buf.WriteString(text)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendW3CJCS(buf, item, profile); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.SliceStable(keys, func(a, b int) bool { return utf16Less(keys[a], keys[b]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := appendW3CJCS(buf, v[k], profile); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// A float64 has lost the token it was written as: refuse rather than guess.
		return fmt.Errorf("corpora: %T has no RFC 8785 form here", value)
	}
	return nil
}

// jcsSHA256Bytes is what a jcs-sha256 digest is taken over.
func jcsSHA256Bytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := appendW3CJCS(&buf, value, true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rfc8785Bytes is RFC 8785 as written, numbers as IEEE 754 doubles: what a
// member identifier names.
func rfc8785Bytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := appendW3CJCS(&buf, value, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
