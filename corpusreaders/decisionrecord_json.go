package corpusreaders

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"unicode/utf8"
)

// The decision-record reader judges bytes the way its reference reader does
// (agent_evidence_verify.decision_record over agent_evidence_verify.ijson), so it
// keeps the JSON values that reader keeps apart apart: an integer token and a
// non-integer token are two types (1 and 1.0 differ under the format's equality),
// a boolean is neither, and an integer outside I-JSON's exact range is carried
// as such so the bounds can be judged rather than the document refused.
//
// Values decoded here are nil, bool, string, drecInt, float64, []any and
// map[string]any.

// drecMaxSafe is I-JSON's exact-integer limit, 2**53 - 1 (RFC 7493 section 2.2).
const drecMaxSafe = 1<<53 - 1

// drecMaxDepth bounds nesting, objects and arrays together, as the reference does.
const drecMaxDepth = 128

// drecInt is an integer token. Unsafe marks one outside +-(2**53 - 1): it is only
// ever produced when the caller asked for unsafe integers to be read rather than
// refused (the bounds of a standing approval, and the bytes judged against them).
type drecInt struct {
	n      *big.Int
	unsafe bool
}

// drecJSONMode selects which of the reference reader's three JSON readings applies.
type drecJSONMode int

const (
	// drecStrict is parse_ijson: a member twice, an unsafe integer, a non-finite or
	// inexact number, a lone surrogate and a non-JSON constant are each refused.
	drecStrict drecJSONMode = iota
	// drecBounds is parse_ijson with the bounds' integer hook: every check still
	// runs except that an integer outside the exact range is read and marked.
	drecBounds
	// drecLenient is Python's json.loads, which reads a corpus member file: the
	// last of a repeated member wins and numbers are read as written.
	drecLenient
)

// drecJSONError is a refusal, with the reference's code.
type drecJSONError struct {
	Code   string
	Detail string
}

func (e *drecJSONError) Error() string { return e.Code + ": " + e.Detail }

func drecRefuse(code, format string, args ...any) error {
	return &drecJSONError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// drecParse reads data under mode.
func drecParse(data []byte, mode drecJSONMode) (any, error) {
	if !utf8.Valid(data) {
		return nil, drecRefuse("not-utf8", "invalid UTF-8")
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		if mode != drecLenient {
			return nil, drecRefuse("not-utf8", "a byte-order mark precedes the text")
		}
		data = data[3:] // json.loads of bytes reads a leading mark as the encoding's
	}
	p := &drecParser{s: data, mode: mode}
	p.ws()
	value, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, drecRefuse("not-parseable", "extra data at byte %d", p.i)
	}
	return value, nil
}

type drecParser struct {
	s    []byte
	i    int
	mode drecJSONMode
}

func (p *drecParser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *drecParser) bad(what string) error {
	return drecRefuse("not-parseable", "%s at byte %d", what, p.i)
}

func (p *drecParser) value(depth int) (any, error) {
	if p.i >= len(p.s) {
		return nil, p.bad("expecting a value")
	}
	for _, constant := range []string{"NaN", "Infinity", "-Infinity"} {
		if p.has(constant) {
			if p.mode != drecLenient {
				return nil, drecRefuse("non-json-number", "%s is not a JSON number", constant)
			}
			p.i += len(constant)
			switch constant {
			case "NaN":
				return math.NaN(), nil
			case "Infinity":
				return math.Inf(1), nil
			}
			return math.Inf(-1), nil
		}
	}
	switch c := p.s[p.i]; {
	case c == '{' || c == '[':
		if depth+1 > drecMaxDepth {
			return nil, drecRefuse("nesting-too-deep", "nesting deeper than %d", drecMaxDepth)
		}
		if c == '{' {
			return p.object(depth + 1)
		}
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for _, lit := range []struct {
		text  string
		value any
	}{{"true", true}, {"false", false}, {"null", nil}} {
		if p.has(lit.text) {
			p.i += len(lit.text)
			return lit.value, nil
		}
	}
	return nil, p.bad("expecting a value")
}

func (p *drecParser) has(text string) bool {
	return len(p.s)-p.i >= len(text) && string(p.s[p.i:p.i+len(text)]) == text
}

func (p *drecParser) object(depth int) (any, error) {
	p.i++ // {
	out := map[string]any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.bad("expecting a property name")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.bad("expecting ':'")
		}
		p.i++
		p.ws()
		value, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		name := key.(string)
		if _, seen := out[name]; seen && p.mode != drecLenient {
			return nil, drecRefuse("duplicate-member", "member %q appears more than once", name)
		}
		out[name] = value
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		return nil, p.bad("expecting ',' or '}'")
	}
}

func (p *drecParser) array(depth int) (any, error) {
	p.i++ // [
	out := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		p.ws()
		value, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, p.bad("expecting ',' or ']'")
	}
}

func drecHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(b[:4]), 16, 16)
	if err != nil {
		return 0, false
	}
	for _, c := range b[:4] {
		if c == '+' || c == '-' {
			return 0, false
		}
	}
	return rune(n), true
}

// str reads a string as CPython's scanner does: control characters are refused,
// an escaped high surrogate followed by an escaped low one is one character, and
// any other escaped surrogate is lone (refused unless the mode is lenient).
func (p *drecParser) str() (any, error) {
	p.i++ // opening quote
	var out []byte
	for {
		if p.i >= len(p.s) {
			return nil, p.bad("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return nil, p.bad("invalid control character")
		case c != '\\':
			out = append(out, c)
			p.i++
			continue
		}
		if p.i+1 >= len(p.s) {
			return nil, p.bad("unterminated string")
		}
		esc := p.s[p.i+1]
		simple := map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
		if r, ok := simple[esc]; ok {
			out = append(out, r)
			p.i += 2
			continue
		}
		if esc != 'u' {
			return nil, p.bad("invalid \\escape")
		}
		r, ok := drecHex4(p.s[p.i+2:])
		if !ok {
			return nil, p.bad("invalid \\uXXXX escape")
		}
		p.i += 6
		if r >= 0xD800 && r <= 0xDBFF && p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
			if low, okLow := drecHex4(p.s[p.i+2:]); okLow && low >= 0xDC00 && low <= 0xDFFF {
				r = 0x10000 + (r-0xD800)<<10 + (low - 0xDC00)
				p.i += 6
			}
		}
		if r >= 0xD800 && r <= 0xDFFF {
			if p.mode != drecLenient {
				return nil, drecRefuse("lone-surrogate", "a string escapes a lone surrogate")
			}
			r = utf8.RuneError
		}
		out = utf8.AppendRune(out, r)
	}
}

func (p *drecParser) digits() int {
	start := p.i
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	return p.i - start
}

// number reads the token CPython's NUMBER_RE matches: an integer part, then an
// optional fraction and exponent; a token with either is a float.
func (p *drecParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if p.digits() == 0 {
		return nil, p.bad("expecting a value")
	}
	intEnd := p.i
	isFloat := false
	if p.i+1 < len(p.s) && p.s[p.i] == '.' && p.s[p.i+1] >= '0' && p.s[p.i+1] <= '9' {
		p.i++
		p.digits()
		isFloat = true
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		save := p.i
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.digits() == 0 {
			p.i = save
		} else {
			isFloat = true
		}
	}
	if !isFloat {
		p.i = intEnd
		return p.integer(string(p.s[start:intEnd]))
	}
	return p.float(string(p.s[start:p.i]))
}

func (p *drecParser) integer(text string) (any, error) {
	n, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, p.bad("not an integer")
	}
	unsafe := n.CmpAbs(big.NewInt(drecMaxSafe)) > 0
	if unsafe && p.mode == drecStrict {
		return nil, drecRefuse("unsafe-integer", "%s is outside +-(2**53 - 1)", text)
	}
	return drecInt{n: n, unsafe: unsafe}, nil
}

// float reads a non-integer token. Outside the lenient mode it is read only when
// the double it names, written back at its shortest, is numerically the token.
func (p *drecParser) float(text string) (any, error) {
	value, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, p.bad("not a number")
	}
	if p.mode == drecLenient {
		return value, nil
	}
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return nil, drecRefuse("value-not-representable", "%s is not a finite double", text)
	}
	token, okToken := new(big.Rat).SetString(text)
	shortest, okShortest := new(big.Rat).SetString(strconv.FormatFloat(value, 'g', -1, 64))
	if !okToken || !okShortest || token.Cmp(shortest) != 0 {
		return nil, drecRefuse("value-not-representable", "%s reads as another double", text)
	}
	return value, nil
}

// --- equality --------------------------------------------------------------------------

// drecNumber is an int or a float as a Python number, for == between them.
func drecNumber(v any) (*big.Rat, bool) {
	switch x := v.(type) {
	case drecInt:
		return new(big.Rat).SetInt(x.n), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return new(big.Rat).SetFloat64(x), true
	case bool:
		if x {
			return big.NewRat(1, 1), true
		}
		return new(big.Rat), true
	}
	return nil, false
}

// drecEq is Python's ==: True, 1 and 1.0 are equal; a string equals only a string.
func drecEq(a, b any) bool {
	if na, okA := drecNumber(a); okA {
		nb, okB := drecNumber(b)
		if !okB {
			if fa, isF := a.(float64); isF && math.IsInf(fa, 0) {
				fb, isFB := b.(float64)
				return isFB && fa == fb
			}
			return false
		}
		return na.Cmp(nb) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case float64: // a non-finite float, which drecNumber left out
		y, ok := b.(float64)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !drecEq(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, has := y[k]
			if !has || !drecEq(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// drecSame is the format's equality: 1, 1.0 and true are three values, while two
// integers compare by value whether or not either is outside the exact range.
func drecSame(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case drecInt:
		y, ok := b.(drecInt)
		return ok && x.n.Cmp(y.n) == 0
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !drecSame(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, has := y[k]
			if !has || !drecSame(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// drecJSONInteger is an integer token inside the exact range (never a boolean).
func drecJSONInteger(v any) bool {
	n, ok := v.(drecInt)
	return ok && !n.unsafe && n.n.CmpAbs(big.NewInt(drecMaxSafe)) <= 0
}

// drecIntValue is the value of an integer drecJSONInteger admits.
func drecIntValue(v any) int64 {
	if n, ok := v.(drecInt); ok && n.n.IsInt64() {
		return n.n.Int64()
	}
	return 0
}

// drecKey is a hashable stand-in for a value, equal exactly when Python's repr is.
func drecKey(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		return fmt.Sprintf("bool:%v", x)
	case string:
		return "str:" + x
	case drecInt:
		return "int:" + x.n.String()
	case float64:
		return "float:" + strconv.FormatFloat(x, 'g', -1, 64)
	}
	return fmt.Sprintf("other:%v", v)
}

// drecRepr is a readable rendering of a value for a finding, close to Python's repr.
func drecRepr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return "'" + x + "'"
	case drecInt:
		return x.n.String()
	case float64:
		text := strconv.FormatFloat(x, 'g', -1, 64)
		if _, err := strconv.ParseInt(text, 10, 64); err == nil {
			text += ".0"
		}
		return text
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = drecRepr(item)
		}
		return fmt.Sprintf("%v", parts)
	case map[string]any:
		return fmt.Sprintf("%v", sortedKeys(x))
	}
	return fmt.Sprint(v)
}

// drecKeys is the sorted member names of an object.
func drecKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
