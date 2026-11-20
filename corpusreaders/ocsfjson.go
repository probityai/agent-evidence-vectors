package corpusreaders

// The strict JSON reading, the canonical bytes and the value comparisons the
// OCSF decision-record reader (ocsfdecision.go) is built on.
//
// The values a parse returns are nil, bool, string, ocsfNum, []any and
// map[string]any. A number keeps what its token said: an integer is read
// exactly (outside +-(2**53 - 1) it is marked wide, outside 64 bits it is
// refused), and any other token is the double it names, kept only when every
// reader reads that same number from it.

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ocsfNum is one JSON number as read. i is set for an integer token and f for
// any other.
type ocsfNum struct {
	isInt bool
	i     *big.Int
	f     float64
	wide  bool
}

const ocsfMaxDepth = 128

var (
	ocsfMaxSafe = big.NewInt(1<<53 - 1)
	ocsfIntMin  = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 63))
	ocsfIntMax  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
)

// ocsfParse reads text as strict I-JSON (RFC 7493): UTF-8 with no byte-order
// mark, a member named twice at any depth refused after its escapes are
// decoded, no lone surrogate, no NaN or Infinity, integers exact and bounded to
// 64 bits, other numbers only when their double is the same number, and nesting
// bounded.
func ocsfParse(text string) (any, error) {
	if !utf8.ValidString(text) {
		return nil, errors.New("not-utf8: invalid UTF-8")
	}
	if strings.HasPrefix(text, "\ufeff") {
		return nil, errors.New("not-utf8: a byte-order mark precedes the text")
	}
	p := &ocsfParser{s: text}
	p.space()
	value, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("not-parseable: extra data at byte %d", p.i)
	}
	return value, nil
}

type ocsfParser struct {
	s string
	i int
}

func (p *ocsfParser) space() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *ocsfParser) value(depth int) (any, error) {
	if p.i >= len(p.s) {
		return nil, errors.New("not-parseable: unexpected end of text")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	case strings.HasPrefix(p.s[p.i:], "NaN") || strings.HasPrefix(p.s[p.i:], "Infinity"):
		return nil, errors.New("non-json-number: NaN and Infinity are not JSON numbers")
	}
	return nil, fmt.Errorf("not-parseable: unexpected character at byte %d", p.i)
}

func (p *ocsfParser) object(depth int) (any, error) {
	if depth > ocsfMaxDepth {
		return nil, fmt.Errorf("nesting-too-deep: nesting deeper than %d", ocsfMaxDepth)
	}
	p.i++
	out := map[string]any{}
	p.space()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("not-parseable: an object member needs a string name at byte %d", p.i)
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("not-parseable: expected ':' at byte %d", p.i)
		}
		p.i++
		p.space()
		value, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		name := key.(string)
		if _, seen := out[name]; seen {
			return nil, fmt.Errorf("duplicate-member: member %q appears more than once", name)
		}
		out[name] = value
		p.space()
		if p.i >= len(p.s) {
			return nil, errors.New("not-parseable: unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, fmt.Errorf("not-parseable: expected ',' or '}' at byte %d", p.i)
		}
	}
}

func (p *ocsfParser) array(depth int) (any, error) {
	if depth > ocsfMaxDepth {
		return nil, fmt.Errorf("nesting-too-deep: nesting deeper than %d", ocsfMaxDepth)
	}
	p.i++
	out := []any{}
	p.space()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		p.space()
		value, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
		p.space()
		if p.i >= len(p.s) {
			return nil, errors.New("not-parseable: unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return out, nil
		default:
			return nil, fmt.Errorf("not-parseable: expected ',' or ']' at byte %d", p.i)
		}
	}
}

func (p *ocsfParser) hex4(at int) (rune, bool) {
	if at+4 > len(p.s) {
		return 0, false
	}
	n, err := strconv.ParseUint(p.s[at:at+4], 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

func (p *ocsfParser) str() (any, error) {
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return nil, fmt.Errorf("not-parseable: a control character in a string at byte %d", p.i)
		case c != '\\':
			b.WriteByte(c)
			p.i++
			continue
		}
		if p.i+1 >= len(p.s) {
			break
		}
		esc := p.s[p.i+1]
		p.i += 2
		switch esc {
		case '"', '\\', '/':
			b.WriteByte(esc)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, ok := p.hex4(p.i)
			if !ok {
				return nil, errors.New("not-parseable: a bad \\u escape")
			}
			p.i += 4
			if utf16.IsSurrogate(r) {
				low := rune(-1)
				if r < 0xDC00 && strings.HasPrefix(p.s[p.i:], "\\u") {
					if l, ok := p.hex4(p.i + 2); ok && l >= 0xDC00 && l <= 0xDFFF {
						low = l
					}
				}
				if low < 0 {
					return nil, errors.New("lone-surrogate: a string escapes a lone surrogate")
				}
				p.i += 6
				r = utf16.DecodeRune(r, low)
			}
			b.WriteRune(r)
		default:
			return nil, fmt.Errorf("not-parseable: an invalid escape at byte %d", p.i-2)
		}
	}
	return nil, errors.New("not-parseable: unterminated string")
}

func (p *ocsfParser) digits() int {
	start := p.i
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	return p.i - start
}

func (p *ocsfParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case p.digits() == 0:
		return nil, errors.New("not-parseable: a number needs digits")
	}
	isInt := true
	if p.i+1 < len(p.s) && p.s[p.i] == '.' && p.s[p.i+1] >= '0' && p.s[p.i+1] <= '9' {
		isInt = false
		p.i++
		p.digits()
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		at := p.i + 1
		if at < len(p.s) && (p.s[at] == '+' || p.s[at] == '-') {
			at++
		}
		if at < len(p.s) && p.s[at] >= '0' && p.s[at] <= '9' {
			isInt = false
			p.i = at
			p.digits()
		}
	}
	token := p.s[start:p.i]
	if isInt {
		return ocsfExactInt(token)
	}
	f, err := ocsfFiniteFloat(token)
	if err != nil {
		return nil, err
	}
	return ocsfNum{f: f}, nil
}

// ocsfExactInt reads an integer token exactly. The format's rule has no form for
// an integer outside 64 bits, so one is refused; one outside +-(2**53 - 1) is
// read and marked wide.
func ocsfExactInt(token string) (any, error) {
	n, ok := new(big.Int).SetString(token, 10)
	if !ok || n.Cmp(ocsfIntMin) < 0 || n.Cmp(ocsfIntMax) > 0 {
		return nil, fmt.Errorf("unsafe-integer: integer token of %d digits is outside 64 bits, where the format's exact-integer rule has no form", len(token))
	}
	wide := new(big.Int).Abs(n).Cmp(ocsfMaxSafe) > 0
	return ocsfNum{isInt: true, i: n, wide: wide}, nil
}

// ocsfDecimal is a decimal number with its trailing and leading zeros stripped:
// value = (-1)^neg * digits * 10^exp, and digits == "" is zero.
type ocsfDecimal struct {
	neg    bool
	digits string
	exp    int
}

func (d ocsfDecimal) equal(o ocsfDecimal) bool {
	if d.digits == "" || o.digits == "" {
		return d.digits == o.digits
	}
	return d.neg == o.neg && d.digits == o.digits && d.exp == o.exp
}

// ocsfDecompose reads a JSON number token or a strconv 'e' form into an
// ocsfDecimal. It reports false when the exponent has more digits than an int64
// holds, which for a nonzero mantissa means no finite double names the number.
func ocsfDecompose(token string) (ocsfDecimal, bool) {
	var d ocsfDecimal
	if strings.HasPrefix(token, "-") {
		d.neg, token = true, token[1:]
	}
	mantissa, expText, hasExp := strings.Cut(strings.ToLower(token), "e")
	whole, frac, _ := strings.Cut(mantissa, ".")
	exp := 0
	if hasExp {
		n, err := strconv.ParseInt(strings.TrimPrefix(expText, "+"), 10, 64)
		if err != nil {
			if allZero(whole + frac) {
				return ocsfDecimal{}, true
			}
			return ocsfDecimal{}, false
		}
		exp = int(n)
	}
	digits := strings.TrimLeft(whole+frac, "0")
	exp -= len(frac)
	trimmed := strings.TrimRight(digits, "0")
	exp += len(digits) - len(trimmed)
	d.digits, d.exp = trimmed, exp
	return d, true
}

func allZero(s string) bool { return strings.Trim(s, "0") == "" }

// ocsfFiniteFloat is the double a non-integer token names, when every reader
// reads the same number from it. The shortest round-trip form of the double is
// what a double-based reader holds and writes back, so the token is read only
// when that form is numerically the token itself: 1.10 and 1.1 agree,
// 0.10000000000000001 reads as 0.1 and is refused, 1e-400 reads as 0 and is
// refused, 1e400 is not finite.
func ocsfFiniteFloat(token string) (float64, error) {
	f, err := strconv.ParseFloat(token, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("not-parseable: %s is not a number", token)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("value-not-representable: %s is not a finite double", token)
	}
	want, ok := ocsfDecompose(token)
	if !ok {
		return 0, fmt.Errorf("value-not-representable: %s reads as the double %v, another number", token, f)
	}
	got, _ := ocsfDecompose(strconv.FormatFloat(f, 'e', -1, 64))
	if !want.equal(got) {
		return 0, fmt.Errorf("value-not-representable: %s reads as the double %v, another number", token, f)
	}
	return f, nil
}

// --- the values, read as Python reads them ---------------------------------------------------

func ocsfIsInt(v any) bool {
	n, ok := v.(ocsfNum)
	return ok && n.isInt
}

func ocsfInt(v any) *big.Int {
	n, _ := v.(ocsfNum)
	return n.i
}

// ocsfRat is the exact number a value is in Python's arithmetic: a bool is 0 or
// 1, an integer is itself and a float is the exact binary fraction it holds.
func ocsfRat(v any) (*big.Rat, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return big.NewRat(1, 1), true
		}
		return new(big.Rat), true
	case ocsfNum:
		if x.isInt {
			return new(big.Rat).SetInt(x.i), true
		}
		return new(big.Rat).SetFloat64(x.f), x.f == x.f && !math.IsInf(x.f, 0)
	}
	return nil, false
}

// pyEqual is Python's == over two JSON values: 1, 1.0 and true are one value
// there, a list equals a list element by element and an object an object member
// by member.
func pyEqual(a, b any) bool {
	if ra, ok := ocsfRat(a); ok {
		rb, ok := ocsfRat(b)
		return ok && ra.Cmp(rb) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
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
			w, present := y[k]
			if !present || !pyEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// pyEqualInt is pyEqual against an integer.
func pyEqualInt(v any, n int64) bool { return pyEqual(v, ocsfNum{isInt: true, i: big.NewInt(n)}) }

// pyTruth is the value of v when it is one of True and False in a Python `in
// (True, False)` test, which 0, 1, 0.0 and 1.0 also pass.
func pyTruth(v any) (value, ok bool) {
	r, isNum := ocsfRat(v)
	if !isNum {
		return false, false
	}
	switch {
	case r.Sign() == 0:
		return false, true
	case r.Cmp(big.NewRat(1, 1)) == 0:
		return true, true
	}
	return false, false
}

// ocsfGet walks object members by name: nil when a step is not an object or the
// member is absent.
func ocsfGet(v any, names ...string) any {
	for _, name := range names {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[name]
	}
	return v
}

func ocsfObj(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// --- canonical bytes -------------------------------------------------------------------------

// ocsfCanon is the RFC 8785 text of a value with integers written exactly, as
// the format's verifier rule says, never through a double.
func ocsfCanon(value any) string {
	var b strings.Builder
	ocsfWrite(&b, value)
	return b.String()
}

func ocsfWrite(b *strings.Builder, value any) {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case ocsfNum:
		if v.isInt {
			b.WriteString(v.i.String())
		} else {
			b.WriteString(a2aNumber(v.f))
		}
	case string:
		a2aString(b, v)
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			ocsfWrite(b, item)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := sortedKeys(v)
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			a2aString(b, k)
			b.WriteByte(':')
			ocsfWrite(b, v[k])
		}
		b.WriteByte('}')
	}
}

// sortUTF16 orders member names by UTF-16 code unit, as RFC 8785 requires.
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return a2aUTF16Less(keys[i], keys[j]) })
}

// ocsfWidePaths lists the paths of integers a double-based reader reads as
// another number.
func ocsfWidePaths(value any, path string) []string {
	var out []string
	switch v := value.(type) {
	case ocsfNum:
		if v.isInt && v.wide {
			f, _ := new(big.Float).SetInt(v.i).Float64()
			back, _ := new(big.Float).SetFloat64(f).Int(nil)
			if back.Cmp(v.i) != 0 {
				if path == "" {
					path = "/"
				}
				out = append(out, path)
			}
		}
	case map[string]any:
		for k, item := range v {
			out = append(out, ocsfWidePaths(item, path+"/"+k)...)
		}
	case []any:
		for i, item := range v {
			out = append(out, ocsfWidePaths(item, fmt.Sprintf("%s/%d", path, i))...)
		}
	}
	return out
}

// --- instants --------------------------------------------------------------------------------

// ocsfInstant is a time as written, read as an instant when it names one.
type ocsfInstant struct {
	text string
	secs *big.Rat
	why  string
}

func (i ocsfInstant) ok() bool { return i.secs != nil }

var (
	ocsfTimeRE = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$`)
	ocsfHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// matchDollar is Python's re.match for a pattern ending in $, which also
// matches before one trailing newline.
func matchDollar(re *regexp.Regexp, s string) []string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m
	}
	if strings.HasSuffix(s, "\n") {
		return re.FindStringSubmatch(strings.TrimSuffix(s, "\n"))
	}
	return nil
}

func ocsfDaysIn(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 31
}

// ocsfOrdinal is Python's date.toordinal: January 1 of year 1 is day 1.
func ocsfOrdinal(year, month, day int) int {
	y := year - 1
	days := y*365 + y/4 - y/100 + y/400
	for m := 1; m < month; m++ {
		days += ocsfDaysIn(year, m)
	}
	return days + day
}

// ocsfInstantOf reads an RFC 3339 time as exact seconds on one axis; a date or
// second no calendar has is no instant, and neither is a time with no offset.
func ocsfInstantOf(v any) ocsfInstant {
	text, isText := v.(string)
	if !isText {
		return ocsfInstant{text: fmt.Sprint(v), why: "not a time"}
	}
	m := matchDollar(ocsfTimeRE, text)
	if m == nil {
		return ocsfInstant{text: text, why: "not a time"}
	}
	num := func(i int) int { n, _ := strconv.Atoi(m[i]); return n }
	year, month, day, hour, minute, second := num(1), num(2), num(3), num(4), num(5), num(6)
	fraction, zone := m[7], m[8]
	if zone == "" {
		return ocsfInstant{text: text, why: "no offset"}
	}
	if hour > 23 || minute > 59 || second > 59 {
		return ocsfInstant{text: text, why: "no such time"}
	}
	if year < 1 || month < 1 || month > 12 || day < 1 || day > ocsfDaysIn(year, month) {
		return ocsfInstant{text: text, why: "no such date"}
	}
	offset := 0
	if zone != "Z" {
		sign := 1
		if zone[0] == '-' {
			sign = -1
		}
		oh, _ := strconv.Atoi(zone[1:3])
		om, _ := strconv.Atoi(zone[4:6])
		if oh > 23 || om > 59 {
			return ocsfInstant{text: text, why: "no such offset"}
		}
		offset = sign * (oh*3600 + om*60)
	}
	whole := int64(ocsfOrdinal(year, month, day))*86400 + int64(hour*3600+minute*60+second-offset)
	total := new(big.Rat).SetInt64(whole)
	if fraction != "" {
		digits := fraction[1:]
		num, _ := new(big.Int).SetString(digits, 10)
		den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(digits))), nil)
		total.Add(total, new(big.Rat).SetFrac(num, den))
	}
	return ocsfInstant{text: text, secs: total}
}

// String prints a number as its token read it, so a finding that quotes a value
// shows 600399 and not a struct.
func (n ocsfNum) String() string {
	if n.isInt {
		return n.i.String()
	}
	return a2aNumber(n.f)
}
