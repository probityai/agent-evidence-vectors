package corpora

// The value layer of the refund-connected reader.
//
// The reference reader (packaging/agent_evidence_vectors/refundconnected.py) is
// written against Python's dynamic values: a JSON document parses to dicts,
// lists, strs, ints, bools and None, and a hostile or damaged retained file
// reaches comparisons, membership tests and indexing with the wrong type. In
// Python each of those either gives a verdict or raises an exception the reader
// does not catch, which ends the whole run. This file reproduces exactly those
// outcomes so the Go reader answers the same on every input, including the
// inputs that crash the reference: a *rcObj is a dict that keeps member order,
// a *big.Int is an int, and rcFault is an uncaught Python exception.
//
// Deliberate differences from CPython, each unreachable from the retained runs
// and from the mutations the differential test applies to them:
//   - str() of a list or dict is not CPython's repr, it is a string no JSON
//     string can equal;
//   - nesting deeper than rcMaxDepth is a fault, as CPython's is a
//     RecursionError at a depth near, but not exactly at, that number.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const rcMaxDepth = 900

// rcObj is a JSON object that remembers the order its members were written in.
// Admission.for_decision and the first-record rule both depend on that order.
type rcObj struct {
	keys []string
	m    map[string]any
}

// get is o.get(key): None for a member that is not there.
func (o *rcObj) get(key string) any { return o.m[key] }

// item is o[key]: a member that is not there raises KeyError.
func (o *rcObj) item(key string) any {
	got, present := o.m[key]
	if !present {
		rcRaise("KeyError", "%q", key)
	}
	return got
}

// rcFault is a Python exception the reference reader does not catch. class is
// the CPython class name; a UnicodeError is classed ValueError because it is a
// subclass of it and that is the only way the reader's except clauses see it.
type rcFault struct{ class, msg string }

func (f rcFault) Error() string { return f.class + ": " + f.msg }

// rcFinding is the reader's Finding exception.
type rcFinding struct{ kind, code string }

func (f rcFinding) verdict() string { return f.kind + ":" + f.code }

func rcRaise(class, format string, args ...any) {
	panic(rcFault{class: class, msg: fmt.Sprintf(format, args...)})
}

// rcCatch runs fn and returns the fault it raised when its class is one of
// classes; any other panic goes on up, as an uncaught exception does.
func rcCatch(fn func(), classes ...string) (caught *rcFault) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		fault, ok := r.(rcFault)
		if !ok {
			panic(r)
		}
		for _, class := range classes {
			if fault.class == class {
				caught = &fault
				return
			}
		}
		panic(r)
	}()
	fn()
	return nil
}

// rcTry runs fn and returns the Finding it raised, if any.
func rcTry(fn func()) (found *rcFinding) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		f, ok := r.(rcFinding)
		if !ok {
			panic(r)
		}
		found = &f
	}()
	fn()
	return nil
}

// ----------------------------------------------------------------------------
// Strict parsing: one JSON document, UTF-8, no duplicate members, no floats and
// no NaN or Infinity, exactly what the reference's parse() accepts.
// ----------------------------------------------------------------------------

type rcParser struct {
	s     []byte
	i     int
	depth int
}

func rcParse(data []byte) any {
	if !utf8.Valid(data) {
		rcRaise("ValueError", "invalid utf-8")
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		rcRaise("ValueError", "unexpected BOM")
	}
	p := &rcParser{s: data}
	v := p.value()
	p.ws()
	if p.i != len(p.s) {
		p.fail("extra data")
	}
	return v
}

func (p *rcParser) fail(what string) {
	rcRaise("ValueError", "json: %s at byte %d", what, p.i)
}

func (p *rcParser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *rcParser) value() any {
	p.ws()
	if p.i >= len(p.s) {
		p.fail("expecting value")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		return p.str()
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for _, lit := range []struct {
		text  string
		value any
	}{{"null", nil}, {"true", true}, {"false", false}} {
		if bytes.HasPrefix(p.s[p.i:], []byte(lit.text)) {
			p.i += len(lit.text)
			return lit.value
		}
	}
	p.fail("expecting value")
	return nil
}

func (p *rcParser) number() any {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := p.i
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case p.i < len(p.s) && p.s[p.i] >= '1' && p.s[p.i] <= '9':
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	default:
		p.fail("expecting value")
	}
	if p.i-digits > 4300 {
		p.fail("integer exceeds the digit limit")
	}
	if p.i < len(p.s) && (p.s[p.i] == '.' || p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.fail("float")
	}
	n, ok := new(big.Int).SetString(string(p.s[start:p.i]), 10)
	if !ok {
		p.fail("integer")
	}
	return n
}

func (p *rcParser) hex4(at int) (int, bool) {
	if at+4 > len(p.s) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(p.s[at:at+4]), 16, 32)
	if err != nil || strings.ContainsAny(string(p.s[at:at+4]), "+-_") {
		return 0, false
	}
	return int(v), true
}

// rcAppendCode appends code point u as UTF-8, a lone surrogate as the three
// bytes CPython keeps it as (WTF-8), so it survives to be compared.
func rcAppendCode(out []byte, u int) []byte {
	if u >= 0xD800 && u <= 0xDFFF {
		return append(out, byte(0xE0|u>>12), byte(0x80|(u>>6)&0x3F), byte(0x80|u&0x3F)) // #nosec G115 -- u is a surrogate, 0xD800 to 0xDFFF, and each byte is masked
	}
	return utf8.AppendRune(out, rune(u)) // #nosec G115 -- u is a code point below 0x110000
}

func (p *rcParser) escape(out []byte) []byte {
	if p.i >= len(p.s) {
		p.fail("unterminated string")
	}
	c := p.s[p.i]
	p.i++
	if short, ok := map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9}[c]; ok {
		return append(out, short)
	}
	if c != 'u' {
		p.fail("invalid escape")
	}
	u, ok := p.hex4(p.i)
	if !ok {
		p.fail("invalid \\u escape")
	}
	p.i += 4
	if u >= 0xD800 && u <= 0xDBFF && bytes.HasPrefix(p.s[p.i:], []byte(`\u`)) {
		low, lok := p.hex4(p.i + 2)
		if !lok {
			p.fail("invalid \\u escape")
		}
		if low >= 0xDC00 && low <= 0xDFFF {
			u = 0x10000 + (u-0xD800)<<10 + (low - 0xDC00)
			p.i += 6
		}
	}
	return rcAppendCode(out, u)
}

func (p *rcParser) str() string {
	p.i++
	var out []byte
	for {
		if p.i >= len(p.s) {
			p.fail("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out)
		case c == '\\':
			p.i++
			out = p.escape(out)
		case c < 0x20:
			p.fail("control character in string")
		default:
			out = append(out, c)
			p.i++
		}
	}
}

func (p *rcParser) descend() {
	p.depth++
	if p.depth > rcMaxDepth {
		rcRaise("RecursionError", "maximum recursion depth exceeded")
	}
}

func (p *rcParser) array() any {
	p.descend()
	p.i++
	out := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		p.depth--
		return out
	}
	for {
		out = append(out, p.value())
		p.ws()
		if p.i >= len(p.s) {
			p.fail("unterminated array")
		}
		c := p.s[p.i]
		p.i++
		if c == ']' {
			p.depth--
			return out
		}
		if c != ',' {
			p.fail("expecting , delimiter")
		}
	}
}

func (p *rcParser) object() any {
	p.descend()
	p.i++
	obj := &rcObj{m: map[string]any{}}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		p.depth--
		return obj
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			p.fail("expecting property name")
		}
		key := p.str()
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			p.fail("expecting : delimiter")
		}
		p.i++
		value := p.value()
		if _, dup := obj.m[key]; dup {
			p.fail("duplicate member")
		}
		obj.keys = append(obj.keys, key)
		obj.m[key] = value
		p.ws()
		if p.i >= len(p.s) {
			p.fail("unterminated object")
		}
		c := p.s[p.i]
		p.i++
		if c == '}' {
			p.depth--
			return obj
		}
		if c != ',' {
			p.fail("expecting , delimiter")
		}
	}
}

// ----------------------------------------------------------------------------
// Python value semantics.
// ----------------------------------------------------------------------------

func rcIsObj(v any) bool {
	_, ok := v.(*rcObj)
	return ok
}

func rcIsStr(v any) bool {
	_, ok := v.(string)
	return ok
}

// rcEqStr is v == s for a str s.
func rcEqStr(v any, s string) bool {
	got, ok := v.(string)
	return ok && got == s
}

// rcItem is v["key"] for a dict key: a dict without the key raises KeyError, and
// indexing anything else by a str raises TypeError.
func rcItem(v any, key string) any {
	obj, ok := v.(*rcObj)
	if !ok {
		rcRaise("TypeError", "indices must be integers, not str")
	}
	got, present := obj.m[key]
	if !present {
		rcRaise("KeyError", "%q", key)
	}
	return got
}

// rcGet is v.get("key"): None for a missing key, AttributeError off a dict.
func rcGet(v any, key string) any {
	obj, ok := v.(*rcObj)
	if !ok {
		rcRaise("AttributeError", "object has no attribute 'get'")
	}
	return obj.m[key]
}

func rcObjOf(v any) *rcObj {
	obj, ok := v.(*rcObj)
	if !ok {
		rcRaise("AttributeError", "object is not a dict")
	}
	return obj
}

// rcKeysAre is set(o) == {want...}.
func rcKeysAre(o *rcObj, want ...string) bool {
	if len(o.keys) != len(want) {
		return false
	}
	for _, key := range want {
		if _, ok := o.m[key]; !ok {
			return false
		}
	}
	return true
}

func rcBoolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// rcNumEq compares the numeric kinds the way == does, so True == 1.
func rcNumEq(a, b any) (equal, numeric bool) {
	ai, aok := rcAsBig(a)
	bi, bok := rcAsBig(b)
	if !aok || !bok {
		return false, false
	}
	return ai.Cmp(bi) == 0, true
}

func rcAsBig(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case *big.Int:
		return x, true
	case bool:
		return big.NewInt(rcBoolInt(x)), true
	}
	return nil, false
}

// rcEq is a == b over parsed JSON values.
func rcEq(a, b any) bool {
	if eq, numeric := rcNumEq(a, b); numeric {
		return eq
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
			if !rcEq(x[i], y[i]) {
				return false
			}
		}
		return true
	case *rcObj:
		y, ok := b.(*rcObj)
		if !ok || len(x.keys) != len(y.keys) {
			return false
		}
		for _, key := range x.keys {
			other, present := y.m[key]
			if !present || !rcEq(x.m[key], other) {
				return false
			}
		}
		return true
	}
	return false
}

// rcKind names the Python type of a parsed value, for typed_equal.
func rcKind(v any) string {
	switch v.(type) {
	case nil:
		return "none"
	case bool:
		return "bool"
	case *big.Int:
		return "int"
	case string:
		return "str"
	case []any:
		return "list"
	}
	return "dict"
}

// rcTypedEq is typed_equal: equal, with the same type at every depth.
func rcTypedEq(a, b any) bool {
	if rcKind(a) != rcKind(b) {
		return false
	}
	switch x := a.(type) {
	case *rcObj:
		y := b.(*rcObj)
		if !rcKeysAre(y, x.keys...) {
			return false
		}
		for _, key := range x.keys {
			if !rcTypedEq(x.m[key], y.m[key]) {
				return false
			}
		}
		return true
	case []any:
		y := b.([]any)
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if !rcTypedEq(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return rcEq(a, b)
}

// rcHashable raises TypeError for the unhashable kinds, as a dict key or set
// member would.
func rcHashable(v any) {
	switch v.(type) {
	case []any, *rcObj:
		rcRaise("TypeError", "unhashable type")
	}
}

// rcIn is x in container.
func rcIn(x, container any) bool {
	switch c := container.(type) {
	case []any:
		for _, e := range c {
			if rcEq(x, e) {
				return true
			}
		}
		return false
	case *rcObj:
		rcHashable(x)
		s, ok := x.(string)
		if !ok {
			return false
		}
		_, present := c.m[s]
		return present
	case string:
		s, ok := x.(string)
		if !ok {
			rcRaise("TypeError", "'in <string>' requires string as left operand")
		}
		return strings.Contains(c, s)
	}
	rcRaise("TypeError", "argument is not iterable")
	return false
}

// rcIter is iterating a value: a list yields its items, a dict its keys, a str
// its characters; anything else is not iterable.
func rcIter(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case *rcObj:
		out := make([]any, len(x.keys))
		for i, k := range x.keys {
			out[i] = k
		}
		return out
	case string:
		var out []any
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	}
	rcRaise("TypeError", "object is not iterable")
	return nil
}

func rcLen(v any) int {
	switch x := v.(type) {
	case []any:
		return len(x)
	case *rcObj:
		return len(x.keys)
	case string:
		return utf8.RuneCountInString(x)
	}
	rcRaise("TypeError", "object has no len()")
	return 0
}

// rcStr is str(v). A list or dict has no faithful spelling here: it gets one
// no JSON string equals, and which of the two spellings CPython gives it is
// never observable from a verdict.
func rcStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case *big.Int:
		return x.String()
	case string:
		return x
	}
	return "\x00container"
}

// rcLess is a < b for the operands the reader compares: two strs, or two ints.
func rcLess(a, b any) bool {
	if x, ok := a.(string); ok {
		if y, ok := b.(string); ok {
			return x < y
		}
	}
	ai, aok := rcAsBig(a)
	bi, bok := rcAsBig(b)
	if aok && bok {
		return ai.Cmp(bi) < 0
	}
	rcRaise("TypeError", "'<' not supported between instances")
	return false
}

// rcLessEq is a <= b: rcLess has already raised TypeError for operands the
// language cannot order, so equality is all that is left to ask.
func rcLessEq(a, b any) bool { return rcLess(a, b) || rcEq(a, b) }

// rcDict is a Python dict keyed by any hashable parsed value, in insertion
// order, with 1 and True the same key.
type rcDict struct {
	keys []any
	vals []any
}

func (d *rcDict) find(key any) int {
	rcHashable(key)
	for i, k := range d.keys {
		if rcEq(k, key) {
			return i
		}
	}
	return -1
}

func (d *rcDict) get(key any) (any, bool) {
	if i := d.find(key); i >= 0 {
		return d.vals[i], true
	}
	return nil, false
}

func (d *rcDict) set(key, val any) {
	if i := d.find(key); i >= 0 {
		d.vals[i] = val
		return
	}
	d.keys = append(d.keys, key)
	d.vals = append(d.vals, val)
}

// ----------------------------------------------------------------------------
// Canonical bytes and the two primitives of the rail: RFC 8785 and Ed25519.
// ----------------------------------------------------------------------------

func rcHasSurrogate(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 {
			return true
		}
	}
	return false
}

// rcUTF8 is s.encode("utf-8"): a lone surrogate cannot be encoded.
func rcUTF8(s string) []byte {
	if rcHasSurrogate(s) {
		rcRaise("ValueError", "surrogates not allowed")
	}
	return []byte(s)
}

func rcJCSString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == 8:
			b.WriteString(`\b`)
		case r == 9:
			b.WriteString(`\t`)
		case r == 10:
			b.WriteString(`\n`)
		case r == 12:
			b.WriteString(`\f`)
		case r == 13:
			b.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func rcUTF16(s string) []uint16 {
	var units []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			units = append(units, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF))) // #nosec G115 -- r is below 0x100000 here, so both units fit 16 bits
			continue
		}
		units = append(units, uint16(r)) // #nosec G115 -- r is below 0x10000 here
	}
	return units
}

func rcUTF16Less(a, b string) bool {
	ua, ub := rcUTF16(a), rcUTF16(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func rcSerialize(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case *big.Int:
		b.WriteString(x.String())
	case string:
		if rcHasSurrogate(x) {
			rcRaise("ValueError", "surrogates not allowed")
		}
		rcJCSString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			rcSerialize(b, e)
		}
		b.WriteByte(']')
	case *rcObj:
		keys := append([]string(nil), x.keys...)
		for _, k := range keys {
			if rcHasSurrogate(k) {
				rcRaise("ValueError", "surrogates not allowed")
			}
		}
		sort.Slice(keys, func(i, j int) bool { return rcUTF16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			rcJCSString(b, k)
			b.WriteByte(':')
			rcSerialize(b, x.m[k])
		}
		b.WriteByte('}')
	}
}

// rcJCS is jcs(): the RFC 8785 bytes of a parsed value.
func rcJCS(v any) []byte {
	var b bytes.Buffer
	rcSerialize(&b, v)
	return b.Bytes()
}

func rcFileRef(data []byte) string { return "sha256:" + sha(data) }

func rcRefOf(v any) string { return rcFileRef(rcJCS(v)) }

// rcCurveP is 2**255 - 19, the field the Ed25519 curve is defined over.
var rcCurveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// rcPublicKeyDecodes is whether the reference's point decompression accepts a
// public key: a y below the field prime, and no sign bit on a point whose x is
// zero. crypto/ed25519 accepts the encodings the reference refuses.
func rcPublicKeyDecodes(pub []byte) bool {
	le := make([]byte, len(pub))
	for i, b := range pub {
		le[len(pub)-1-i] = b
	}
	sign := le[0]&0x80 != 0
	le[0] &= 0x7F
	y := new(big.Int).SetBytes(le)
	if y.Cmp(rcCurveP) >= 0 {
		return false
	}
	zeroX := y.Cmp(big.NewInt(1)) == 0 || y.Cmp(new(big.Int).Sub(rcCurveP, big.NewInt(1))) == 0
	return !zeroX || !sign
}

// rcEdVerify is the signature check. It is a variable so that the differential test can
// look past signatures and reach the rules behind them; nothing else assigns it.
var rcEdVerify = rcEd25519Verify

// rcEd25519Verify is ed25519_verify of the reference rail.
func rcEd25519Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !rcPublicKeyDecodes(pub) {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// rcFromHex is bytes.fromhex: pairs of hex digits, with ASCII whitespace
// allowed between pairs.
func rcFromHex(s string) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, false
		}
		hi, lo := rcHexVal(s[i]), rcHexVal(s[i+1])
		if hi < 0 || lo < 0 {
			return nil, false
		}
		out = append(out, byte(hi<<4|lo)) // #nosec G115 -- hi and lo are base64 sextets, so the byte is at most 255
		i += 2
	}
	return out, true
}

func rcHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// rcB64 is base64.b64decode(s, validate=True): ASCII only, the alphabet only,
// correct padding and nothing after it. Unused trailing bits are not checked.
func rcB64(s string) ([]byte, bool) {
	if len(s)%4 != 0 {
		return nil, false
	}
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 {
		return nil, false
	}
	out, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil || strings.ContainsAny(body, "\r\n") {
		return nil, false
	}
	return out, true
}

func rcB64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

var (
	rcHex64Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rcRefRe       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rcPaymentRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	rcSecondsGate = regexp.MustCompile(`^\p{Nd}{4}-\p{Nd}{2}-\p{Nd}{2}T\p{Nd}{2}:\p{Nd}{2}:\p{Nd}{2}Z$`)
	rcMillisGate  = regexp.MustCompile(`^\p{Nd}{4}-\p{Nd}{2}-\p{Nd}{2}T\p{Nd}{2}:\p{Nd}{2}:\p{Nd}{2}\.\p{Nd}{3}Z$`)
	// rcStrptimeDate is the date and time part of the regular expression
	// datetime.strptime builds for "%Y-%m-%dT%H:%M:%S": only the year and the
	// second place of the other fields take a non-ASCII decimal digit.
	rcStrptimeDate = `(\p{Nd}{4})-(1[0-2]|0[1-9]|[1-9])-(3[0-1]|[1-2]\p{Nd}|0[1-9]|[1-9]| [1-9])` +
		`T(2[0-3]|[0-1]\p{Nd}|\p{Nd}):([0-5]\p{Nd}|\p{Nd}):(6[0-1]|[0-5]\p{Nd}|\p{Nd})`
	rcStrptimeSeconds = regexp.MustCompile(`(?i)^` + rcStrptimeDate + `Z$`)
	rcStrptimeFrac    = regexp.MustCompile(`(?i)^` + rcStrptimeDate + `\.([0-9]{1,6})Z$`)
)

func rcMatch(re *regexp.Regexp, v any) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

// rcIsHex64 is bool(_HEX64.match(str(v))).
func rcIsHex64(v any) bool { return rcHex64Re.MatchString(rcStr(v)) }

// rcASCIIID is ascii_id: a non-empty str of printable ASCII.
func rcASCIIID(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// rcDigitValue is int() of one decimal digit of any script: every range of the
// Nd category starts at a zero and holds whole sets of ten.
func rcDigitValue(r rune) int {
	for _, rg := range unicode.Nd.R16 {
		if rune(rg.Lo) <= r && r <= rune(rg.Hi) { // #nosec G115 -- the Nd table holds code points below 0x110000
			return int(r-rune(rg.Lo)) % 10
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if rune(rg.Lo) <= r && r <= rune(rg.Hi) { // #nosec G115 -- the Nd table holds code points below 0x110000
			return int(r-rune(rg.Lo)) % 10
		}
	}
	return 0
}

// rcAtoi is int() of a field the strptime pattern matched: decimal digits of any
// script, with the one leading space a day field may carry.
func rcAtoi(field string) int {
	n := 0
	for _, r := range strings.TrimSpace(field) {
		n = n*10 + rcDigitValue(r)
	}
	return n
}

// rcDateTime builds the UTC instant datetime.strptime would, or raises
// ValueError for a field datetime refuses.
func rcDateTime(parts []string, micro int) time.Time {
	var n [6]int
	for i := range n {
		n[i] = rcAtoi(parts[i])
	}
	t := time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], micro*1000, time.UTC)
	if n[0] < 1 || n[1] < 1 || n[1] > 12 || n[5] > 59 || t.Day() != n[2] || t.Hour() != n[3] || t.Minute() != n[4] {
		rcRaise("ValueError", "timestamp out of range")
	}
	return t
}

// rcTSs is ts_s: a whole-second UTC timestamp.
func rcTSs(v any) time.Time {
	s, ok := v.(string)
	if !ok || !rcSecondsGate.MatchString(s) {
		rcRaise("ValueError", "timestamp")
	}
	m := rcStrptimeSeconds.FindStringSubmatch(s)
	if m == nil {
		rcRaise("ValueError", "time data does not match format")
	}
	return rcDateTime(m[1:7], 0)
}

// rcTSms is ts_ms: a millisecond UTC timestamp.
func rcTSms(v any) time.Time {
	s, ok := v.(string)
	if !ok || !rcMillisGate.MatchString(s) {
		rcRaise("ValueError", "timestamp")
	}
	return rcTSexact(s)
}

// rcTSexact is ts_exact: datetime.strptime(str(v), "%Y-%m-%dT%H:%M:%S.%fZ"),
// which takes one-digit fields, any case of T and Z, and one to six fractional
// digits.
func rcTSexact(v any) time.Time {
	m := rcStrptimeFrac.FindStringSubmatch(rcStr(v))
	if m == nil {
		rcRaise("ValueError", "time data does not match format")
	}
	micro, _ := strconv.Atoi(m[7] + strings.Repeat("0", 6-len(m[7])))
	return rcDateTime(m[1:7], micro)
}

// rcCeilS is ceil_s; one second past the last representable instant is the
// OverflowError CPython raises.
func rcCeilS(t time.Time) time.Time {
	if t.Nanosecond() == 0 {
		return t
	}
	up := t.Truncate(time.Second).Add(time.Second)
	if up.Year() > 9999 {
		rcRaise("OverflowError", "date value out of range")
	}
	return up
}

func rcFloorS(t time.Time) time.Time { return t.Truncate(time.Second) }

// rcSplitLines is bytes.splitlines(): lines end at \n, \r or \r\n, and a final
// terminator does not start another line.
func rcSplitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' && data[i] != '\r' {
			continue
		}
		lines = append(lines, data[start:i])
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// rcBytesFromHex is bytes.fromhex(v): a non-str raises TypeError, a malformed str
// ValueError.
func rcBytesFromHex(v any) []byte {
	s, ok := v.(string)
	if !ok {
		rcRaise("TypeError", "fromhex() argument must be str")
	}
	out, good := rcFromHex(s)
	if !good {
		rcRaise("ValueError", "non-hexadecimal number found in fromhex() arg")
	}
	return out
}

// rcGetDefault is v.get(key, def) on a dict: the default stands in only for a
// member that is not there, so a member holding None stays None.
func rcGetDefault(v any, key string, def any) any {
	obj := rcObjOf(v)
	if got, present := obj.m[key]; present {
		return got
	}
	return def
}

// rcFirst is v[0] for the values a JSON document holds.
func rcFirst(v any) any {
	switch x := v.(type) {
	case []any:
		if len(x) == 0 {
			rcRaise("IndexError", "list index out of range")
		}
		return x[0]
	case string:
		if x == "" {
			rcRaise("IndexError", "string index out of range")
		}
		return string([]rune(x)[0])
	case *rcObj:
		rcRaise("KeyError", "0")
	}
	rcRaise("TypeError", "object is not subscriptable")
	return nil
}

// item is d[key]: a key that is not there raises KeyError.
func (d *rcDict) item(key any) any {
	got, ok := d.get(key)
	if !ok {
		rcRaise("KeyError", "key")
	}
	return got
}

// rcSet is a Python set of parsed values.
type rcSet struct{ items []any }

func (s *rcSet) has(x any) bool {
	rcHashable(x)
	for _, e := range s.items {
		if rcEq(e, x) {
			return true
		}
	}
	return false
}

func (s *rcSet) add(x any) {
	if !s.has(x) {
		s.items = append(s.items, x)
	}
}

// rcStrMapHas is x in m for a dict with str keys.
func rcStrMapHas[V any](m map[string]V, x any) bool {
	_, present := rcStrMapGet(m, x)
	return present
}

// rcStrMapGet is m.get(x) for a dict with str keys.
func rcStrMapGet[V any](m map[string]V, x any) (V, bool) {
	var zero V
	rcHashable(x)
	s, ok := x.(string)
	if !ok {
		return zero, false
	}
	got, present := m[s]
	return got, present
}
