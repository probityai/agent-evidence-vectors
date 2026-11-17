package corpusreaders

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func init() { register(catalogTrust{}) }

// catalogTrust judges corpora/vectors-catalog-trust-manifest/: one signed ARD or AI
// Catalog object per member, judged under the construction its context names. The
// checks and their order are profiles/catalog-trust-manifest.md; the first that fails
// names the reason. This is a second implementation of the Python reference reader
// (agent_evidence_vectors/catalogtrust.py) written from the profile, with its own
// JSON parser, RFC 8785 writer, ES256 and Ed25519, so a case whose verdict depends
// on a reading the two disagree on shows up as a finding here.
type catalogTrust struct{}

func (catalogTrust) Suite() string { return "catalog-trust-manifest/v1" }

const (
	ctDraft    = "ard-draft-bu-00"
	ctField    = "field-whole-entry"
	ctAIC      = "ai-catalog-2026-11"
	ctSnapshot = "ai-catalog-snapshot"
	ctSafe     = 9007199254740991.0
	ctInToto   = "https://in-toto.io/Statement/v1"
	ctDSSEType = "application/vnd.in-toto+json"
)

var (
	ctTyp = map[string]string{ctAIC: "ai-catalog-trust-manifest+jws",
		ctSnapshot: "ai-catalog+jws"}
	ctAlgs = map[string][]string{ctDraft: {"ES256", "EdDSA"}, ctField: {"ES256", "EdDSA"},
		ctAIC: {"ES256"}, ctSnapshot: {"ES256"}}
	ctLabel    = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	ctRootDID  = regexp.MustCompile(`\Adid:web:(?:` + ctLabel + `\.)*` + ctLabel + `\z`)
	ctFragment = regexp.MustCompile(`\A(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+\z`)
	ctB64URL   = regexp.MustCompile(`\A[A-Za-z0-9_-]*\z`)
	ctURL      = regexp.MustCompile(`\A([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(?:[/?#].*)?\z`)
	ctDSSEStd  = regexp.MustCompile(`\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z`)
	ctDSSEURL  = regexp.MustCompile(`\A(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?\z`)
	ctTime     = regexp.MustCompile(`\A([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):` +
		`([0-9]{2})(\.[0-9]+)?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))\z`)
	ctPrivateJWK = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

	errCTDuplicate = errors.New("duplicate member")
	errCTInvalid   = errors.New("not JSON")
)

// ctObject keeps member order for the parser and a map for lookups.
type ctObject struct {
	keys []string
	vals map[string]any
}

func (o *ctObject) get(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[key]
	return v, ok
}

func (o *ctObject) str(key string) (string, bool) {
	v, _ := o.get(key)
	s, ok := v.(string)
	return s, ok
}

func (o *ctObject) obj(key string) *ctObject {
	v, _ := o.get(key)
	child, _ := v.(*ctObject)
	return child
}

// without is a shallow copy of o lacking key.
func (o *ctObject) without(key string) *ctObject {
	out := &ctObject{vals: map[string]any{}}
	for _, k := range o.keys {
		if k != key {
			out.keys = append(out.keys, k)
			out.vals[k] = o.vals[k]
		}
	}
	return out
}

func (o *ctObject) with(key string, value any) *ctObject {
	out := o.without(key)
	out.keys = append(out.keys, key)
	out.vals[key] = value
	return out
}

// ctNumber is a JSON number as the double a parser reads it as.
type ctNumber float64

// --------------------------------------------------------------------------- JSON

type ctParser struct {
	data []byte
	pos  int
}

// ctParse reads one JSON value. A repeated member name is reported when its object
// closes, so a fault inside a later member value of the same object is reported
// first, as a scanning parser meets it.
func ctParse(data []byte) (any, error) {
	if !utf8.Valid(data) || ctTooDeep(data) {
		return nil, errCTInvalid
	}
	p := &ctParser{data: data}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.data) {
		return nil, errCTInvalid
	}
	return v, nil
}

// ctMaxNesting bounds the arrays and objects open at once; a deeper text is refused
// before it is parsed, so every reader holds the same values (json_invalid).
const ctMaxNesting = 64

// ctTooDeep scans the bytes for more than ctMaxNesting open arrays and objects. The
// structural characters are ASCII, and no UTF-8 sequence holds an ASCII byte.
func ctTooDeep(data []byte) bool {
	depth, inString, escaped := 0, false, false
	for _, b := range data {
		switch {
		case inString && escaped:
			escaped = false
		case inString && b == '\\':
			escaped = true
		case inString && b == '"':
			inString = false
		case inString:
		case b == '"':
			inString = true
		case b == '[' || b == '{':
			depth++
			if depth > ctMaxNesting {
				return true
			}
		case b == ']' || b == '}':
			depth--
		}
	}
	return false
}

func (p *ctParser) space() {
	for p.pos < len(p.data) && strings.IndexByte(" \t\n\r", p.data[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *ctParser) value() (any, error) {
	p.space()
	if p.pos >= len(p.data) {
		return nil, errCTInvalid
	}
	switch p.data[p.pos] {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		return p.string()
	case 't':
		return p.literal("true", true)
	case 'f':
		return p.literal("false", false)
	case 'n':
		return p.literal("null", nil)
	default:
		return p.number()
	}
}

func (p *ctParser) literal(word string, v any) (any, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return nil, errCTInvalid
	}
	p.pos += len(word)
	return v, nil
}

func (p *ctParser) object() (any, error) {
	p.pos++
	out := &ctObject{vals: map[string]any{}}
	duplicate := false
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, errCTInvalid
		}
		key, err := p.string()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, errCTInvalid
		}
		p.pos++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, seen := out.vals[key]; seen {
			duplicate = true
		} else {
			out.keys = append(out.keys, key)
		}
		out.vals[key] = v
		p.space()
		if p.pos >= len(p.data) {
			return nil, errCTInvalid
		}
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.data[p.pos] != '}' {
			return nil, errCTInvalid
		}
		p.pos++
		if duplicate {
			return nil, errCTDuplicate
		}
		return out, nil
	}
}

func (p *ctParser) array() (any, error) {
	p.pos++
	out := []any{}
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return out, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.space()
		if p.pos >= len(p.data) {
			return nil, errCTInvalid
		}
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.data[p.pos] != ']' {
			return nil, errCTInvalid
		}
		p.pos++
		return out, nil
	}
}

// string decodes a JSON string. A \u escape naming a lone surrogate is kept as its
// three-byte generalized UTF-8 form, so the value still differs from U+FFFD and the
// RFC 8785 writer can refuse it.
func (p *ctParser) string() (string, error) {
	p.pos++
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", errCTInvalid
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", errCTInvalid
		case c != '\\':
			out = append(out, c)
			p.pos++
			continue
		}
		var err error
		if out, err = p.escape(out); err != nil {
			return "", err
		}
	}
}

var ctSimpleEscapes = map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f',
	'n': '\n', 'r': '\r', 't': '\t'}

// escape decodes the escape sequence at p.pos onto out; a high surrogate followed by a
// low one is one code point, and any other surrogate stays lone.
func (p *ctParser) escape(out []byte) ([]byte, error) {
	if p.pos+1 >= len(p.data) {
		return nil, errCTInvalid
	}
	escape := p.data[p.pos+1]
	p.pos += 2
	if simple, ok := ctSimpleEscapes[escape]; ok {
		return append(out, simple), nil
	}
	if escape != 'u' {
		return nil, errCTInvalid
	}
	unit, ok := p.hex4()
	if !ok {
		return nil, errCTInvalid
	}
	if unit >= 0xD800 && unit < 0xDC00 && p.pos+1 < len(p.data) &&
		p.data[p.pos] == '\\' && p.data[p.pos+1] == 'u' {
		save := p.pos
		p.pos += 2
		if low, ok := p.hex4(); ok && low >= 0xDC00 && low <= 0xDFFF {
			return utf8.AppendRune(out, utf16.DecodeRune(rune(unit), rune(low))), nil
		}
		p.pos = save
	}
	return ctAppendWTF8(out, rune(unit)), nil
}

func (p *ctParser) hex4() (uint16, bool) {
	if p.pos+4 > len(p.data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(p.data[p.pos:p.pos+4]), 16, 16)
	if err != nil || strings.ContainsAny(string(p.data[p.pos:p.pos+4]), "+-") {
		return 0, false
	}
	p.pos += 4
	return uint16(n), true // #nosec G115 -- ParseUint with bitSize 16 bounds n
}

func ctAppendWTF8(out []byte, r rune) []byte {
	if r >= 0xD800 && r <= 0xDFFF {
		return append(out, byte(0xE0|r>>12), // #nosec G115 -- r < 0xE000, so r>>12 < 0x0E
			byte(0x80|(r>>6)&0x3F), byte(0x80|r&0x3F)) // #nosec G115 -- masked to six bits
	}
	return utf8.AppendRune(out, r)
}

var ctNumberText = regexp.MustCompile(`\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`)

func (p *ctParser) number() (any, error) {
	text := ctNumberText.Find(p.data[p.pos:])
	if text == nil {
		return nil, errCTInvalid
	}
	p.pos += len(text)
	f, err := strconv.ParseFloat(string(text), 64)
	var numErr *strconv.NumError
	if err != nil && (!errors.As(err, &numErr) || numErr.Err != strconv.ErrRange) {
		return nil, errCTInvalid
	}
	return ctNumber(f), nil
}

// --------------------------------------------------------------------------- RFC 8785

var errCTNotInteroperable = errors.New("number_not_interoperable")
var errCTNoCanonicalForm = errors.New("no_canonical_form")

func ctNumbersFirst(v any) error {
	switch t := v.(type) {
	case ctNumber:
		if math.Abs(float64(t)) > ctSafe {
			return errCTNotInteroperable
		}
	case []any:
		for _, item := range t {
			if err := ctNumbersFirst(item); err != nil {
				return err
			}
		}
	case *ctObject:
		for _, k := range t.keys {
			if err := ctNumbersFirst(t.vals[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

func ctCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := ctWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ctWrite(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case ctNumber:
		text, err := ctNumberForm(float64(t))
		if err != nil {
			return err
		}
		buf.WriteString(text)
	case string:
		return ctWriteString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := ctWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case *ctObject:
		keys := append([]string(nil), t.keys...)
		sort.SliceStable(keys, func(i, j int) bool { return ctUTF16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := ctWriteString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := ctWrite(buf, t.vals[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errCTNoCanonicalForm
	}
	return nil
}

// ctUTF16Less orders member names by UTF-16 code unit, as RFC 8785 section 3.2.3 does.
func ctUTF16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func ctWriteString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errCTNoCanonicalForm // a lone surrogate has no UTF-8 form
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case r < 0x20:
			escapes := map[rune]string{8: `\b`, 9: `\t`, 10: `\n`, 12: `\f`, 13: `\r`}
			if e, ok := escapes[r]; ok {
				buf.WriteString(e)
			} else {
				fmt.Fprintf(buf, `\u%04x`, r)
			}
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return nil
}

// ctNumberForm is ECMAScript Number::toString for a finite double (RFC 8785 3.2.2.3).
func ctNumberForm(v float64) (string, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "", errCTNoCanonicalForm
	}
	if v == 0 {
		return "0", nil
	}
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	sci := strconv.FormatFloat(v, 'e', -1, 64) // d.ddde±XX, shortest round trip
	mantissa, exponent, _ := strings.Cut(sci, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(exponent)
	k, n := len(digits), exp+1
	var text string
	switch {
	case k <= n && n <= 21:
		text = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		text = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		text = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		fraction := ""
		if k > 1 {
			fraction = "." + digits[1:]
		}
		signE := "+"
		if e < 0 {
			signE, e = "-", -e
		}
		text = digits[:1] + fraction + "e" + signE + strconv.Itoa(e)
	}
	return sign + text, nil
}

// ctEqual is value equality as the Python reference compares decoded JSON.
func ctEqual(a, b any) bool {
	switch x := a.(type) {
	case *ctObject:
		y, ok := b.(*ctObject)
		if !ok || len(x.vals) != len(y.vals) {
			return false
		}
		for k, v := range x.vals {
			w, has := y.vals[k]
			if !has || !ctEqual(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !ctEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// --------------------------------------------------------------------------- helpers

func ctB64URLDecode(text any) ([]byte, bool) {
	s, ok := text.(string)
	if !ok || !ctB64URL.MatchString(s) || len(s)%4 == 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

func ctIndex(v any, i int) any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	if i < 0 || i >= len(list) {
		return nil
	}
	return list[i]
}

func ctIn(v any, set []string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, item := range set {
		if s == item {
			return true
		}
	}
	return false
}

func ctReject(reason string) scDecision { return scDecision{"reject", reason} }

type ctKey struct {
	alg string
	ed  ed25519.PublicKey
	ec  *ecdsa.PublicKey
}

func ctOnCurve(x, y *big.Int) bool {
	curve := elliptic.P256().Params()
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(curve.P) >= 0 || y.Cmp(curve.P) >= 0 {
		return false
	}
	// y^2 = x^3 - 3x + b (mod p)
	lhs := new(big.Int).Mul(y, y)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Sub(rhs, new(big.Int).Mul(big.NewInt(3), x))
	rhs.Add(rhs, curve.B)
	return lhs.Sub(lhs, rhs).Mod(lhs, curve.P).Sign() == 0
}

func ctPublicKey(method *ctObject) ctKey {
	jwk := method.obj("publicKeyJwk")
	if jwk == nil {
		return ctKey{alg: "none"}
	}
	kty, _ := jwk.str("kty")
	crv, _ := jwk.str("crv")
	switch {
	case kty == "OKP" && crv == "Ed25519":
		x, _ := jwk.get("x")
		raw, ok := ctB64URLDecode(x)
		if ok && len(raw) == ed25519.PublicKeySize {
			return ctKey{alg: "EdDSA", ed: ed25519.PublicKey(raw)}
		}
	case kty == "EC" && crv == "P-256":
		xv, hasX := jwk.get("x")
		yv, hasY := jwk.get("y")
		xr, okX := ctB64URLDecode(xv)
		yr, okY := ctB64URLDecode(yv)
		if hasX && hasY && okX && okY {
			x, y := new(big.Int).SetBytes(xr), new(big.Int).SetBytes(yr)
			if ctOnCurve(x, y) {
				return ctKey{alg: "ES256", ec: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}}
			}
		}
	}
	return ctKey{alg: "none"}
}

// ctJWKFault reports a JWK that is not a public key fit to verify alg.
func ctJWKFault(method *ctObject, alg any) bool {
	jwk := method.obj("publicKeyJwk")
	if jwk == nil {
		return false
	}
	for _, name := range ctPrivateJWK {
		if _, has := jwk.get(name); has {
			return true
		}
	}
	if use, has := jwk.get("use"); has && use != "sig" {
		return true
	}
	if ops, has := jwk.get("key_ops"); has {
		list, ok := ops.([]any)
		found := false
		for _, op := range list {
			found = found || op == "verify"
		}
		if !ok || !found {
			return true
		}
	}
	if a, has := jwk.get("alg"); has && a != alg {
		return true
	}
	if kty, _ := jwk.str("kty"); kty == "EC" {
		xv, _ := jwk.get("x")
		yv, _ := jwk.get("y")
		xr, okX := ctB64URLDecode(xv)
		yr, okY := ctB64URLDecode(yv)
		return !okX || !okY || len(xr) != 32 || len(yr) != 32
	}
	return false
}

func ctVerify(key ctKey, message, signature []byte) bool {
	switch key.alg {
	case "EdDSA":
		return len(signature) == ed25519.SignatureSize && ed25519.Verify(key.ed, message, signature)
	case "ES256":
		if len(signature) != 64 {
			return false
		}
		digest := sha256.Sum256(message)
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(key.ec, digest[:], r, s)
	}
	return false
}

// ctVerifyDSSE checks a DSSE signature: as JWS, and for ES256 also the strict DER
// ECDSA-Sig-Value (RFC 3279 section 2.2.3) sigstore and in-toto signers write.
func ctVerifyDSSE(key ctKey, message, signature []byte) bool {
	if ctVerify(key, message, signature) {
		return true
	}
	if key.alg != "ES256" {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(key.ec, digest[:], signature)
}

func ctAbsolute(ref any, base any) any {
	r, ok := ref.(string)
	b, okBase := base.(string)
	if ok && okBase && strings.HasPrefix(r, "#") {
		return b + r
	}
	return ref
}

// ctMethods lists every verification method with its id made absolute (DID Core
// 3.2.2), and the ids the assertionMethod relationship authorizes.
func ctMethods(document *ctObject) ([]*ctObject, map[string]bool) {
	base, _ := document.get("id")
	var methods []*ctObject
	assertion := map[string]bool{}
	listed, _ := document.get("verificationMethod")
	for _, item := range ctList(listed) {
		if m, ok := item.(*ctObject); ok {
			if id, isStr := m.str("id"); isStr {
				methods = append(methods, m.with("id", ctAbsolute(id, base)))
			}
		}
	}
	granted, _ := document.get("assertionMethod")
	for _, item := range ctList(granted) {
		switch t := item.(type) {
		case string:
			if id, ok := ctAbsolute(t, base).(string); ok {
				assertion[id] = true
			}
		case *ctObject:
			if id, isStr := t.str("id"); isStr {
				absolute := ctAbsolute(id, base).(string)
				assertion[absolute] = true
				methods = append(methods, t.with("id", absolute))
			}
		}
	}
	return methods, assertion
}

func ctList(v any) []any {
	list, _ := v.([]any)
	return list
}

func ctSelected(methods []*ctObject, kid any) []*ctObject {
	var out []*ctObject
	for _, m := range methods {
		if id, _ := m.get("id"); id == kid && kid != nil {
			out = append(out, m)
		}
	}
	return out
}

// ctInstant is an RFC 3339 date-time as exact seconds since 1970, or nil.
func ctInstant(v any) *big.Rat {
	text, ok := v.(string)
	if !ok {
		return nil
	}
	m := ctTime.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	n := func(i int) int { value, _ := strconv.Atoi(m[i]); return value }
	year, month, day, hour, minute, second := n(1), n(2), n(3), n(4), n(5), n(6)
	if month < 1 || month > 12 || day < 1 || day > ctDaysInMonth(year, month) || hour > 23 ||
		minute > 59 || second > 60 {
		return nil
	}
	total := ctDaysFromCivil(year, month, day)*86400 + int64(hour*3600+minute*60+second)
	seconds := new(big.Rat).SetInt64(total)
	if m[7] != "" {
		fraction, _ := new(big.Rat).SetString("0" + m[7])
		seconds.Add(seconds, fraction)
	}
	if m[8] == "" {
		if n(10) > 23 || n(11) > 59 {
			return nil
		}
		offset := int64((n(10)*60 + n(11)) * 60)
		if m[9] == "-" {
			offset = -offset
		}
		total -= offset
		seconds.Sub(seconds, new(big.Rat).SetInt64(offset))
	}
	if second == 60 && !ctLeapSecond(total-1) {
		return nil
	}
	return seconds
}

// ctLeapSecondDays are the UTC days that end in a leap second, from the IERS list
// (leap-seconds.list, file hash a9bad145 84c31c70 758402aa b37bfd54 5923836a, expires 28
// June 2027). A second of 60 names a real instant only at 23:59:60 UTC on one of them.
var ctLeapSecondDays = func() map[int64]bool {
	days := map[int64]bool{}
	for _, d := range [][3]int{{1972, 6, 30}, {1972, 12, 31}, {1973, 12, 31}, {1974, 12, 31},
		{1975, 12, 31}, {1976, 12, 31}, {1977, 12, 31}, {1978, 12, 31}, {1979, 12, 31},
		{1981, 6, 30}, {1982, 6, 30}, {1983, 6, 30}, {1985, 6, 30}, {1987, 12, 31},
		{1989, 12, 31}, {1990, 12, 31}, {1992, 6, 30}, {1993, 6, 30}, {1994, 6, 30},
		{1995, 12, 31}, {1997, 6, 30}, {1998, 12, 31}, {2005, 12, 31}, {2008, 12, 31},
		{2012, 6, 30}, {2015, 6, 30}, {2016, 12, 31}} {
		days[ctDaysFromCivil(d[0], d[1], d[2])] = true
	}
	return days
}()

// ctLeapSecond reports whether before (whole UTC seconds since 1970) is 23:59:59 on a
// leap day, so the second after it is 23:59:60.
func ctLeapSecond(before int64) bool {
	day, ofDay := before/86400, before%86400
	if ofDay < 0 {
		day, ofDay = day-1, ofDay+86400
	}
	return ofDay == 86399 && ctLeapSecondDays[day]
}

func ctDaysInMonth(year, month int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

func ctDaysFromCivil(year, month, day int) int64 {
	y := int64(year)
	if month <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := int64(month + 9)
	if month > 2 {
		mp = int64(month - 3)
	}
	doy := (153*mp+2)/5 + int64(day) - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

// --------------------------------------------------------------------------- the reader

func (catalogTrust) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v drVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		caseDir := filepath.Join(dir, v.Path)
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = acFileFindings(caseDir, v.Files)
		got, err := ctDecide(caseDir)
		switch {
		case err != nil:
			member.Findings = append(member.Findings, err.Error())
		case got != v.Expected:
			member.Findings = append(member.Findings, fmt.Sprintf(
				"derived %s/%s, the manifest declares %s/%s",
				got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// ctCase is one member being judged; each method applies a run of consecutive checks
// and returns the first reason that fails, or "".
type ctCase struct {
	dir          string
	construction string
	role         string
	entryIndex   int
	manifest     int
	context      map[string]any
	catalog      *ctObject
	documents    *ctObject
	obj          *ctObject
	entry        *ctObject
	parts        []string
	header       *ctObject
	signature    []byte
	alg          any
	identity     string
	kid          string
	key          ctKey
	artifact     []byte
	publisher    string
}

// ctNoIndex stands for an index the context gives as something other than a
// non-negative integer: it selects nothing (1.0 is the integer 1; -1, 0.5 and true are
// not indexes).
const ctNoIndex = math.MinInt

func ctIndexOf(context map[string]any, name string) int {
	v, present := context[name]
	if !present {
		return 0
	}
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f < 0 || f > 1<<31 {
		return ctNoIndex
	}
	return int(f)
}

func ctDecide(caseDir string) (scDecision, error) {
	var context map[string]any
	if err := scReadJSON(caseDir, "context.json", &context); err != nil {
		return scDecision{}, err
	}
	c := &ctCase{dir: caseDir, context: context}
	reason, err := c.load()
	if err != nil {
		return scDecision{}, err
	}
	for _, step := range []func() string{c.signatureObject, c.readHeader, c.critical,
		c.signer, c.selectKey, c.signedBytes} {
		if reason != "" {
			break
		}
		reason = step()
	}
	if reason == "" && c.construction == ctSnapshot {
		reason = c.times(c.catalog.obj("signature"))
		if reason == "" {
			return scDecision{"accept", "snapshot_signature_valid"}, nil
		}
	}
	for _, step := range []func() string{c.subject, c.artifactDigest, c.origin,
		c.attestations, c.publisherRule, c.manifestTimes} {
		if reason != "" {
			break
		}
		reason = step()
	}
	if reason != "" {
		return ctReject(reason), nil
	}
	return scDecision{"accept", "signature_covers_release"}, nil
}

// load applies the gates: a closed construction and role, and JSON the reader can hold.
func (c *ctCase) load() (string, error) {
	c.construction, _ = c.context["construction"].(string)
	if _, known := ctAlgs[c.construction]; !known {
		return "construction_unknown", nil
	}
	c.role, _ = c.context["role"].(string)
	if c.role != "publisher" && c.role != "contributor" {
		return "role_unknown", nil
	}
	c.entryIndex, c.manifest = ctIndexOf(c.context, "entry"), ctIndexOf(c.context, "manifest")
	var values [2]any
	for i, name := range []string{"catalog.json", "did-documents.json"} {
		body, err := readIn(c.dir, name)
		if err != nil {
			return "", fmt.Errorf("%s cannot be read: %w", name, err)
		}
		value, err := ctParse(body)
		if errors.Is(err, errCTDuplicate) {
			return "duplicate_member", nil
		}
		if err != nil {
			return "json_invalid", nil
		}
		values[i] = value
	}
	catalog, okCatalog := values[0].(*ctObject)
	documents, okDocuments := values[1].(*ctObject)
	if !okCatalog || !okDocuments {
		return "json_invalid", nil
	}
	c.catalog, c.documents = catalog, documents
	return "", nil
}

func (c *ctCase) ardShaped() bool { return c.construction == ctDraft || c.construction == ctField }

func (c *ctCase) entryAt() *ctObject {
	entries, _ := c.catalog.get("entries")
	if c.entryIndex == ctNoIndex {
		return nil
	}
	entry, _ := ctIndex(entries, c.entryIndex).(*ctObject)
	return entry
}

func (c *ctCase) signatureObject() string {
	var obj *ctObject
	switch {
	case c.construction == ctSnapshot:
		if c.catalog.obj("signature") != nil {
			obj = c.catalog
		}
	case c.ardShaped():
		obj = c.entryAt().obj("trustManifest")
	case c.manifest != ctNoIndex:
		manifests, _ := c.entryAt().get("trustManifests")
		obj, _ = ctIndex(manifests, c.manifest).(*ctObject)
	}
	var jws string
	var ok bool
	if c.ardShaped() {
		jws, ok = obj.str("signature")
	} else {
		jws, ok = obj.obj("signature").str("jws")
	}
	if obj == nil || !ok {
		return "signature_missing"
	}
	c.obj, c.parts, c.entry = obj, strings.Split(jws, "."), c.entryAt()
	return ""
}

// readHeader applies jws_malformed through key_source_in_header.
func (c *ctCase) readHeader() string {
	if len(c.parts) != 3 || c.parts[1] != "" {
		return "jws_malformed"
	}
	headerBytes, okHeader := ctB64URLDecode(c.parts[0])
	if !okHeader {
		return "jws_malformed"
	}
	headerValue, err := ctParse(headerBytes)
	header, isObject := headerValue.(*ctObject)
	signature, okSig := ctB64URLDecode(c.parts[2])
	if err != nil || !isObject || !okSig {
		return "jws_malformed"
	}
	c.header, c.signature = header, signature
	if b64, has := header.get("b64"); has {
		if _, isBool := b64.(bool); !isBool {
			return "jws_malformed"
		}
	}
	if want, typed := ctTyp[c.construction]; typed {
		if typ, _ := header.get("typ"); typ != want {
			return "typ_missing_or_mismatched"
		}
	}
	c.alg, _ = header.get("alg")
	if !ctIn(c.alg, ctAlgs[c.construction]) {
		return "alg_not_allowed_for_profile"
	}
	for _, name := range []string{"jku", "jwk", "x5u", "x5c"} {
		if _, has := header.get(name); has {
			return "key_source_in_header"
		}
	}
	return ""
}

// critical applies b64_forbidden_for_profile, jws_crit_unsupported and b64_without_crit.
func (c *ctCase) critical() string {
	_, hasB64 := c.header.get("b64")
	if !c.ardShaped() && hasB64 {
		return "b64_forbidden_for_profile"
	}
	crit, _ := c.header.get("crit")
	critList, critIsList := crit.([]any)
	if crit != nil {
		bad := !critIsList || len(critList) == 0
		for _, name := range critList {
			if _, present := c.header.get(fmt.Sprint(name)); name != "b64" || !present {
				bad = true
			}
		}
		if bad {
			return "jws_crit_unsupported"
		}
	}
	declared := false
	for _, name := range critList {
		declared = declared || name == "b64"
	}
	if hasB64 && !declared {
		return "b64_without_crit"
	}
	return ""
}

// signer applies profile_unsupported through did_document_not_identity.
func (c *ctCase) signer() string {
	var identity any
	if c.ardShaped() {
		identity, _ = c.obj.get("identity")
	} else {
		signature := c.obj.obj("signature")
		identity, _ = signature.get("signer")
		if profile, _ := signature.get("profile"); profile != "did-web-v1" {
			return "profile_unsupported"
		}
		id, isStr := identity.(string)
		if !isStr || !ctRootDIDWeb(id) {
			return "signer_not_root_did_web"
		}
	}
	kid, _ := c.header.get("kid")
	kidText, kidIsStr := kid.(string)
	idText, idIsStr := identity.(string)
	if !kidIsStr || !idIsStr || !strings.HasPrefix(kidText, idText+"#") ||
		!ctFragment.MatchString(kidText[len(idText)+1:]) {
		return "kid_not_under_identity"
	}
	c.identity, c.kid = idText, kidText
	document := c.documents.obj(idText)
	if docID, _ := document.get("id"); document == nil || docID != idText {
		return "did_document_not_identity"
	}
	return ""
}

// selectKey applies kid_not_in_did_document through alg_key_mismatch.
func (c *ctCase) selectKey() string {
	methods, assertion := ctMethods(c.documents.obj(c.identity))
	selected := ctSelected(methods, c.kid)
	switch {
	case len(selected) == 0:
		return "kid_not_in_did_document"
	case len(selected) > 1:
		return "verification_method_ambiguous"
	case !assertion[c.kid]:
		return "key_not_assertion_method"
	}
	method := selected[0]
	if controller, _ := method.get("controller"); !c.ardShaped() && controller != c.identity {
		return "method_controller_mismatch"
	}
	if ctJWKFault(method, c.alg) {
		return "jwk_not_signing_key"
	}
	c.key = ctPublicKey(method)
	if c.key.alg != c.alg {
		return "alg_key_mismatch"
	}
	return ""
}

func (c *ctCase) payload() any {
	switch c.construction {
	case ctSnapshot, ctAIC:
		return c.obj.without("additionalSignatures").with("signature",
			c.obj.obj("signature").without("jws"))
	case ctDraft:
		return c.obj.without("signature")
	}
	return c.entry.with("trustManifest", c.entry.obj("trustManifest").without("signature"))
}

// signedBytes applies number_not_interoperable, no_canonical_form and signature_invalid.
func (c *ctCase) signedBytes() string {
	signed := c.payload()
	if ctNumbersFirst(signed) != nil {
		return "number_not_interoperable"
	}
	body, err := ctCanonical(signed)
	if err != nil {
		return "no_canonical_form"
	}
	message := []byte(c.parts[0] + ".")
	if b64, _ := c.header.get("b64"); b64 == false {
		message = append(message, body...)
	} else {
		message = append(message, base64.RawURLEncoding.EncodeToString(body)...)
	}
	if !ctVerify(c.key, message, c.signature) {
		return "signature_invalid"
	}
	return ""
}

// subject applies signer_not_contributor through subject_entry_mismatch.
func (c *ctCase) subject() string {
	if contributor, _ := c.obj.get("contributor"); c.construction == ctAIC &&
		contributor != c.identity {
		return "signer_not_contributor"
	}
	subject := c.obj.obj("subject")
	if subject == nil {
		return "subject_missing"
	}
	for _, member := range []string{"identifier", "type"} {
		want, isStr := c.entry.str(member)
		if got, _ := subject.get(member); !isStr || got != want {
			return "subject_entry_mismatch"
		}
	}
	subjectDigest, _ := subject.get("digest")
	entryDigest, _ := c.entry.get("digest")
	subjectVersion, inSubject := subject.get("version")
	entryVersion, inEntry := c.entry.get("version")
	if !ctEqual(subjectDigest, entryDigest) || inSubject != inEntry ||
		!ctEqual(subjectVersion, entryVersion) {
		return "subject_entry_mismatch"
	}
	return ""
}

// artifactDigest applies entry_digest_missing_for_url and artifact_digest_mismatch.
func (c *ctCase) artifactDigest() string {
	entryDigest, hasDigest := c.entry.get("digest")
	_, hasURL := c.entry.get("url")
	if _, hasData := c.entry.get("data"); c.ardShaped() && hasURL == hasData {
		return "entry_delivery_not_one" // draft 3.1: exactly one of url and data
	}
	if !hasDigest && (hasURL || c.construction == ctAIC) {
		return "entry_digest_missing_for_url"
	}
	var artifact []byte
	var err error
	if data, hasData := c.entry.get("data"); hasData && !hasURL {
		// AI Catalog "digest": for data, hash the UTF-8 JCS-canonicalized JSON value.
		artifact, err = ctCanonical(data)
	} else {
		artifact, err = readIn(c.dir, "artifact.json")
	}
	if err != nil || entryDigest != "sha256:"+sha(artifact) {
		return "artifact_digest_mismatch"
	}
	c.artifact = artifact
	return ""
}

// origin applies url_origin_unbound (draft 6.2): a url on another origin than the
// publisher's binds only when the artifact there declares the entry identifier.
func (c *ctCase) origin() string {
	identifier, _ := c.entry.str("identifier")
	if parts := strings.Split(identifier, ":"); len(parts) > 3 && parts[0] == "urn" &&
		parts[1] == "air" {
		c.publisher = parts[2]
	}
	if _, hasURL := c.entry.get("url"); !c.ardShaped() || !hasURL {
		return ""
	}
	url, _ := c.entry.str("url")
	if c.publisher != "" && ctHTTPSOrigin(url) == "https://"+strings.ToLower(c.publisher) {
		return ""
	}
	var declared any
	if value, err := ctParse(c.artifact); err == nil && len(c.artifact) > 0 {
		if descriptor, ok := value.(*ctObject); ok {
			declared, _ = descriptor.get("identifier")
		}
	}
	if declared != any(identifier) {
		return "url_origin_unbound"
	}
	return ""
}

// ctRootDIDWeb reports a root did:web DID: labels of a lowercase ASCII domain of at
// most 253 octets (RFC 1035 section 2.3.4) whose last label is not all digits (RFC 3696
// section 2), which also excludes a dotted IPv4 address.
func ctRootDIDWeb(id string) bool {
	if !ctRootDID.MatchString(id) {
		return false
	}
	domain := strings.TrimPrefix(id, "did:web:")
	last := domain[strings.LastIndexByte(domain, '.')+1:]
	return len(domain) <= 253 && strings.Trim(last, "0123456789") != ""
}

// ctHTTPSOrigin is the RFC 6454 origin of an https URL as https://<host>, or "". The
// scheme and host are case-insensitive and 443 is the default port; userinfo (RFC 9110
// section 4.2.4), a percent-escaped host and an IP literal are not read.
func ctHTTPSOrigin(url string) string {
	m := ctURL.FindStringSubmatch(url)
	if m == nil || strings.ToLower(m[1]) != "https" || strings.Contains(m[2], "@") {
		return ""
	}
	host, port, _ := strings.Cut(m[2], ":")
	if host == "" || strings.ContainsAny(host, "%[") || (port != "" && port != "443") {
		return ""
	}
	return "https://" + strings.ToLower(host)
}

// publisherRule applies publisher_not_signer or publisher_authorization_absent.
func (c *ctCase) publisherRule() string {
	if c.role != "publisher" || (c.publisher != "" && c.identity == "did:web:"+c.publisher) {
		return ""
	}
	if c.construction == ctAIC {
		return "publisher_not_signer"
	}
	return "publisher_authorization_absent"
}

func (c *ctCase) manifestTimes() string {
	if c.ardShaped() {
		return c.times(c.obj)
	}
	return c.times(c.obj.obj("signature"))
}

// ctFalsy is a value a Python truth test reads as false.
func ctFalsy(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case string:
		return t == ""
	case float64:
		return t == 0
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// attestations applies attestation_digest_mismatch, attestation_unsigned and
// attestation_transplanted to each vendored attestation the context names.
func (c *ctCase) attestations() string {
	files, _ := c.context["attestationFiles"].([]any)
	items, _ := c.obj.get("attestations")
	entryDigest, _ := c.entry.get("digest")
	for index, item := range ctList(items) {
		var name any
		if index < len(files) {
			name = files[index]
		}
		if ctFalsy(name) {
			continue
		}
		var data []byte
		if text, ok := name.(string); ok && !strings.ContainsAny(text, "/\\\x00") && text != "." &&
			text != ".." && existsIn(c.dir, text) {
			data, _ = readIn(c.dir, text)
		}
		var digest any
		if object, ok := item.(*ctObject); ok {
			digest, _ = object.get("digest")
		}
		if data == nil || digest != "sha256:"+sha(data) {
			return "attestation_digest_mismatch"
		}
		statement := c.signedStatement(data)
		if statement == nil {
			return "attestation_unsigned"
		}
		if !ctNamesDigest(statement, entryDigest) {
			return "attestation_transplanted"
		}
	}
	return ""
}

func ctNamesDigest(statement *ctObject, digest any) bool {
	subjects, _ := statement.get("subject")
	for _, s := range ctList(subjects) {
		if subject, ok := s.(*ctObject); ok {
			if hash, isStr := subject.obj("digest").str("sha256"); isStr && digest == "sha256:"+hash {
				return true
			}
		}
	}
	return false
}

// signedStatement is the in-toto Statement in a DSSE envelope whose signature a key
// authorized by its DID's document verifies, or nil.
func (c *ctCase) signedStatement(data []byte) *ctObject {
	value, err := ctParse(data)
	envelope, ok := value.(*ctObject)
	if err != nil || !ok {
		return nil
	}
	payloadText, okPayload := envelope.str("payload")
	kind, _ := envelope.get("payloadType")
	signatures, isList := func() ([]any, bool) {
		v, _ := envelope.get("signatures")
		list, ok := v.([]any)
		return list, ok
	}()
	body, okBody := ctDSSEDecode(payloadText)
	if !okPayload || !okBody || kind != ctDSSEType || !isList {
		return nil
	}
	pae := append([]byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(ctDSSEType), ctDSSEType, len(body))),
		body...)
	for _, item := range signatures {
		signature, ok := item.(*ctObject)
		if !ok {
			continue
		}
		keyid, _ := signature.str("keyid")
		key := c.dsseKey(keyid)
		sigValue, present := signature.get("sig")
		sigText, isStr := sigValue.(string)
		if !present {
			sigText, isStr = "", true
		}
		raw, okSig := ctDSSEDecode(sigText)
		if key.alg == "none" || !isStr || !okSig || !ctVerifyDSSE(key, pae, raw) {
			continue
		}
		statementValue, err := ctParse(body)
		statement, isObject := statementValue.(*ctObject)
		if typ, _ := statement.get("_type"); err != nil || !isObject || typ != ctInToto {
			return nil
		}
		return statement
	}
	return nil
}

// ctDSSEDecode reads a DSSE base64 field: "Either standard or URL-safe base64
// encodings are allowed. Signers may use either, and verifiers MUST accept either"
// (DSSE protocol.md); one alphabet per string, padded, and nothing else, so the line
// breaks encoding/base64 skips are refused (RFC 4648 section 3.3).
func ctDSSEDecode(text string) ([]byte, bool) {
	var raw []byte
	var err error
	switch {
	case len(text)%4 != 0:
		return nil, false
	case ctDSSEStd.MatchString(text):
		raw, err = base64.StdEncoding.DecodeString(text)
	case ctDSSEURL.MatchString(text):
		raw, err = base64.URLEncoding.DecodeString(text)
	default:
		return nil, false
	}
	return raw, err == nil
}

func (c *ctCase) dsseKey(keyid string) ctKey {
	did, _, found := strings.Cut(keyid, "#")
	document := c.documents.obj(did)
	if id, _ := document.get("id"); !found || document == nil || id != did {
		return ctKey{alg: "none"}
	}
	methods, assertion := ctMethods(document)
	selected := ctSelected(methods, keyid)
	if len(selected) != 1 || !assertion[keyid] {
		return ctKey{alg: "none"}
	}
	key := ctPublicKey(selected[0])
	if ctJWKFault(selected[0], key.alg) {
		return ctKey{alg: "none"}
	}
	return key
}

// times applies timestamp_invalid, issued_in_future and manifest_expired to the
// object carrying issuedAt and expiresAt.
func (c *ctCase) times(holder *ctObject) string {
	issued, _ := holder.get("issuedAt")
	expires, _ := holder.get("expiresAt")
	at, start, end := ctInstant(c.context["at"]), ctInstant(issued), ctInstant(expires)
	if at == nil || (issued == nil && !c.ardShaped()) || (issued != nil && start == nil) ||
		(expires != nil && end == nil) || (start != nil && end != nil && end.Cmp(start) <= 0) {
		return "timestamp_invalid"
	}
	if start != nil && at.Cmp(start) < 0 {
		return "issued_in_future"
	}
	if end != nil && at.Cmp(end) >= 0 {
		return "manifest_expired"
	}
	return ""
}
