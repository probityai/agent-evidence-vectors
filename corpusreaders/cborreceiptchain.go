package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func init() { register(cborReceiptChain{}) }

// cborReceiptChain judges corpora/vectors-cbor-receipt-chain/. Each member is a
// stream of signed CBOR receipts, the consumer's trust inputs and the decision a
// reader must reach. The reader decodes every receipt with a strict CBOR
// decoder, applies the seven checks the Python reader applies in the same
// order, and names the first that fails:
//
//  1. receipt_shape: every line is a well formed four-member receipt;
//  2. signature: every signature verifies under the key the receipt carries;
//  3. signer_pinned: every signing key is one the consumer pinned;
//  4. no_duplicate_receipt: no receipt appears twice;
//  5. single_use: no signed request proof is allowed by two receipts;
//  6. chain_order: each receipt names the one before it, and the first names
//     the pinned predecessor;
//  7. head_anchor: the last receipt and the count match the pinned head.
//
// A stream that passes all seven is supported, unless the bytes cannot show
// completeness: chain_reset, head_not_anchored or effect_not_recorded are
// not_established. The format is the pinned profile the manifest names; the
// reader derives every field position, name and context from it.
type cborReceiptChain struct{}

func (cborReceiptChain) Suite() string { return "cbor-receipt-chain/v1" }

type crcManifest struct {
	CorpusDigest string            `json:"corpusDigest"`
	Vectors      []json.RawMessage `json:"vectors"`
	Profile      struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"profile"`
}

type crcVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

type crcProfile struct {
	Outer             map[string]string `json:"outer"`
	Fields            map[string]int64  `json:"fields"`
	KeyForm           string            `json:"key_form"`
	LineMember        *string           `json:"line_member"`
	AllowOutcome      string            `json:"allow_outcome"`
	SignatureContext  string            `json:"signature_context_hex"`
	signatureContextB []byte
}

type crcCase struct {
	Chain         string   `json:"chain"`
	Profile       string   `json:"profile"`
	SignerKeys    []string `json:"signer_keys"`
	Head          *string  `json:"head"`
	Count         *int     `json:"count"`
	FirstPrev     *string  `json:"first_prev"`
	RequireEffect bool     `json:"require_effect"`
}

// crcReceipt is one parsed receipt. Members of the payload keep their decoded
// values so single use compares the request and the proof exactly.
type crcReceipt struct {
	signer  string
	digest  string
	prev    *string
	outcome any
	request any
	proof   any
	hasProf bool
}

func (cborReceiptChain) Judge(dir string, raw []byte) (*Result, error) {
	var manifest crcManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	profileBytes, perr := readIn(dir, manifest.Profile.Path)
	if perr != nil {
		result.Findings = append(result.Findings, manifest.Profile.Path+" is declared and absent")
	} else if sha(profileBytes) != manifest.Profile.SHA256 {
		result.Findings = append(result.Findings, manifest.Profile.Path+" does not match its manifest digest")
	}
	for _, entry := range manifest.Vectors {
		var v crcVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = crcJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(scManifest{CorpusDigest: manifest.CorpusDigest, Vectors: manifest.Vectors}); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func crcJudgeMember(caseDir string, v crcVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got, err := crcDecide(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// crcDecide reads one member's inputs and returns the derived decision. An
// error means an input could not be read at all, which is a finding.
func crcDecide(caseDir string) (scDecision, error) {
	var c crcCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return scDecision{}, err
	}
	var profile crcProfile
	if err := scReadJSON(caseDir, c.Profile, &profile); err != nil {
		return scDecision{}, err
	}
	context, err := hex.DecodeString(profile.SignatureContext)
	if err != nil {
		return scDecision{}, errors.New("the profile's signature context is not hex")
	}
	profile.signatureContextB = context
	stream, err := readIn(caseDir, c.Chain)
	if err != nil {
		return scDecision{}, fmt.Errorf("%s cannot be read: %w", c.Chain, err)
	}
	var lines []string
	for _, line := range strings.Split(string(stream), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return crcJudgeStream(lines, c, profile)
}

func crcFail(check string) (scDecision, error) {
	return scDecision{Decision: "contradicted", Reason: check}, nil
}

func crcJudgeStream(lines []string, c crcCase, profile crcProfile) (scDecision, error) {
	var parsed []crcReceipt
	for _, line := range lines {
		r, kind := crcParse(line, profile)
		switch kind {
		case crcMalformed:
			return crcFail("receipt_shape")
		case crcBadSignature:
			return crcFail("signature")
		}
		parsed = append(parsed, r)
	}
	if len(parsed) == 0 {
		return crcFail("receipt_shape")
	}
	pinned := map[string]bool{}
	for _, k := range c.SignerKeys {
		pinned[strings.ToLower(k)] = true
	}
	for _, p := range parsed {
		if !pinned[p.signer] {
			return crcFail("signer_pinned")
		}
	}
	seenDigest := map[string]bool{}
	for _, p := range parsed {
		if seenDigest[p.digest] {
			return crcFail("no_duplicate_receipt")
		}
		seenDigest[p.digest] = true
	}
	seenUse := map[string]bool{}
	for _, p := range parsed {
		if p.hasProf && p.proof != nil {
			if outcome, ok := p.outcome.(string); ok && outcome == profile.AllowOutcome {
				token := crcRender(p.request) + "|" + crcRender(p.proof)
				if seenUse[token] {
					return crcFail("single_use")
				}
				seenUse[token] = true
			}
		}
	}
	resets := false
	for i, p := range parsed {
		switch {
		case i == 0:
			if !crcSame(p.prev, c.FirstPrev) {
				return crcFail("chain_order")
			}
		case p.prev == nil:
			resets = true
		case *p.prev != parsed[i-1].digest:
			return crcFail("chain_order")
		}
	}
	if c.Head != nil {
		if c.Count == nil {
			return scDecision{}, errors.New("case.json pins a head and carries no count")
		}
		if parsed[len(parsed)-1].digest != *c.Head || len(parsed) != *c.Count {
			return crcFail("head_anchor")
		}
	}
	if resets {
		return scDecision{Decision: "not_established", Reason: "chain_reset"}, nil
	}
	if c.Head == nil {
		return scDecision{Decision: "not_established", Reason: "head_not_anchored"}, nil
	}
	if _, hasEffect := profile.Fields["effect"]; c.RequireEffect && !hasEffect {
		return scDecision{Decision: "not_established", Reason: "effect_not_recorded"}, nil
	}
	return scDecision{Decision: "supported", Reason: "receipt_chain_holds"}, nil
}

func crcSame(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

type crcParseKind int

const (
	crcOK crcParseKind = iota
	crcMalformed
	crcBadSignature
)

// crcWire returns the hex of one receipt: the line, or the named member of a
// JSON line.
func crcWire(line string, profile crcProfile) (string, bool) {
	if profile.LineMember == nil {
		return line, true
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &members); err != nil {
		return "", false
	}
	var wire string
	if err := json.Unmarshal(members[*profile.LineMember], &wire); err != nil {
		return "", false
	}
	return wire, true
}

// crcFromHex reads hex the way Python's bytes.fromhex does: ASCII whitespace
// may sit between bytes, never inside one.
func crcFromHex(s string) ([]byte, bool) {
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
		b, err := hex.DecodeString(s[i : i+2])
		if err != nil {
			return nil, false
		}
		out = append(out, b[0])
		i += 2
	}
	return out, true
}

func crcParse(line string, profile crcProfile) (crcReceipt, crcParseKind) {
	wire, ok := crcWire(line, profile)
	if !ok {
		return crcReceipt{}, crcMalformed
	}
	raw, ok := crcFromHex(wire)
	if !ok {
		return crcReceipt{}, crcMalformed
	}
	outerValue, err := crcDecode(raw)
	if err != nil {
		return crcReceipt{}, crcMalformed
	}
	outer, isMap := outerValue.(crcMap)
	names := profile.Outer
	want := []string{names["version"], names["payload"], names["signer_key"], names["signature"]}
	if !isMap || !outer.keysAre(want) {
		return crcReceipt{}, crcMalformed
	}
	version, isInt := outer.get(crcText(names["version"])).(crcInt)
	if !isInt || version.neg || version.mag > 255 {
		return crcReceipt{}, crcMalformed
	}
	payload, isBytes := outer.get(crcText(names["payload"])).([]byte)
	if !isBytes {
		return crcReceipt{}, crcMalformed
	}
	key, ok := crcBytes(outer.get(crcText(names["signer_key"])), profile.KeyForm, ed25519.PublicKeySize)
	if !ok {
		return crcReceipt{}, crcMalformed
	}
	sig, ok := crcBytes(outer.get(crcText(names["signature"])), profile.KeyForm, ed25519.SignatureSize)
	if !ok {
		return crcReceipt{}, crcMalformed
	}
	message := append(append(append([]byte{}, profile.signatureContextB...), byte(version.mag)), payload...)
	if !ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return crcReceipt{}, crcBadSignature
	}
	bodyValue, err := crcDecode(payload)
	body, isBody := bodyValue.(crcMap)
	if err != nil || !isBody {
		return crcReceipt{}, crcMalformed
	}
	if inner, ok := body.get(crcInt{mag: uint64(profile.Fields["version"])}).(crcInt); !ok || inner != version {
		return crcReceipt{}, crcMalformed
	}
	r := crcReceipt{signer: hex.EncodeToString(key), digest: sha(raw)}
	switch prev := body.get(crcInt{mag: uint64(profile.Fields["prev_hash"])}).(type) {
	case nil:
	case []byte:
		if len(prev) != 32 {
			return crcReceipt{}, crcMalformed
		}
		text := hex.EncodeToString(prev)
		r.prev = &text
	default:
		return crcReceipt{}, crcMalformed
	}
	field := func(role string) any {
		if id, ok := profile.Fields[role]; ok {
			return body.get(crcInt{mag: uint64(id)})
		}
		return nil
	}
	r.outcome, r.request, r.proof = field("outcome"), field("request_hash"), field("proof")
	_, r.hasProf = profile.Fields["proof"]
	return r, crcOK
}

// crcBytes reads a key or a signature: the byte string itself, or the second
// member of an [algorithm, bytes] pair.
func crcBytes(value any, form string, size int) ([]byte, bool) {
	if form == "pair" {
		pair, ok := value.([]any)
		if !ok || len(pair) != 2 {
			return nil, false
		}
		value = pair[1]
	}
	b, ok := value.([]byte)
	return b, ok && len(b) == size
}

// crcRender is an exact, type-tagged rendering of a decoded value, so two
// values compare equal only when they are the same item.
func crcRender(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("bool:%t", x)
	case crcInt:
		return fmt.Sprintf("int:%t:%d", x.neg, x.mag)
	case []byte:
		return "bytes:" + hex.EncodeToString(x)
	case string:
		return fmt.Sprintf("text:%q", x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = crcRender(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case crcMap:
		parts := make([]string, len(x.pairs))
		for i, p := range x.pairs {
			parts[i] = crcRender(p[0]) + "=" + crcRender(p[1])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "?"
}

// A decoded CBOR integer keeps its sign and magnitude, so values past 64 bits
// of signed range survive.
type crcInt struct {
	neg bool
	mag uint64
}

type crcText string

// crcMap keeps the pairs in wire order. Keys are integers or text, never
// repeated.
type crcMap struct{ pairs [][2]any }

func (m crcMap) get(key any) any {
	for _, p := range m.pairs {
		if crcKeyEqual(p[0], key) {
			return p[1]
		}
	}
	return nil
}

func (m crcMap) keysAre(names []string) bool {
	if len(m.pairs) != len(names) {
		return false
	}
	for _, name := range names {
		found := false
		for _, p := range m.pairs {
			if text, ok := p[0].(string); ok && text == name {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func crcKeyEqual(a, b any) bool {
	if t, ok := b.(crcText); ok {
		b = string(t)
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case crcInt:
		y, ok := b.(crcInt)
		return ok && x == y
	}
	return false
}

type crcDecoder struct {
	buf    []byte
	pos    int
	budget int
}

var errCrcMalformed = errors.New("malformed CBOR")

// crcDecode reads exactly one CBOR item, strictly: no tags, floats, simple
// values other than false, true and null, indefinite lengths or reserved
// additional information; map keys are integers or text and never repeat; the
// item count and depth are bounded; nothing may follow it.
func crcDecode(data []byte) (any, error) {
	d := &crcDecoder{buf: data, budget: 4096}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, errCrcMalformed
	}
	return v, nil
}

func (d *crcDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.buf)-d.pos) {
		return nil, errCrcMalformed
	}
	out := d.buf[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

func (d *crcDecoder) item(depth int) (any, error) {
	d.budget--
	if depth > 16 || d.budget < 0 {
		return nil, errCrcMalformed
	}
	head, err := d.take(1)
	if err != nil {
		return nil, err
	}
	major, info := head[0]>>5, head[0]&31
	if major == 7 {
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, errCrcMalformed
	}
	if major == 6 || info > 27 {
		return nil, errCrcMalformed
	}
	arg := uint64(info)
	if info >= 24 {
		raw, err := d.take(uint64(1) << (info - 24))
		if err != nil {
			return nil, err
		}
		arg = 0
		for _, b := range raw {
			arg = arg<<8 | uint64(b)
		}
	}
	switch major {
	case 0:
		return crcInt{mag: arg}, nil
	case 1:
		return crcInt{neg: true, mag: arg}, nil
	case 2, 3:
		raw, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		if major == 2 {
			return bytes.Clone(raw), nil
		}
		if !utf8.Valid(raw) {
			return nil, errCrcMalformed
		}
		return string(raw), nil
	}
	if arg > uint64(len(d.buf)) {
		return nil, errCrcMalformed
	}
	if major == 4 {
		items := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return items, nil
	}
	out := crcMap{}
	for i := uint64(0); i < arg; i++ {
		key, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		switch key.(type) {
		case string, crcInt:
		default:
			return nil, errCrcMalformed
		}
		for _, p := range out.pairs {
			if crcKeyEqual(p[0], key) {
				return nil, errCrcMalformed
			}
		}
		value, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		out.pairs = append(out.pairs, [2]any{key, value})
	}
	return out, nil
}
