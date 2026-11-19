package corpusreaders

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

func init() { register(lifecycleBinding{}) }

// lifecycleBinding judges corpora/vectors-lifecycle-binding/. Each member is one
// set of decision, control and execution records under the lifecycle_binding term,
// with the consumer's key bindings and revocation snapshot. The reader derives
// each member's decision and reason from the record bytes alone, with the rules
// the Python reader applies, in the same order:
//
//  1. admission: strict I-JSON text (a repeated member after escape decoding is
//     no_duplicate_member; a lone surrogate, an unsafe integer, a number that
//     overflows a double or text that is not a JSON array is record_shape), then
//     each record's registered tag (unregistered_tag) and its members, names,
//     integrity block and digests (record_shape);
//  2. per (decision, instruction) group: a shared record identity anywhere in the
//     set is indeterminate; an execution no control covers is not_evaluated; a
//     missing issuer-side control, execution or cited decision is missing (a
//     receiver-side control alone records what the executor's side received,
//     never what was allowed); an artifact that
//     does not authenticate (hash over the domain-tagged RFC 8785 bytes, then an
//     Ed25519 signature over the tagged {current, suite} object) is a failure; a
//     producer the revocation snapshot does not list as active is not_evaluated;
//     an issuer-side control signed by a key that signs an execution in the group
//     is a failure, under any producer name; then every authorized digest is
//     compared with every executed digest;
//  3. the set's answer is failure when any group fails, else the first of
//     indeterminate, not_evaluated and missing, else satisfied. A set with no
//     group is missing, or empty_denominator when it holds no record.
type lifecycleBinding struct{}

func (lifecycleBinding) Suite() string { return "lifecycle-binding/v1" }

const lbTagPrefix = "agent-evidence/lifecycle-binding/v1/"

// lbMembers are the members a record of each registered type must carry.
var lbMembers = map[string][]string{
	"decision": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity"},
	"control": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity",
		"decision_ref", "instruction_id", "boundary_side", "authorized_action_digest"},
	"execution": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity",
		"decision_ref", "instruction_id", "executed_action_digest"},
}

type lbBinding struct {
	PublicKeyHex string `json:"public_key_hex"`
	Suite        string `json:"suite"`
}

type lbCase struct {
	Bindings   map[string]lbBinding `json:"bindings"`
	Revocation map[string]struct {
		State string `json:"state"`
	} `json:"revocation"`
	RecordsText string `json:"records_text"`
}

// lbRecord is one admitted record.
type lbRecord struct {
	kind, id, producer, instruction, decisionRef, side, authorized, executed string
	current, signature                                                       string
	raw                                                                      map[string]any
}

// lbRefused is a set the profile cannot admit, with the reason it names.
type lbRefused struct{ reason string }

func (e lbRefused) Error() string { return e.reason }

func (lifecycleBinding) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v scVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = lbJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func lbJudgeMember(caseDir string, v scVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c lbCase
	if err := scReadJSON(caseDir, "record.json", &c); err != nil {
		return append(findings, err.Error())
	}
	if got := lbDecide(c); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func lbDecide(c lbCase) scDecision {
	records, err := lbParseRecords(c.RecordsText)
	if err != nil {
		var refused lbRefused
		if errors.As(err, &refused) {
			return scDecision{"refused", refused.reason}
		}
		return scDecision{"refused", "record_shape"}
	}
	states := lbGroupStates(records, c)
	if len(states) == 0 {
		if len(records) > 0 {
			return scDecision{"missing", "missing"}
		}
		return scDecision{"missing", "empty_denominator"}
	}
	for _, state := range []string{"failure", "indeterminate", "not_evaluated", "missing"} {
		if states[state] {
			return scDecision{state, state}
		}
	}
	return scDecision{"satisfied", "satisfied"}
}

// lbParseRecords is strict I-JSON, then admission of every record in order.
func lbParseRecords(text string) ([]lbRecord, error) {
	p := &lbParser{text: text}
	value, err := p.document()
	if err != nil {
		return nil, err
	}
	if p.lone {
		return nil, lbRefused{"record_shape"}
	}
	list, ok := value.([]any)
	if !ok {
		return nil, lbRefused{"record_shape"}
	}
	records := make([]lbRecord, 0, len(list))
	for _, item := range list {
		record, err := lbAdmit(item)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func lbString(m map[string]any, key string) (string, bool) {
	s, ok := m[key].(string)
	return s, ok
}

func lbSHA(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return "", false
	}
	for _, c := range s[7:] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", false
		}
	}
	return s, true
}

func lbAdmit(item any) (lbRecord, error) {
	shape := lbRefused{"record_shape"}
	m, ok := item.(map[string]any)
	if !ok {
		return lbRecord{}, shape
	}
	kind, _ := m["artifact_type"].(string)
	if m["lifecycle_version"] != "v1" || lbMembers[kind] == nil {
		return lbRecord{}, lbRefused{"unregistered_tag"}
	}
	for _, name := range lbMembers[kind] {
		if _, present := m[name]; !present {
			return lbRecord{}, shape
		}
	}
	r := lbRecord{kind: kind, raw: m}
	names := []string{"record_id", "producer"}
	if kind != "decision" {
		names = append(names, "instruction_id")
	}
	for _, name := range names {
		if s, ok := lbString(m, name); !ok || s == "" {
			return lbRecord{}, shape
		}
	}
	r.id, _ = lbString(m, "record_id")
	r.producer, _ = lbString(m, "producer")
	r.instruction, _ = lbString(m, "instruction_id")
	integrity, ok := m["integrity"].(map[string]any)
	if !ok {
		return lbRecord{}, shape
	}
	var currentOK bool
	if r.current, currentOK = lbSHA(integrity["current"]); !currentOK {
		return lbRecord{}, shape
	}
	signature, ok := integrity["signature"].(map[string]any)
	if !ok {
		return lbRecord{}, shape
	}
	if r.signature, ok = signature["value"].(string); !ok {
		return lbRecord{}, shape
	}
	if kind != "decision" {
		ref, ok := m["decision_ref"].(map[string]any)
		if !ok {
			return lbRecord{}, shape
		}
		if r.decisionRef, ok = ref["record_id"].(string); !ok {
			return lbRecord{}, shape
		}
	}
	if kind == "control" {
		r.side, _ = m["boundary_side"].(string)
		if r.side != "issuer" && r.side != "receiver" {
			return lbRecord{}, shape
		}
	}
	for _, pointer := range []string{"authorized_action_digest", "executed_action_digest"} {
		if value, present := m[pointer]; present {
			digest, ok := lbSHA(value)
			if !ok {
				return lbRecord{}, shape
			}
			if pointer == "authorized_action_digest" {
				r.authorized = digest
			} else {
				r.executed = digest
			}
		}
	}
	return r, nil
}

// lbHashInput is the domain tag, one LF, then the RFC 8785 bytes of the record
// without integrity.current and integrity.signature.
func lbHashInput(r lbRecord) ([]byte, error) {
	body := make(map[string]any, len(r.raw))
	for k, v := range r.raw {
		if k != "integrity" {
			body[k] = v
		}
	}
	rest := map[string]any{}
	for k, v := range r.raw["integrity"].(map[string]any) {
		if k != "current" && k != "signature" {
			rest[k] = v
		}
	}
	if len(rest) > 0 {
		body["integrity"] = rest
	}
	return lbPreImage(r.kind, "hash", body)
}

func lbPreImage(kind, purpose string, value any) ([]byte, error) {
	var buf strings.Builder
	if err := a2aWrite(&buf, value); err != nil {
		return nil, err
	}
	return []byte(lbTagPrefix + kind + "/" + purpose + "\n" + buf.String()), nil
}

// lbAuthenticated reports whether the producer is bound with the ed25519 suite,
// the record's hash matches its tagged pre-image and the producer's signature
// verifies over the tagged {current, suite} object.
func lbAuthenticated(r lbRecord, bindings map[string]lbBinding) bool {
	binding, ok := bindings[r.producer]
	if !ok || binding.Suite != "ed25519" {
		return false
	}
	pre, err := lbHashInput(r)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(pre)
	if "sha256:"+hex.EncodeToString(sum[:]) != r.current {
		return false
	}
	message, err := lbPreImage(r.kind, "signature", map[string]any{"current": r.current, "suite": binding.Suite})
	if err != nil {
		return false
	}
	pub, perr := lbFromHex(binding.PublicKeyHex)
	sig, serr := lbFromHex(r.signature)
	if perr != nil || serr != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// lbFromHex reads hex the way Python's bytes.fromhex does: ASCII whitespace is skipped.
func lbFromHex(text string) ([]byte, error) {
	return hex.DecodeString(strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' {
			return -1
		}
		return r
	}, text))
}

// lbSelfAuthorized reports an issuer-side control signed by a key that signs an
// execution in the group, whatever producer name each is bound under.
func lbSelfAuthorized(controls, executions []lbRecord, bindings map[string]lbBinding) bool {
	executing := map[string]bool{}
	for _, e := range executions {
		executing[bindings[e.producer].PublicKeyHex] = true
	}
	for _, control := range controls {
		if control.side == "issuer" && executing[bindings[control.producer].PublicKeyHex] {
			return true
		}
	}
	return false
}

type lbGroupKey struct{ decision, instruction string }

// lbGroupStates gives each (decision, instruction) group one state, in the
// rule order above, and returns the set of states the groups hold.
func lbGroupStates(records []lbRecord, c lbCase) map[string]bool {
	counts := map[string]int{}
	decisions := map[string]lbRecord{}
	for _, r := range records {
		counts[r.id]++
		if r.kind == "decision" {
			decisions[r.id] = r
		}
	}
	groups := map[lbGroupKey][]lbRecord{}
	for _, r := range records {
		if r.kind != "decision" {
			key := lbGroupKey{r.decisionRef, r.instruction}
			groups[key] = append(groups[key], r)
		}
	}
	states := map[string]bool{}
	for key, members := range groups {
		states[lbGroupState(key, members, decisions, counts, c)] = true
	}
	return states
}

func lbGroupState(key lbGroupKey, members []lbRecord, decisions map[string]lbRecord,
	counts map[string]int, c lbCase) string {
	var controls, executions []lbRecord
	issuerSide := false
	shared := counts[key.decision] > 1
	for _, m := range members {
		shared = shared || counts[m.id] > 1
		if m.kind == "control" {
			controls = append(controls, m)
			issuerSide = issuerSide || m.side == "issuer"
		} else {
			executions = append(executions, m)
		}
	}
	decision, cited := decisions[key.decision]
	switch {
	case shared:
		return "indeterminate"
	case len(executions) > 0 && len(controls) == 0:
		return "not_evaluated"
	case !issuerSide || len(executions) == 0 || !cited:
		return "missing"
	}
	checked := append([]lbRecord{decision}, members...)
	for _, r := range checked {
		if !lbAuthenticated(r, c.Bindings) {
			return "failure"
		}
	}
	for _, r := range checked {
		if c.Revocation[r.producer].State != "active" {
			return "not_evaluated"
		}
	}
	if lbSelfAuthorized(controls, executions, c.Bindings) {
		return "failure"
	}
	authorized, executed := map[string]bool{}, map[string]bool{}
	for _, control := range controls {
		authorized[control.authorized] = true
	}
	for _, execution := range executions {
		executed[execution.executed] = true
	}
	if len(authorized) != 1 || len(executed) != 1 {
		return "failure"
	}
	for digest := range authorized {
		if !executed[digest] {
			return "failure"
		}
	}
	return "satisfied"
}

// lbParser is a strict I-JSON reader that raises its refusal at the moment
// CPython's json scanner would: a number is judged when scanned, a repeated
// member when its object closes, a lone surrogate once the whole text parsed.
type lbParser struct {
	text string
	pos  int
	lone bool
}

var lbShape = lbRefused{"record_shape"}

func (p *lbParser) space() {
	for p.pos < len(p.text) && strings.IndexByte(" \t\n\r", p.text[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *lbParser) document() (any, error) {
	p.space()
	value, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.text) {
		return nil, lbShape
	}
	return value, nil
}

func (p *lbParser) value() (any, error) {
	if p.pos >= len(p.text) {
		return nil, lbShape
	}
	switch c := p.text[p.pos]; {
	case c == '"':
		return p.str()
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	for literal, value := range map[string]any{"true": true, "false": false, "null": nil} {
		if strings.HasPrefix(p.text[p.pos:], literal) {
			p.pos += len(literal)
			return value, nil
		}
	}
	return nil, lbShape
}

func (p *lbParser) array() (any, error) {
	p.pos++
	out := []any{}
	p.space()
	if p.pos < len(p.text) && p.text[p.pos] == ']' {
		p.pos++
		return out, nil
	}
	for {
		p.space()
		item, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, item)
		p.space()
		if p.pos >= len(p.text) {
			return nil, lbShape
		}
		switch p.text[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return out, nil
		default:
			return nil, lbShape
		}
	}
}

func (p *lbParser) object() (any, error) {
	p.pos++
	out := map[string]any{}
	repeated := false
	p.space()
	if p.pos < len(p.text) && p.text[p.pos] == '}' {
		p.pos++
		return out, nil
	}
	for {
		p.space()
		if p.pos >= len(p.text) || p.text[p.pos] != '"' {
			return nil, lbShape
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.pos >= len(p.text) || p.text[p.pos] != ':' {
			return nil, lbShape
		}
		p.pos++
		p.space()
		item, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := out[key.(string)]; dup {
			repeated = true
		}
		out[key.(string)] = item
		p.space()
		if p.pos >= len(p.text) {
			return nil, lbShape
		}
		switch p.text[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			if repeated {
				return nil, lbRefused{"no_duplicate_member"}
			}
			return out, nil
		default:
			return nil, lbShape
		}
	}
}

// number scans the JSON number grammar; an integer outside +-(2^53-1) and a
// float that overflows a double are refused when scanned.
func (p *lbParser) number() (any, error) {
	start, i := p.pos, p.pos
	digits := func() int {
		n := 0
		for i < len(p.text) && p.text[i] >= '0' && p.text[i] <= '9' {
			i++
			n++
		}
		return n
	}
	if p.text[i] == '-' {
		i++
	}
	if i < len(p.text) && p.text[i] == '0' {
		i++
	} else if digits() == 0 {
		return nil, lbShape
	}
	integral := true
	if i+1 < len(p.text) && p.text[i] == '.' && p.text[i+1] >= '0' && p.text[i+1] <= '9' {
		i++
		digits()
		integral = false
	}
	if i < len(p.text) && (p.text[i] == 'e' || p.text[i] == 'E') {
		j := i + 1
		if j < len(p.text) && (p.text[j] == '+' || p.text[j] == '-') {
			j++
		}
		if j < len(p.text) && p.text[j] >= '0' && p.text[j] <= '9' {
			i = j
			digits()
			integral = false
		}
	}
	token := p.text[start:i]
	p.pos = i
	if integral {
		n, err := strconv.ParseInt(token, 10, 64)
		if err != nil || n > 1<<53-1 || n < -(1<<53-1) {
			return nil, lbShape
		}
	} else if f, err := strconv.ParseFloat(token, 64); math.IsInf(f, 0) || math.IsNaN(f) ||
		(err != nil && !errors.Is(err, strconv.ErrRange)) {
		return nil, lbShape
	}
	return json.Number(token), nil
}

// str decodes a JSON string: control characters are refused, an escaped
// surrogate that is not half of a pair is kept (as three bytes, so two
// different ones stay different keys) and flagged for refusal after the parse.
func (p *lbParser) str() (any, error) {
	p.pos++
	var out strings.Builder
	for {
		if p.pos >= len(p.text) {
			return nil, lbShape
		}
		c := p.text[p.pos]
		switch {
		case c == '"':
			p.pos++
			return out.String(), nil
		case c < 0x20:
			return nil, lbShape
		case c != '\\':
			r, size := utf8.DecodeRuneInString(p.text[p.pos:])
			out.WriteRune(r)
			p.pos += size
		default:
			if err := p.escape(&out); err != nil {
				return nil, err
			}
		}
	}
}

func (p *lbParser) escape(out *strings.Builder) error {
	p.pos++
	if p.pos >= len(p.text) {
		return lbShape
	}
	c := p.text[p.pos]
	p.pos++
	if simple := strings.IndexByte(`"\/bfnrt`, c); simple >= 0 {
		out.WriteByte([]byte{'"', '\\', '/', '\b', '\f', '\n', '\r', '\t'}[simple])
		return nil
	}
	if c != 'u' {
		return lbShape
	}
	code, ok := p.hex4()
	if !ok {
		return lbShape
	}
	if code >= 0xD800 && code <= 0xDBFF && strings.HasPrefix(p.text[p.pos:], `\u`) {
		save := p.pos
		p.pos += 2
		if low, ok := p.hex4(); ok && low >= 0xDC00 && low <= 0xDFFF {
			out.WriteRune(rune(0x10000 + (code-0xD800)<<10 + (low - 0xDC00)))
			return nil
		}
		p.pos = save
	}
	if code >= 0xD800 && code <= 0xDFFF {
		p.lone = true
		out.WriteByte(byte(0xE0 | code>>12))
		out.WriteByte(byte(0x80 | (code>>6)&0x3F))
		out.WriteByte(byte(0x80 | code&0x3F))
		return nil
	}
	out.WriteRune(rune(code))
	return nil
}

func (p *lbParser) hex4() (int, bool) {
	if p.pos+4 > len(p.text) {
		return 0, false
	}
	for _, c := range p.text[p.pos : p.pos+4] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(p.text[p.pos:p.pos+4], 16, 16)
	p.pos += 4
	return int(n), err == nil
}
