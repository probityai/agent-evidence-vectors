package corpora

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func init() { register(agentDecision{}) }

// agentDecision judges vectors-agent-decision/, the corpus for the args_hash
// rule of the agent-decision/v0.1 predicate proposed on in-toto/attestation#554.
//
// It is the Go rail over that corpus. The Python rail is the corpus's own
// check_vectors.py, and the rules below are that reader restated rather than
// imported: two spellings of one rule set are the only arrangement that finds a
// rule both get wrong the same way. Most members test canonicalization, so this
// file carries its own RFC 8785 writer and its own argument parser; the aee
// package's canonicalizer refuses every non-integer number, which is exactly the
// value space these members exist to exercise.
type agentDecision struct{}

func (agentDecision) Suite() string { return "agent-decision-conformance" }

const adStatementType = "https://in-toto.io/Statement/v1"

var (
	adHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	adRFC3339     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	adStates      = []string{"recorded", "redacted", "unavailable", "not_recorded"}
	adMaxSafe     = big.NewInt(1<<53 - 1)
)

// adRules is the reader's rule order, which is also the order of first refusal.
// The sweep in the test disables each in turn.
var adRules = []string{
	"signature", "statement", "predicate-shape", "args-state", "args-hash-presence",
	"args-hash-format", "arguments-json", "arguments-duplicate", "arguments-integer",
	"arguments-overflow", "args-hash-match",
}

type adManifest struct {
	PredicateType string `json:"predicateType"`
	PayloadType   string `json:"payloadType"`
	Keys          struct {
		Producer struct {
			PublicKey string `json:"publicKey"`
		} `json:"producer"`
	} `json:"keys"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []adVector     `json:"vectors"`
}

type adVector struct {
	ID                 string  `json:"id"`
	Slug               string  `json:"slug"`
	Kind               string  `json:"kind"`
	File               string  `json:"file"`
	Arguments          string  `json:"arguments"`
	CanonicalArguments *string `json:"canonicalArguments"`
	Parent             string  `json:"parent"`
	Expected           struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
}

type adReport struct {
	verdict string
	code    string
}

// adRefusal carries a verdict and the code that names the refusing rule.
type adRefusal struct{ verdict, code string }

func (r *adRefusal) Error() string { return r.code }

func adMalformed(code string) error { return &adRefusal{"malformed", code} }

func (agentDecision) Judge(dir string, raw []byte) (*Result, error) {
	var m adManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepts := map[string]bool{}
	for _, v := range m.Vectors {
		if v.Kind == "accept" {
			accepts[v.ID] = true
		}
	}
	counts := map[string]int{}
	for _, v := range m.Vectors {
		counts[v.Kind]++
		member := Member{ID: v.ID, Kind: v.Kind, Findings: adJudgeMember(dir, &m, v, accepts)}
		result.Members = append(result.Members, member)
	}
	if fmt.Sprint(counts) != fmt.Sprint(m.Counts) {
		result.Findings = append(result.Findings,
			fmt.Sprintf("counts %v disagree with the members %v", m.Counts, counts))
	}
	if digest, err := adCorpusDigest(dir, m.Vectors); err != nil || digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the committed bytes")
	}
	return result, nil
}

func adJudgeMember(dir string, m *adManifest, v adVector, accepts map[string]bool) []string {
	label := v.ID + " (" + v.Slug + ")"
	var findings []string
	if v.Kind == "reject" && !accepts[v.Parent] {
		findings = append(findings, label+": parent is not an accept member")
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		return append(findings, label+": the member file cannot be read")
	}
	var arguments []byte
	if v.Arguments != "" {
		if arguments, err = readIn(dir, v.Arguments); err != nil {
			return append(findings, label+": the arguments file cannot be read")
		}
	}
	if "v"+sha(append(append([]byte{}, body...), arguments...))[:16] != v.ID {
		findings = append(findings, label+": identifier does not recompute from the member's own bytes")
	}
	report := adVerify(body, arguments, m, "")
	var codes []string
	if report.code != "" {
		codes = []string{report.code}
	}
	if report.verdict != v.Expected.Verdict || fmt.Sprint(codes) != fmt.Sprint(v.Expected.Codes) {
		findings = append(findings, fmt.Sprintf("%s: expected %s %v, reached %s %v",
			label, v.Expected.Verdict, v.Expected.Codes, report.verdict, codes))
	}
	if v.CanonicalArguments != nil {
		value, err := adAdmit(arguments, "")
		if err != nil {
			findings = append(findings, label+": carries canonicalArguments over arguments this rail refuses")
		} else if got, err := adCanonical(value); err != nil || string(got) != *v.CanonicalArguments {
			findings = append(findings, label+": canonicalArguments disagrees")
		}
	}
	return findings
}

// adCorpusDigest is SHA-256 over every member's envelope followed by its
// disclosed arguments, in identifier order: the arguments are an input a
// verifier reads, so they belong to the member.
func adCorpusDigest(dir string, vectors []adVector) (string, error) {
	ordered := append([]adVector{}, vectors...)
	sort.SliceStable(ordered, func(a, b int) bool { return ordered[a].ID < ordered[b].ID })
	h := sha256.New()
	for _, v := range ordered {
		for _, rel := range []string{v.File, v.Arguments} {
			if rel == "" {
				continue
			}
			body, err := readIn(dir, rel)
			if err != nil {
				return "", err
			}
			h.Write(body)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// adVerify judges one member. disabled names a rule to switch off; an admission
// rule switched off is replaced by the behaviour a common library shows in its
// place, so the test's sweep measures whether the corpus catches that library.
func adVerify(envelope, arguments []byte, m *adManifest, disabled string) adReport {
	err := adCheck(envelope, arguments, m, disabled)
	if err == nil {
		return adReport{verdict: "valid"}
	}
	var refused *adRefusal
	if errors.As(err, &refused) {
		return adReport{verdict: refused.verdict, code: refused.code}
	}
	return adReport{verdict: "malformed", code: "statement-malformed"}
}

func adCheck(envelope, arguments []byte, m *adManifest, disabled string) error {
	// Bytes that are not JSON at all are a malformed member; JSON that is not an
	// object is an envelope carrying no signature, which is how Python reads both.
	var parsed any
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return err
	}
	env, isObject := parsed.(map[string]any)
	if !isObject {
		return &adRefusal{"invalid", "signature-invalid"}
	}
	var payload []byte
	var err error
	if disabled == "signature" {
		text, _ := env["payload"].(string)
		payload, err = base64.StdEncoding.DecodeString(text)
	} else {
		payload, err = adSignature(env, m)
	}
	if err != nil {
		return err
	}
	var stmt map[string]any
	if disabled == "statement" {
		err = json.Unmarshal(payload, &stmt)
	} else {
		stmt, err = adStatement(payload, m.PredicateType)
	}
	if err != nil {
		return err
	}
	calls, err := adCalls(stmt["predicate"], disabled)
	if err != nil {
		return err
	}
	for _, c := range calls {
		call, ok := c.(map[string]any)
		if !ok {
			return errors.New("a tool call is not an object")
		}
		if err := adCall(call, arguments, disabled); err != nil {
			return err
		}
	}
	return nil
}

func adSignature(env map[string]any, m *adManifest) ([]byte, error) {
	invalid := &adRefusal{"invalid", "signature-invalid"}
	if env["payloadType"] != m.PayloadType {
		return nil, invalid
	}
	text, _ := env["payload"].(string)
	payload, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, invalid
	}
	sigs, ok := env["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return nil, invalid
	}
	entry, _ := sigs[0].(map[string]any)
	sigText, _ := entry["sig"].(string)
	sig, err := base64.StdEncoding.Strict().DecodeString(sigText)
	key, keyErr := hex.DecodeString(m.Keys.Producer.PublicKey)
	if err != nil || keyErr != nil || len(key) != ed25519.PublicKeySize {
		return nil, invalid
	}
	if !ed25519.Verify(ed25519.PublicKey(key), adPAE(m.PayloadType, payload), sig) {
		return nil, invalid
	}
	return payload, nil
}

func adPAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func adStatement(payload []byte, predicateType string) (map[string]any, error) {
	bad := adMalformed("statement-malformed")
	var stmt map[string]any
	if err := json.Unmarshal(payload, &stmt); err != nil || stmt == nil {
		return nil, bad
	}
	subjects, ok := stmt["subject"].([]any)
	if !ok || len(subjects) == 0 {
		return nil, bad
	}
	for _, s := range subjects {
		subject, ok := s.(map[string]any)
		if !ok {
			return nil, bad
		}
		_, named := subject["name"].(string)
		digest, digested := subject["digest"].(map[string]any)
		if !named || !digested || len(digest) == 0 {
			return nil, bad
		}
	}
	if stmt["_type"] != adStatementType || stmt["predicateType"] != predicateType {
		return nil, bad
	}
	return stmt, nil
}

func adText(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// adCalls checks the fields the RFC marks required and returns the tool calls.
func adCalls(raw any, disabled string) ([]any, error) {
	predicate, isObject := raw.(map[string]any)
	if disabled == "predicate-shape" {
		calls, _ := predicate["tool_calls"].([]any)
		return calls, nil
	}
	calls, ok := predicate["tool_calls"].([]any)
	decidedAt, dated := predicate["decided_at"].(string)
	if !isObject || !adHeadOK(predicate) || !ok || !adToolCallsOK(calls) ||
		!dated || !adRFC3339.MatchString(decidedAt) {
		return nil, adMalformed("predicate-malformed")
	}
	return calls, nil
}

// adHeadOK checks who decided and under which policies.
func adHeadOK(predicate map[string]any) bool {
	principal, ok := predicate["principal"].(map[string]any)
	if !adText(predicate["agent_id"]) || !ok || !adText(principal["subject"]) {
		return false
	}
	evaluations, ok := predicate["policy_evaluations"].([]any)
	if !ok || len(evaluations) == 0 {
		return false
	}
	for _, e := range evaluations {
		if !adEvaluationOK(e) {
			return false
		}
	}
	return true
}

func adEvaluationOK(e any) bool {
	ev, ok := e.(map[string]any)
	_, reasoned := ev["reason"].(string)
	decision := ev["decision"]
	return ok && adText(ev["policy"]) && reasoned && (decision == "allow" || decision == "deny")
}

func adToolCallsOK(calls []any) bool {
	if len(calls) == 0 {
		return false
	}
	for _, c := range calls {
		call, ok := c.(map[string]any)
		if !ok || !adText(call["name"]) {
			return false
		}
	}
	return true
}

// adDeclarations checks args_state, then whether args_hash is present where
// the state calls for one, then its format. It reports whether the state is
// one of the closed set.
func adDeclarations(call map[string]any, disabled string) (bool, error) {
	stateValue, hasState := call["args_state"]
	state, _ := stateValue.(string)
	known := hasState && adContains(adStates, state)
	if disabled != "args-state" && !hasState {
		return false, adMalformed("args-state-missing")
	}
	if disabled != "args-state" && !known {
		return false, adMalformed("args-state-unknown")
	}
	return known, adHashDeclaration(call, known, state, disabled)
}

// adHashDeclaration checks args_hash against the state that governs it.
func adHashDeclaration(call map[string]any, known bool, state, disabled string) error {
	digestValue, present := call["args_hash"]
	hashed := known && (state == "recorded" || state == "redacted")
	if disabled != "args-hash-presence" {
		if hashed && !present {
			return adMalformed("args-hash-required")
		}
		if known && !hashed && present {
			return adMalformed("args-hash-forbidden")
		}
	}
	digest, isText := digestValue.(string)
	if present && disabled != "args-hash-format" && (!isText || !adHashPattern.MatchString(digest)) {
		return adMalformed("args-hash-format")
	}
	return nil
}

func adCall(call map[string]any, arguments []byte, disabled string) error {
	known, err := adDeclarations(call, disabled)
	if err != nil {
		return err
	}
	digest, isText := call["args_hash"].(string)
	if !known || call["args_state"] != "recorded" || arguments == nil || !isText {
		return nil
	}
	value, err := adAdmit(arguments, disabled)
	if err != nil {
		return err
	}
	canonical, err := adCanonical(value)
	if err != nil {
		return err
	}
	if disabled != "args-hash-match" && "sha256:"+sha(canonical) != strings.ToLower(digest) {
		return &adRefusal{"invalid", "args-hash-mismatch"}
	}
	return nil
}

func adContains(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// adInt and adFloat keep the two number kinds apart: an integer literal stays
// exact, and anything written with a fraction or exponent is a double.
type adInt int64
type adFloat float64

// adObject keeps member order only so a repeated name can be resolved the way
// a last-wins parser does when the duplicate rule is switched off; the writer
// sorts by UTF-16 code unit regardless.
type adObject struct {
	names  []string
	values map[string]any
}

// adAdmit parses disclosed argument bytes under the corpus's admission rules.
// Repeated names are found when an object closes and numbers when they are
// read, which is the order Python's parser raises them in, so both rails name
// the same first refusal on a member that breaks two rules at once.
func adAdmit(raw []byte, disabled string) (any, error) {
	notJSON := adMalformed("arguments-not-json")
	if !utf8.Valid(raw) {
		return nil, notJSON
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := adParse(dec, disabled, 0)
	if err != nil {
		var refused *adRefusal
		if errors.As(err, &refused) {
			return nil, err
		}
		return nil, notJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, notJSON
	}
	if _, isObject := value.(*adObject); !isObject && disabled != "arguments-json" {
		return nil, notJSON
	}
	return value, nil
}

// adMaxDepth bounds nesting on untrusted argument bytes, as the aee parser does.
const adMaxDepth = 128

func adParse(dec *json.Decoder, disabled string, depth int) (any, error) {
	if depth > adMaxDepth {
		return nil, errors.New("arguments nest too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			list := []any{}
			for dec.More() {
				item, err := adParse(dec, disabled, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, item)
			}
			_, err := dec.Token()
			return list, err
		}
		if t != '{' {
			return nil, fmt.Errorf("unexpected delimiter %v", t)
		}
		return adParseObject(dec, disabled, depth)
	case json.Number:
		return adNumber(string(t), disabled)
	default:
		return tok, nil
	}
}

func adParseObject(dec *json.Decoder, disabled string, depth int) (any, error) {
	obj := &adObject{values: map[string]any{}}
	duplicate := false
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := nameTok.(string)
		value, err := adParse(dec, disabled, depth+1)
		if err != nil {
			return nil, err
		}
		if _, seen := obj.values[name]; seen {
			duplicate = true
		} else {
			obj.names = append(obj.names, name)
		}
		obj.values[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if duplicate && disabled != "arguments-duplicate" {
		return nil, adMalformed("arguments-duplicate-member")
	}
	return obj, nil
}

func adNumber(literal, disabled string) (any, error) {
	if !strings.ContainsAny(literal, ".eE") {
		n, ok := new(big.Int).SetString(literal, 10)
		if !ok {
			return nil, fmt.Errorf("integer literal %s does not parse", literal)
		}
		if new(big.Int).Abs(n).Cmp(adMaxSafe) <= 0 {
			return adInt(n.Int64()), nil
		}
		if disabled != "arguments-integer" {
			return nil, adMalformed("arguments-integer-unsafe")
		}
		f, _ := new(big.Float).SetInt(n).Float64()
		return adFloat(f), nil
	}
	f, err := strconv.ParseFloat(literal, 64)
	if err != nil && !math.IsInf(f, 0) {
		return nil, err
	}
	if math.IsInf(f, 0) {
		if disabled == "arguments-overflow" {
			return nil, nil
		}
		return nil, adMalformed("arguments-number-overflow")
	}
	return adFloat(f), nil
}

// adCanonical is RFC 8785 over an admitted value.
func adCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := adWrite(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func adWrite(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case string:
		adWriteString(buf, t)
	case adInt:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case adFloat:
		s, err := adES6(float64(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := adWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case *adObject:
		names := append([]string{}, t.names...)
		sort.Slice(names, func(a, b int) bool { return adUTF16Less(names[a], names[b]) })
		buf.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				buf.WriteByte(',')
			}
			adWriteString(buf, name)
			buf.WriteByte(':')
			if err := adWrite(buf, t.values[name]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("not JSON: %T", v)
	}
	return nil
}

// adWriteString escapes only what RFC 8785 section 3.2.2.2 names; every other
// code point is written as raw UTF-8.
func adWriteString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
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

// adUTF16Less orders member names by UTF-16 code unit (RFC 8785 section 3.2.3),
// which differs from code point order once a name holds a character outside
// the Basic Multilingual Plane.
func adUTF16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// adES6 is ECMA-262 Number::toString for a finite double: plain digits from
// 1e-6 up to but excluding 1e21, the shortest exponent form outside that.
func adES6(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("RFC 8785 forbids NaN and Infinity")
	}
	if f == 0 {
		return "0", nil
	}
	if abs := math.Abs(f); abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	sign := exponent[:1]
	exponent = strings.TrimLeft(exponent[1:], "0")
	return mantissa + "e" + sign + exponent, nil
}
