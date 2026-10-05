package corpora

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- the git empty-tree object name under sha1 is a published constant, not a MAC
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(auditRecord{}) }

// auditRecord judges vectors-agent-audit-record/, the conformance corpus of
// Appendix B of draft-gilda-wimse-agent-audit-record-03.
//
// It is the Go rail over that corpus, restated from the draft rather than
// imported from the Python reader at packaging/agent_evidence_vectors/
// auditrecord.py. The rules run in the order the draft's "Verifying a record"
// section gives: the signature over the RFC 8785 bytes, the JSON profile,
// membership, then the recomputes. The manifest pins one code per reject
// member and that code is the first refusal, so the order is part of the
// published answer and matches the Python reader's.
type auditRecord struct{}

func (auditRecord) Suite() string { return "agent-audit-record-conformance" }

const (
	arStatementType = "https://in-toto.io/Statement/v1"
	arPayloadType   = "application/vnd.in-toto+json"
	arMaxDepth      = 128
	arUnattributed  = "unattributed"
)

var arEmptyTree = map[string]string{
	"sha1":   arEmptyTreeDigest(true),
	"sha256": arEmptyTreeDigest(false),
}

func arEmptyTreeDigest(isSHA1 bool) string {
	if isSHA1 {
		sum := sha1.Sum([]byte("tree 0\x00")) // #nosec G401 -- a published object name, not a security use
		return hex.EncodeToString(sum[:])
	}
	return sha([]byte("tree 0\x00"))
}

var arVocabularies = []struct {
	path    string
	allowed []string
}{
	{"tier", []string{"voluntary", "authoritative"}},
	{"hashAlgorithm", []string{"sha256"}},
	{"agent.authentication", []string{"wimse-wpt", "http-message-signature", "mtls", "oauth-access-token", "none"}},
	{"delegation.subjectKind", []string{"user", "system", "none"}},
	{"resource.kind", []string{"path", "uri", "tool"}},
	{"resource.binding", []string{"digest-bound", "not-bindable"}},
	{"decision.reported", []string{"permit", "deny", "permit-with-conditions"}},
	{"effect.observed", []string{"occurred", "none", "unknown"}},
	{"effect.interval.baseResolution", []string{"supplied", "empty-tree"}},
	{"agreement", []string{"agree", "disagree", "not-exercised", "indeterminate", "one-sided"}},
	{"correlation.scope", []string{"producer", "cross-party"}},
	{"correlation.timeBasis", []string{"beacon-anchored", "asserted"}},
	{"correlation.externalAnchor.kind", []string{"rfc3161", "transparency-log", "opentimestamps"}},
	{"posture.reported", []string{"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}},
	{"posture.observed", []string{"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}},
	{"posture.agreement", []string{"agree", "disagree"}},
	{"observation.vantage", []string{"below-observed", "peer", "self"}},
	{"evaluation.status", []string{"evaluated", "not-evaluated"}},
	{"oversight.act", []string{"observation", "check", "decision", "release"}},
}

// arUnavailableInputs is the closed set an evaluation that did not happen
// names its missing inputs from: the standing source, the key source and the
// consumption state a verifier reads before it can decide, and the policy
// source a decision point reads its policy from.
var arUnavailableInputs = []string{"standing-source", "key-source", "consumption-state", "policy-source"}

// arEvaluationMembers are the only members an evaluation object may carry. A
// free-text reason beside the closed set would name an input nobody can compare.
var arEvaluationMembers = []string{"status", "unavailableInput"}

// arOversightMembers are the only members an oversight object may carry.
var arOversightMembers = []string{"act", "recordDigest"}

var arRemediationVocab = map[string][]string{
	"cause": {"session-revoked", "risk-elevated", "subject-disabled", "token-replay-suspected",
		"policy-changed", "operator-action"},
	"enforcement": {"access-attenuated", "session-terminated", "tokens-discarded",
		"privileges-reduced", "reevaluated", "not-enforced"},
	"postEnforcementEffect": {"occurred", "none", "unknown"},
}

var arTopMembers = []string{
	"recordId", "tier", "hashAlgorithm", "agent", "delegation", "resource", "decision",
	"effect", "agreement", "correlation", "posture", "remediation", "observation",
	"fieldEvidence", "doesNotAssert", "issuedAt", "evaluation",
}

var arNestedMembers = []struct {
	path  string
	names []string
}{
	{"agent", []string{"id", "credentialDigest", "authentication", "signers"}},
	{"delegation", []string{"subject", "subjectKind", "authorityDigest"}},
	{"resource", []string{"kind", "id", "binding"}},
	{"decision", []string{"action", "requestDigest", "reported", "decisionPointId", "policyDigest", "reportedAt"}},
	{"effect", []string{"observed", "interval", "pathScope", "writes"}},
	{"effect.interval", []string{"beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"}},
	{"correlation", []string{"id", "scope", "timeBasis"}},
	{"posture", []string{"reported", "reportedDigest", "observed", "observedDigest", "assessedAt", "agreement"}},
	{"observation", []string{"vantage", "coverage"}},
	{"observation.coverage", []string{"scopeComplete", "gaps"}},
	{"evaluation", []string{"status"}},
}

var (
	arWriteMembers       = []string{"path", "preStateDigest", "postStateDigest", "requestDigest", "inScope"}
	arRemediationMembers = []string{"cause", "signalReceivedAt", "enforcedAt", "enforcement",
		"postEnforcementEffect", "postEnforcementRoot"}
	arCommitmentMembers = []string{"committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig"}
	arFieldEvidenceKeys = []string{"agent", "correlation", "decision", "delegation", "posture",
		"remediation", "resource"}
)

// errMalformed carries the first refusal code.
type errMalformed struct{ code string }

func (e errMalformed) Error() string { return e.code }

func arRefuse(code string) error { return errMalformed{code} }

type arState struct {
	statement map[string]any
	pred      map[string]any
	tier      string
}

// arAt walks a dotted path through nested objects. A missing or mistyped step
// returns ok=false, which the rules read as a shape defect.
func arAt(root map[string]any, dotted string) (any, bool) {
	var node any = root
	for _, part := range strings.Split(dotted, ".") {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return node, true
}

func arObj(root map[string]any, dotted string) map[string]any {
	value, _ := arAt(root, dotted)
	object, _ := value.(map[string]any)
	return object
}

func arStr(root map[string]any, dotted string) string {
	value, _ := arAt(root, dotted)
	s, _ := value.(string)
	return s
}

func arList(root map[string]any, dotted string) []any {
	value, _ := arAt(root, dotted)
	list, _ := value.([]any)
	return list
}

func arContains(values []string, v string) bool {
	for _, candidate := range values {
		if candidate == v {
			return true
		}
	}
	return false
}

func arDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	return sha(canonical), nil
}

func arUnder(path, scope string) bool {
	if scope == "/" {
		return strings.HasPrefix(path, "/")
	}
	base := scope
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return path == strings.TrimSuffix(scope, "/") || strings.HasPrefix(path, base)
}

func arInstant(value string) (time.Time, error) {
	instant, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, arRefuse("timestamp-malformed")
	}
	return instant, nil
}

func arDepth(value any) int {
	best := 0
	switch t := value.(type) {
	case map[string]any:
		for _, child := range t {
			if d := arDepth(child); d > best {
				best = d
			}
		}
		return 1 + best
	case []any:
		for _, child := range t {
			if d := arDepth(child); d > best {
				best = d
			}
		}
		return 1 + best
	}
	return 0
}

// arParse applies the JSON profile and returns the RFC 8785 bytes and the
// decoded statement. A repeated name or an unsafe integer is refused by the
// canonicalizer; the depth bound is counted here with the top-level value as
// level one, so a Statement nested 129 levels deep is refused.
func arParse(payload []byte) ([]byte, map[string]any, error) {
	if err := aee.CheckIJSON(payload); err != nil {
		switch {
		case errors.Is(err, aee.ErrDuplicateMember):
			return nil, nil, arRefuse("duplicate-member")
		case errors.Is(err, aee.ErrUnsafeInteger):
			return nil, nil, arRefuse("unsafe-integer")
		case errors.Is(err, aee.ErrNonIntegerNumber):
			return nil, nil, arRefuse("value-not-representable")
		case errors.Is(err, aee.ErrInputTooDeep):
			return nil, nil, arRefuse("nesting-too-deep")
		}
		return nil, nil, arRefuse("not-parseable")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, nil, arRefuse("not-parseable")
	}
	if arDepth(value) > arMaxDepth {
		return nil, nil, arRefuse("nesting-too-deep")
	}
	canonical, err := aee.Canonicalize(payload)
	if err != nil {
		if errors.Is(err, aee.ErrInputTooDeep) {
			return nil, nil, arRefuse("nesting-too-deep")
		}
		return nil, nil, arRefuse("not-parseable")
	}
	statement, ok := value.(map[string]any)
	if !ok {
		return nil, nil, arRefuse("statement-shape")
	}
	return canonical, statement, nil
}

type arReport struct {
	verdict string
	code    string
	tier    string
}

// arVerify judges one DSSE envelope. disabled names one rule to skip, which is
// how the mutation test asks whether that rule is load-bearing.
func arVerify(raw []byte, predicateType, observerKey, disabled string) arReport {
	var envelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := aee.CheckIJSON(raw); err != nil || json.Unmarshal(raw, &envelope) != nil ||
		envelope.PayloadType != arPayloadType {
		return arReport{verdict: "malformed", code: "envelope-unreadable"}
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return arReport{verdict: "malformed", code: "envelope-unreadable"}
	}
	canonical, statement, err := arParse(payload)
	if err != nil {
		return arReport{verdict: "malformed", code: err.Error()}
	}
	if disabled != "signature" && !arSignatureHolds(envelope.Signatures, canonical, observerKey) {
		return arReport{verdict: "malformed", code: "signature-invalid"}
	}
	pred, ok := statement["predicate"].(map[string]any)
	if _, isList := statement["subject"].([]any); !ok || !isList {
		return arReport{verdict: "malformed", code: "statement-shape"}
	}
	state := &arState{statement: statement, pred: pred}
	for _, rule := range arRules(predicateType) {
		if rule.name == disabled {
			continue
		}
		if err := arRun(rule.check, state); err != nil {
			return arReport{verdict: "malformed", code: err.Error(), tier: state.tier}
		}
	}
	return arReport{verdict: "valid", tier: state.tier}
}

// arRun converts a panic from a mistyped member into a refusal, so one member
// with a shape no rule names cannot stop the replay of the rest.
func arRun(check func(*arState) error, state *arState) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = arRefuse("unhandled-shape")
		}
	}()
	return check(state)
}

func arSignatureHolds(signatures []struct {
	Sig string `json:"sig"`
}, canonical []byte, observerKey string) bool {
	key, err := hex.DecodeString(observerKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	message := aee.PAE(arPayloadType, canonical)
	for _, entry := range signatures {
		sig, err := base64.StdEncoding.DecodeString(entry.Sig)
		if err == nil && ed25519.Verify(ed25519.PublicKey(key), message, sig) {
			return true
		}
	}
	return false
}

type arRule struct {
	name  string
	check func(*arState) error
}

func arRules(predicateType string) []arRule {
	return []arRule{
		{"statement", func(s *arState) error {
			if s.statement["_type"] != arStatementType {
				return arRefuse("statement-type-unexpected")
			}
			if s.statement["predicateType"] != predicateType {
				return arRefuse("predicate-type-mismatch")
			}
			return nil
		}},
		{"subject-interval", arRuleSubjectInterval},
		{"required-members", arRuleRequiredMembers},
		{"closed-vocabularies", arRuleVocabularies},
		{"evaluation", arRuleEvaluation},
		{"oversight", arRuleOversight},
		{"delegation", func(s *arState) error {
			if arStr(s.pred, "delegation.subjectKind") == "none" && arStr(s.pred, "delegation.subject") != "none" {
				return arRefuse("delegation-subject-inconsistent")
			}
			return nil
		}},
		{"binding", arRuleBinding},
		{"request-digest", arRuleRequestDigest},
		{"subject-after-root", func(s *arState) error {
			subject := s.statement["subject"].([]any)
			digest := arStr(subject[1].(map[string]any), "digest.sha256")
			if digest != arStr(s.pred, "effect.interval.afterRoot") {
				return arRefuse("subject-after-root-mismatch")
			}
			return nil
		}},
		{"external-anchor", func(s *arState) error {
			correlation := arObj(s.pred, "correlation")
			_, anchor := correlation["externalAnchor"]
			if (correlation["timeBasis"] == "beacon-anchored") != anchor {
				return arRefuse("external-anchor-inconsistent")
			}
			return nil
		}},
		{"remediation-order", arRuleRemediationOrder},
		{"empty-tree", func(s *arState) error {
			if arStr(s.pred, "effect.interval.baseResolution") != "empty-tree" {
				return nil
			}
			if arStr(s.pred, "effect.interval.beforeRoot") != arEmptyTree[arStr(s.pred, "hashAlgorithm")] {
				return arRefuse("empty-tree-constant-mismatch")
			}
			return nil
		}},
		{"commitment", arRuleCommitment},
		{"write-chain", arRuleWriteChain},
		{"path-scope-literal", func(s *arState) error {
			for _, scope := range arList(s.pred, "effect.pathScope") {
				text, ok := scope.(string)
				if !ok || strings.ContainsAny(text, "*?[]{}") {
					return arRefuse("path-scope-glob")
				}
			}
			return nil
		}},
		{"tier", arRuleTier},
		{"write-scope", arRuleWriteScope},
		{"observed", func(s *arState) error {
			if arStr(s.pred, "effect.observed") != arDeriveObserved(s.pred) {
				return arRefuse("effect-observed-underivable")
			}
			return nil
		}},
		{"agreement", arRuleAgreement},
		{"posture-agreement", func(s *arState) error {
			p := arObj(s.pred, "posture")
			equal := p["reported"] == p["observed"] && p["reportedDigest"] == p["observedDigest"]
			want := "disagree"
			if equal {
				want = "agree"
			}
			if p["agreement"] != want {
				return arRefuse("posture-agreement-underivable")
			}
			return nil
		}},
		{"field-evidence", arRuleFieldEvidence},
	}
}

func arRuleSubjectInterval(s *arState) error {
	_, hasInterval := arAt(s.pred, "effect.interval")
	want := 1
	if hasInterval {
		want = 2
	}
	if len(s.statement["subject"].([]any)) != want {
		return arRefuse("subject-interval-mismatch")
	}
	return nil
}

func arHasAll(object map[string]any, names []string) bool {
	if object == nil {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func arRuleRequiredMembers(s *arState) error {
	if !arHasAll(s.pred, arTopMembers) {
		return arRefuse("member-missing")
	}
	for _, nested := range arNestedMembers {
		if !arHasAll(arObj(s.pred, nested.path), nested.names) {
			return arRefuse("member-missing")
		}
	}
	for _, write := range arList(s.pred, "effect.writes") {
		object, _ := write.(map[string]any)
		if !arHasAll(object, arWriteMembers) {
			return arRefuse("member-missing")
		}
	}
	for _, row := range arList(s.pred, "remediation") {
		object, _ := row.(map[string]any)
		if !arHasAll(object, arRemediationMembers) {
			return arRefuse("member-missing")
		}
	}
	return nil
}

func arRuleVocabularies(s *arState) error {
	for _, vocab := range arVocabularies {
		value, present := arAt(s.pred, vocab.path)
		if !present {
			continue // only correlation.externalAnchor.kind is conditional; its rule runs later
		}
		text, _ := value.(string)
		if !arContains(vocab.allowed, text) {
			return arRefuse("value-outside-vocabulary")
		}
	}
	for _, row := range arList(s.pred, "remediation") {
		object := row.(map[string]any)
		for _, name := range sortedKeys(arRemediationVocab) {
			text, _ := object[name].(string)
			if !arContains(arRemediationVocab[name], text) {
				return arRefuse("value-outside-vocabulary")
			}
		}
	}
	for _, value := range arObj(s.pred, "fieldEvidence") {
		if value != "substrate-covered" && value != "producer-asserted" {
			return arRefuse("value-outside-vocabulary")
		}
	}
	return nil
}

// arRuleEvaluation holds the evaluation member to its two shapes. An evaluated
// decision names no unavailable input; a decision that could not be evaluated
// names at least one, each once, from the closed set. The reported decision and
// the agreement table are not read here: a verifier that could not evaluate
// still reports what it enforced, and this member says why.
func arRuleEvaluation(s *arState) error {
	evaluation := arObj(s.pred, "evaluation")
	for name := range evaluation {
		if !arContains(arEvaluationMembers, name) {
			return arRefuse("evaluation-malformed")
		}
	}
	raw, carried := evaluation["unavailableInput"]
	if evaluation["status"] == "evaluated" {
		if carried {
			return arRefuse("evaluation-inconsistent")
		}
		return nil
	}
	inputs, ok := raw.([]any)
	if !carried || !ok || len(inputs) == 0 {
		return arRefuse("evaluation-inconsistent")
	}
	seen := map[string]bool{}
	for _, item := range inputs {
		text, _ := item.(string)
		if !arContains(arUnavailableInputs, text) {
			return arRefuse("value-outside-vocabulary")
		}
		if seen[text] {
			return arRefuse("evaluation-inconsistent")
		}
		seen[text] = true
	}
	return nil
}

// arRuleOversight checks the optional oversight member when it is present: an
// act from the closed set, which the vocabulary rule already held, and at most
// a digest of the overseer's own signed record beside it.
func arRuleOversight(s *arState) error {
	raw, present := s.pred["oversight"]
	if !present {
		return nil
	}
	oversight, ok := raw.(map[string]any)
	if !ok {
		return arRefuse("oversight-malformed")
	}
	if _, has := oversight["act"]; !has {
		return arRefuse("member-missing")
	}
	for name, value := range oversight {
		if !arContains(arOversightMembers, name) {
			return arRefuse("oversight-malformed")
		}
		if name == "recordDigest" {
			text, _ := value.(string)
			if !arIsDigest(text) {
				return arRefuse("oversight-malformed")
			}
		}
	}
	return nil
}

func arIsDigest(text string) bool {
	if len(text) != 64 {
		return false
	}
	for _, r := range text {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func arRuleBinding(s *arState) error {
	resource := arObj(s.pred, "resource")
	_, carried := resource["argumentsDigest"]
	if resource["binding"] == "digest-bound" && !carried {
		return arRefuse("arguments-digest-missing")
	}
	if resource["binding"] == "not-bindable" && carried {
		return arRefuse("arguments-digest-forbidden")
	}
	return nil
}

// arRequestDigest is the RFC 8785 digest over action, argumentsDigest,
// resourceId and resourceKind; under not-bindable the object holds no
// argumentsDigest member at all.
func arRequestDigest(pred map[string]any) (string, error) {
	resource := arObj(pred, "resource")
	body := map[string]any{
		"action":       arStr(pred, "decision.action"),
		"resourceId":   resource["id"],
		"resourceKind": resource["kind"],
	}
	if resource["binding"] == "digest-bound" {
		body["argumentsDigest"] = resource["argumentsDigest"]
	}
	return arDigest(body)
}

func arRuleRequestDigest(s *arState) error {
	recomputed, err := arRequestDigest(s.pred)
	if err != nil || arStr(s.pred, "decision.requestDigest") != recomputed {
		return arRefuse("request-digest-mismatch")
	}
	first, _ := s.statement["subject"].([]any)[0].(map[string]any)
	if arStr(first, "digest.sha256") != recomputed {
		return arRefuse("subject-request-mismatch")
	}
	return nil
}

func arRuleRemediationOrder(s *arState) error {
	for _, row := range arList(s.pred, "remediation") {
		object := row.(map[string]any)
		enforced, err := arInstant(fmt.Sprint(object["enforcedAt"]))
		if err != nil {
			return err
		}
		signal, err := arInstant(fmt.Sprint(object["signalReceivedAt"]))
		if err != nil {
			return err
		}
		if enforced.Before(signal) {
			return arRefuse("remediation-order")
		}
	}
	return nil
}

func arCommitment(pred map[string]any) (map[string]any, bool) {
	commitment := arObj(pred, "observation.priorCommitment")
	return commitment, arHasAll(commitment, arCommitmentMembers)
}

func arRuleCommitment(s *arState) error {
	commitment, complete := arCommitment(s.pred)
	if !complete {
		return nil
	}
	committed, err := arInstant(fmt.Sprint(commitment["committedAt"]))
	if err != nil {
		return err
	}
	opened, err := arInstant(arStr(s.pred, "effect.interval.openedAt"))
	if err != nil {
		return err
	}
	if !committed.Before(opened) {
		return arRefuse("commitment-order")
	}
	digest, err := arDigest(map[string]any{
		"authorityDigest": arStr(s.pred, "delegation.authorityDigest"),
		"beforeRoot":      arStr(s.pred, "effect.interval.beforeRoot"),
		"recordId":        s.pred["recordId"],
		"witnessNonce":    commitment["witnessNonce"],
	})
	if err != nil || commitment["commitmentDigest"] != digest {
		return arRefuse("commitment-digest-mismatch")
	}
	for _, signer := range arList(s.pred, "agent.signers") {
		if signer == commitment["keyid"] {
			return arRefuse("commitment-key-is-agent-signer")
		}
	}
	return nil
}

func arRuleWriteChain(s *arState) error {
	current := arStr(s.pred, "effect.interval.beforeRoot")
	for _, write := range arList(s.pred, "effect.writes") {
		object := write.(map[string]any)
		if object["preStateDigest"] != current {
			return arRefuse("write-chain-broken")
		}
		current, _ = object["postStateDigest"].(string)
	}
	if current != arStr(s.pred, "effect.interval.afterRoot") {
		return arRefuse("write-chain-broken")
	}
	return nil
}

func arScope(pred map[string]any) []string {
	var scope []string
	for _, entry := range arList(pred, "effect.pathScope") {
		text, _ := entry.(string)
		scope = append(scope, text)
	}
	return scope
}

func arInAnyScope(path string, scope []string) bool {
	for _, s := range scope {
		if arUnder(path, s) {
			return true
		}
	}
	return false
}

// arTierFailures lists the tier clauses a record fails, in the draft's order.
func arTierFailures(pred map[string]any) []string {
	var failed []string
	if arStr(pred, "observation.vantage") != "below-observed" {
		failed = append(failed, "tier-overclaim-vantage")
	}
	if _, complete := arCommitment(pred); !complete {
		failed = append(failed, "tier-overclaim-commitment")
	}
	scope := arScope(pred)
	if len(scope) == 0 {
		failed = append(failed, "tier-overclaim-scope")
	}
	gapInside := false
	for _, gap := range arList(pred, "observation.coverage.gaps") {
		text, _ := gap.(string)
		if arInAnyScope(text, scope) {
			gapInside = true
		}
	}
	complete, _ := arAt(pred, "observation.coverage.scopeComplete")
	if complete != true && gapInside {
		failed = append(failed, "tier-overclaim-coverage")
	}
	if arStr(pred, "resource.binding") != "digest-bound" {
		failed = append(failed, "tier-overclaim-binding")
	}
	return failed
}

func arRuleTier(s *arState) error {
	failed := arTierFailures(s.pred)
	s.tier = "authoritative"
	if len(failed) > 0 {
		s.tier = "voluntary"
	}
	if s.pred["tier"] == "authoritative" && len(failed) > 0 {
		return arRefuse(failed[0])
	}
	return nil
}

func arRuleWriteScope(s *arState) error {
	scope := arScope(s.pred)
	for _, write := range arList(s.pred, "effect.writes") {
		object := write.(map[string]any)
		path, _ := object["path"].(string)
		if object["inScope"] != arInAnyScope(path, scope) {
			return arRefuse("write-scope-mismatch")
		}
	}
	return nil
}

// arDeriveObserved: occurred for a write attributed to this request; none for
// no such write and no unattributed write inside pathScope; unknown otherwise.
func arDeriveObserved(pred map[string]any) string {
	own := arStr(pred, "decision.requestDigest")
	scope := arScope(pred)
	unknown := false
	for _, write := range arList(pred, "effect.writes") {
		object := write.(map[string]any)
		if object["requestDigest"] == own {
			return "occurred"
		}
		path, _ := object["path"].(string)
		if object["requestDigest"] == arUnattributed && arInAnyScope(path, scope) {
			unknown = true
		}
	}
	if unknown {
		return "unknown"
	}
	return "none"
}

func arDeriveAgreement(reported, observed string) string {
	switch {
	case observed == "unknown":
		return "indeterminate"
	case reported == "deny" && observed == "none":
		return "agree"
	case reported == "deny":
		return "disagree"
	case observed == "occurred":
		return "agree"
	}
	return "not-exercised"
}

func arRuleAgreement(s *arState) error {
	agreement := arStr(s.pred, "agreement")
	if agreement == "one-sided" {
		return arRefuse("agreement-reserved-value")
	}
	if agreement != arDeriveAgreement(arStr(s.pred, "decision.reported"), arStr(s.pred, "effect.observed")) {
		return arRefuse("agreement-underivable")
	}
	return nil
}

func arRuleFieldEvidence(s *arState) error {
	evidence := arObj(s.pred, "fieldEvidence")
	keys := sortedKeys(evidence)
	if strings.Join(keys, ",") != strings.Join(arFieldEvidenceKeys, ",") {
		return arRefuse("field-evidence-keys")
	}
	if arStr(s.pred, "observation.vantage") == "self" {
		for _, value := range evidence {
			if value == "substrate-covered" {
				return arRefuse("field-evidence-self-substrate")
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The corpus judge.
// ---------------------------------------------------------------------------

type arManifest struct {
	PredicateType string            `json:"predicateType"`
	Counts        map[string]int    `json:"counts"`
	EmptyTree     map[string]string `json:"emptyTree"`
	CorpusDigest  string            `json:"corpusDigest"`
	Keys          struct {
		Observer struct {
			PublicKey string `json:"publicKey"`
		} `json:"observer"`
	} `json:"keys"`
	Vectors []arVector `json:"vectors"`
}

type arVector struct {
	ID       string `json:"id"`
	DraftID  string `json:"draftId"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Parent   string `json:"parent"`
	Expected struct {
		// A pointer, because an indeterminate member must carry no verdict at
		// all and an absent field has to be told apart from an empty one.
		Verdict     *string  `json:"verdict"`
		Codes       []string `json:"codes"`
		DerivedTier *string  `json:"derivedTier"`
	} `json:"expected"`
	Readings []struct {
		Verdict string `json:"verdict"`
	} `json:"readings"`
}

func (auditRecord) Judge(dir string, raw []byte) (*Result, error) {
	var manifest arManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	byID := map[string]arVector{}
	for _, v := range manifest.Vectors {
		byID[v.ID] = v
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(manifest.Vectors))
	files := make([]string, 0, len(manifest.Vectors))
	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		member.Findings = append(member.Findings, arJudgeMember(dir, &manifest, v, byID)...)
		result.Members = append(result.Members, member)
	}
	result.Findings = arCorpusFindings(dir, &manifest, ids, files)
	return result, nil
}

func arJudgeMember(dir string, manifest *arManifest, v arVector, byID map[string]arVector) []string {
	label := v.DraftID
	var findings []string
	if v.Kind == "reject" && byID[v.Parent].Kind != "accept" {
		findings = append(findings, label+": names no accept parent")
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		return append(findings, label+": the member file cannot be read")
	}
	if idFromBytes(body) != v.ID {
		findings = append(findings, label+": identifier does not recompute from the member's own bytes")
	}
	report := arVerify(body, manifest.PredicateType, manifest.Keys.Observer.PublicKey, "")
	switch v.Kind {
	case "accept", "reject":
		findings = append(findings, arDeclaredFindings(label, v, report)...)
	case "indeterminate":
		var allowed []string
		for _, reading := range v.Readings {
			allowed = append(allowed, reading.Verdict)
		}
		sort.Strings(allowed)
		if v.Expected.Verdict != nil {
			findings = append(findings, label+": declared indeterminate and pins expected.verdict beside "+
				"readings, so a scorer reading that field marks a listed reading wrong")
		} else if len(allowed) < 2 {
			findings = append(findings, label+": declared indeterminate and names fewer than two readings")
		} else if !arContains(allowed, report.verdict) {
			findings = append(findings, fmt.Sprintf("%s: this rail took %q, outside %v", label, report.verdict, allowed))
		}
	default:
		findings = append(findings, fmt.Sprintf("%s: kind %q is not one this rail replays", label, v.Kind))
	}
	return findings
}

func arDeclaredFindings(label string, v arVector, report arReport) []string {
	declared := ""
	if v.Expected.Verdict != nil {
		declared = *v.Expected.Verdict
	}
	if report.verdict != declared {
		return []string{fmt.Sprintf("%s: expected %s, got %s [%s]", label, declared, report.verdict, report.code)}
	}
	want := strings.Join(v.Expected.Codes, ",")
	if want != report.code {
		return []string{fmt.Sprintf("%s: expected codes [%s], got [%s]", label, want, report.code)}
	}
	if report.verdict == "valid" && (v.Expected.DerivedTier == nil || *v.Expected.DerivedTier != report.tier) {
		return []string{fmt.Sprintf("%s: expected derivedTier differs from recomputed %q", label, report.tier)}
	}
	return nil
}

func arCorpusFindings(dir string, manifest *arManifest, ids, files []string) []string {
	var findings []string
	measured := map[string]int{}
	for _, v := range manifest.Vectors {
		measured[v.Kind]++
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		findings = append(findings, bad)
	}
	for algorithm, constant := range arEmptyTree {
		if manifest.EmptyTree[algorithm] != constant {
			findings = append(findings, "the manifest's "+algorithm+" empty-tree constant is not the one this rail computes")
		}
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		findings = append(findings, "the corpus digest could not be recomputed: "+err.Error())
	} else if digest != manifest.CorpusDigest {
		findings = append(findings, "corpusDigest does not match the member files on disk")
	}
	return findings
}
