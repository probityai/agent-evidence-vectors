// Package observedeffect verifies statements carrying the Observed Effect
// predicate, whose normative definition is spec/predicates/observed-effect.md.
//
// A mutation interval observed from a vantage the observed party does not
// control: the state root before, the state root after, the path scope the
// observation covered, and the digest of the authority under which mutation was
// permitted. The interval is not the contribution; binding it to independently
// observed execution is.
//
// This package is the second independent statement of those rules. The first is
// vectors-observed-effect/check_vectors.py, the reference verifier that shipped
// with the corpus, and the corpus was judged by nothing else: the repository's Go
// binary refused the directory by name, exit 2, because no reader answered for its
// suite. Two implementations in two languages that agree member by member is the
// only arrangement in which either can be caught being wrong, and neither reads
// the other: the rules here are ported from the specification text, the codes from
// the manifest's own declarations.
//
// Rule order is load-bearing. The first refusal is the code a member's manifest
// entry names, so reordering the table changes published expectations.
package observedeffect

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Verdict values. Malformed is a defect in the carried bytes, reached before any
// trust input; invalid is a coherent statement whose own rules refuse its claims.
const (
	verdictMalformed = "malformed"
	verdictInvalid   = "invalid"
	verdictValid     = "valid"
)

// StatementType is the in-toto statement envelope this predicate is carried in.
const StatementType = "https://in-toto.io/Statement/v1"

// Report is one verification. Codes carries the single first refusal, which is
// what the corpus pins: a verifier that reported every rule a record breaks would
// make the expectation depend on rule order in a second way.
type Report struct {
	Verdict string   `json:"verdict"`
	Codes   []string `json:"codes"`
	// DerivedTier is the tier RECOMPUTED from the record, never the tier the
	// record claims. Empty where the statement was refused before the recompute
	// could run.
	DerivedTier string `json:"derivedTier,omitempty"`
	// EffectsIndependentlyObserved says the reads and writes this record carries
	// were seen by somebody other than the observed party: the statement verified
	// and its vantage is below-observed, which stage one only admits from a
	// first-hand observer holding a commitment signed before the interval. It is
	// independent of the tier. A below-observed record that names a blind spot
	// inside its own scope recomputes to voluntary, and the writes it did see are
	// still witnessed; reading them as self-report would make an observer who
	// discloses a gap worth less than one who hides it.
	EffectsIndependentlyObserved bool `json:"effectsIndependentlyObserved"`
	// AbsenceEstablished says the record establishes that nothing it does not
	// carry happened inside pathScope: the statement verified and the recomputed
	// tier is authoritative. This is the reading the predicate forbids for a
	// voluntary record. Neither bit is copied from the record.
	AbsenceEstablished bool `json:"absenceEstablished"`
}

// fault is one refusal on its way out of a rule.
type fault struct {
	stage string
	code  string
}

func malformed(code string) *fault { return &fault{stage: verdictMalformed, code: code} }
func invalid(code string) *fault   { return &fault{stage: verdictInvalid, code: code} }

// Closed vocabularies. Fail-closed on an unknown value: a verifier that ignores a
// value it does not know reads a record it does not understand as conforming.
var (
	tiers           = set("voluntary", "authoritative")
	mutations       = set("observed", "none")
	hashAlgorithms  = set("sha256", "sha1")
	vantages        = set("below-observed", "peer", "self")
	baseResolutions = set("supplied", "recorded-parent", "empty-tree")
	readStates      = set("bytes-read", "no-bytes-read", "unavailable")
	agreements      = set("agree", "disagree", "one-sided")
	// origins is how the evidence in this record ARRIVED, which is a different
	// question from where the producer stood. Three of the four are the sibling
	// vocabulary's; first-hand is that registry's own, for a producer that
	// observed somebody else's execution itself.
	origins = set("self", "first-hand", "third-party-control-plane", "log-import")
	// importOrigins hold somebody else's log. An importer has no quote to
	// present, so it may not claim a hardware-rooted runtime.
	importOrigins = set("third-party-control-plane", "log-import")
)

// glob metacharacters. A scope carrying one is a pattern, and a pattern is
// resolved by whoever reads it; the universal scope is the literal "/".
const globMetacharacters = "*?[]{}!"

// timestampGrammar is RFC 3339, UTC, Z designator, no fractional second. The
// ordering rules compare strings, which is sound for exactly one grammar.
var timestampGrammar = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// emptyTree is the object name of the empty tree per hash algorithm: the terminal
// case of base resolution, and what makes beforeRoot unconditionally required
// rather than optional-when-unknown.
var emptyTree = map[string]string{
	// The empty tree's object name in the sha1 object format, written as a
	// literal. crypto/sha1 is blocklisted by this module's lint contract and
	// nothing else here needs a sha1 implementation, so the constant is stated
	// and then CHECKED rather than computed: a test asserts it equals the value
	// the corpus manifest publishes, which the reference verifier computes from
	// the same preimage in Python.
	"sha1":   "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
	"sha256": sha256Hex([]byte("tree 0\x00")),
}

// EmptyTree returns the empty-tree constant for one algorithm, so a caller
// constructing a base-resolution record does not restate the literal.
func EmptyTree(algorithm string) (string, bool) {
	value, ok := emptyTree[algorithm]
	return value, ok
}

// selfDerivable are the facts a statement determines about ITSELF. For these the
// observed side of a dual value is not a matter of report, and a verifier
// recomputes it: the member the predicate offers as catching a lying producer was
// a free string, so a record carrying two writes could declare writes.count
// observed as 7 and agree with itself.
var selfDerivable = map[string]func(*ctx) string{
	"writes.count":        func(c *ctx) string { return fmt.Sprint(len(c.list(c.pred, "writes"))) },
	"reads.count":         func(c *ctx) string { return fmt.Sprint(len(c.list(c.pred, "reads"))) },
	"pathScope.count":     func(c *ctx) string { return fmt.Sprint(len(c.list(c.pred, "pathScope"))) },
	"interval.beforeRoot": func(c *ctx) string { return c.str(c.interval(), "beforeRoot") },
	"interval.afterRoot":  func(c *ctx) string { return c.str(c.interval(), "afterRoot") },
	"authorityDigest":     func(c *ctx) string { return c.str(c.pred, "authorityDigest") },
}

// ctx is one statement under verification.
type ctx struct {
	stmt   map[string]any
	pred   map[string]any
	policy Policy
	// derivedTier is filled by the tier recompute so the report can carry it.
	derivedTier string
}

// rule is one named rule. The name is what the mutation table disables, and a
// rule whose removal changes no verdict measures nothing.
type rule struct {
	name string
	fn   func(*ctx) *fault
}

// rules runs in order because stage one precedes stage two and because the first
// refusal is the code the corpus pins.
func rules() []rule {
	return []rule{
		{"ijson-integers", ruleIJSONIntegers},
		{"predicate-type", rulePredicateType},
		{"required-members", ruleRequiredMembers},
		{"closed-vocabularies", ruleClosedVocabularies},
		{"timestamp-grammar", ruleTimestampGrammar},
		{"interval-order", ruleIntervalOrder},
		{"base-vocabulary", ruleBaseVocabulary},
		{"empty-tree-constant", ruleEmptyTreeConstant},
		{"path-scope-literal", rulePathScopeLiteral},
		{"paths-normalized", rulePathsNormalized},
		{"mutation-coherence", ruleMutationCoherence},
		{"write-chain", ruleWriteChain},
		{"subject-binding", ruleSubjectBinding},
		{"read-bindings", ruleReadBindings},
		{"range-preimage", ruleRangePreimage},
		{"read-chain", ruleReadChain},
		{"empty-tree-holds-no-bytes", ruleEmptyTreeHoldsNoBytes},
		{"coverage-coherence", ruleCoverageCoherence},
		{"coverage-gaps-named", ruleCoverageGapsNamed},
		{"origin-carries-the-vantage", ruleOriginCarriesTheVantage},
		{"import-origin-platform", ruleImportOriginPlatform},
		{"prior-commitment-present", rulePriorCommitmentPresent},
		{"commitment-digest", ruleCommitmentDigest},
		{"keyid-form", ruleKeyidForm},
		{"agreement-derivable", ruleAgreementDerivable},
		{"dual-value-recomputes", ruleDualValueRecomputes},
		{"commitment-signature", ruleCommitmentSignature},
		{"commitment-order", ruleCommitmentOrder},
		{"commitment-keyid-disjoint", ruleCommitmentKeyidDisjoint},
		{"write-scope", ruleWriteScope},
		{"tier-recompute", ruleTierRecompute},
		{"authoritative-carries-rows", ruleAuthoritativeCarriesRows},
	}
}

// RuleNames lists the rules in the order they run. Exported so a caller can
// report what it enforced; there is no exported way to turn one off.
func RuleNames() []string {
	all := rules()
	out := make([]string, 0, len(all))
	for _, r := range all {
		out = append(out, r.name)
	}
	return out
}

// Policy is what a consumer brings to a verification. Nothing here is read from
// the record: a record that carried its own expected predicate type, or its own
// key, would be grading its own homework.
type Policy struct {
	// PredicateType is the Type URI this consumer routes to. Required: a policy
	// carrying none refuses every statement, because a verifier that accepts any
	// predicate type has stopped checking which predicate it is reading.
	// PredicateTypeFromSpec reads it out of the document that defines it.
	PredicateType string
	// ObserverPublicKeyHex is the observer key the consumer anchored out of band.
	ObserverPublicKeyHex string
	// Blobs are the blobs this consumer holds, keyed by digest. A verifier
	// holding one recomputes the range preimage over it; a verifier holding none
	// treats the range digest as an opaque commitment, which is why the predicate
	// calls three of the four read bindings checkable rather than four.
	Blobs map[string][]byte
}

// PredicateTypeFromSpec reads the Type URI out of the predicate document that
// defines it, so no caller has to restate it. The reference verifier does the same
// thing for the same reason: the specification is the normative statement of what
// this predicate IS, and a constant in a second file is a second definition that
// can drift from it.
func PredicateTypeFromSpec(path string) (string, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- the caller names the specification document
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, found := strings.CutPrefix(line, "Type URI:"); found {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("%s states no Type URI line", path)
}

// Verify judges one DSSE envelope carrying an Observed Effect statement.
func Verify(raw []byte, policy Policy) *Report {
	return verify(raw, policy, "")
}

// verify is Verify with one rule disabled by name, which is how the mutation table
// asks whether that rule is load-bearing. The parameter is unexported and there is
// no flag, environment variable or build tag that reaches it: the seam exists for a
// test in this package and not for a caller.
func verify(raw []byte, policy Policy, skip string) *Report {
	envelope, payload, f := openEnvelope(raw)
	if f != nil {
		return &Report{Verdict: f.stage, Codes: []string{f.code}}
	}
	decoded, f := decodeIJSON(payload)
	if f != nil {
		return &Report{Verdict: f.stage, Codes: []string{f.code}}
	}
	stmt, ok := decoded.(map[string]any)
	if !ok {
		return &Report{Verdict: verdictMalformed, Codes: []string{"not-parseable"}}
	}
	c := &ctx{stmt: stmt, policy: policy}
	if f := c.prepare(); f != nil {
		return &Report{Verdict: f.stage, Codes: []string{f.code}}
	}
	for _, r := range rules() {
		if r.name == skip {
			continue
		}
		if f := r.fn(c); f != nil {
			return &Report{Verdict: f.stage, Codes: []string{f.code}, DerivedTier: c.derivedTier}
		}
	}
	if f := verifyEnvelopeSignature(envelope, payload, policy.ObserverPublicKeyHex); f != nil {
		return &Report{Verdict: f.stage, Codes: []string{f.code}, DerivedTier: c.derivedTier}
	}
	return &Report{
		Verdict:                      verdictValid,
		Codes:                        []string{},
		DerivedTier:                  c.derivedTier,
		EffectsIndependentlyObserved: c.str(c.observation(), "vantage") == "below-observed",
		AbsenceEstablished:           c.derivedTier == "authoritative",
	}
}

// prepare pulls the two members every rule below indexes.
func (c *ctx) prepare() *fault {
	if c.str(c.stmt, "_type") != StatementType {
		return malformed("statement-type-unexpected")
	}
	pred, ok := c.stmt["predicate"].(map[string]any)
	if !ok {
		return malformed("unhandled-shape:predicate")
	}
	c.pred = pred
	return nil
}

// openEnvelope decodes the DSSE envelope and its payload bytes.
func openEnvelope(raw []byte) (map[string]any, []byte, *fault) {
	decoded, f := decodeIJSON(raw)
	if f != nil {
		return nil, nil, f
	}
	envelope, ok := decoded.(map[string]any)
	if !ok {
		return nil, nil, malformed("not-parseable")
	}
	encoded, ok := envelope["payload"].(string)
	if !ok {
		return nil, nil, malformed("not-parseable")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, nil, malformed("not-parseable")
	}
	return envelope, payload, nil
}

// verifyEnvelopeSignature is the last gate, after every carried-bytes rule held.
func verifyEnvelopeSignature(envelope map[string]any, payload []byte, observerPublicKeyHex string) *fault {
	signatures, ok := envelope["signatures"].([]any)
	if !ok || len(signatures) == 0 {
		return malformed("envelope-signature-unreadable")
	}
	first, ok := signatures[0].(map[string]any)
	if !ok {
		return malformed("envelope-signature-unreadable")
	}
	encoded, ok := first["sig"].(string)
	if !ok {
		return malformed("envelope-signature-unreadable")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return malformed("envelope-signature-unreadable")
	}
	key, err := hex.DecodeString(observerPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return malformed("envelope-signature-unreadable")
	}
	payloadType, ok := envelope["payloadType"].(string)
	if !ok {
		return malformed("envelope-signature-unreadable")
	}
	if !ed25519.Verify(key, pae(payloadType, payload), signature) {
		return invalid("envelope-signature-invalid")
	}
	return nil
}

// pae is DSSE's pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// --- accessors -------------------------------------------------------------
//
// Lenient by design: a missing member reads as the zero value rather than as a
// distinct fault, because rule-required-members runs third and every member the
// rules below index is named there. A type that is wrong rather than absent falls
// through to the rule that states the value's vocabulary, which is where the
// refusal belongs -- a record whose tier is the number 3 is refused for carrying
// an unknown tier, not for a shape nobody described.

func (c *ctx) str(m map[string]any, name string) string {
	if m == nil {
		return ""
	}
	value, _ := m[name].(string)
	return value
}

func (c *ctx) list(m map[string]any, name string) []any {
	if m == nil {
		return nil
	}
	value, _ := m[name].([]any)
	return value
}

func (c *ctx) obj(m map[string]any, name string) map[string]any {
	if m == nil {
		return nil
	}
	value, _ := m[name].(map[string]any)
	return value
}

func (c *ctx) interval() map[string]any    { return c.obj(c.pred, "interval") }
func (c *ctx) observation() map[string]any { return c.obj(c.pred, "observation") }

// commitment returns the prior commitment and whether the record carries one.
func (c *ctx) commitment() (map[string]any, bool) {
	obs := c.observation()
	if obs == nil {
		return nil, false
	}
	raw, present := obs["priorCommitment"]
	if !present || raw == nil {
		return nil, false
	}
	value, ok := raw.(map[string]any)
	return value, ok
}

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func sha256Hex(preimage []byte) string {
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}

// requireMembers refuses a member that is absent, naming it. No member has a
// default and no verifier may supply one.
func requireMembers(m map[string]any, names ...string) *fault {
	for _, name := range names {
		if m == nil {
			return malformed("required-member-absent:" + name)
		}
		if _, present := m[name]; !present {
			return malformed("required-member-absent:" + name)
		}
	}
	return nil
}

// timestampOK is the grammar check, separated so several rules can state it.
func timestampOK(value any) bool {
	text, ok := value.(string)
	if !ok || !timestampGrammar.MatchString(text) {
		return false
	}
	_, err := time.Parse(time.RFC3339, text)
	return err == nil
}

// numberText renders a decoded JSON number back to its source spelling.
func numberText(value any) (json.Number, bool) {
	number, ok := value.(json.Number)
	return number, ok
}
