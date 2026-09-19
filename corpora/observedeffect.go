package corpora

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- see oeEmptyTree for why a git object name is not a security primitive here
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/astrogilda/agent-evidence-vectors/aee"
)

func init() { register(observedEffect{}) }

// observedEffect judges vectors-observed-effect/, the Observed Effect predicate
// corpus, by replaying every member through a verifier stated here.
//
// This reader is the SECOND RAIL. The corpus ships its own reference verifier at
// vectors-observed-effect/check_vectors.py, and that file says why it imports
// nothing from the generator: two independent statements of one rule is the only
// arrangement in which either can fail. The same argument is why the rules below
// are written out rather than shelled out to. If this reader called that script,
// a rule wrong in both places would be a rule the repository reports as checked
// twice, and nothing in the tree would disagree.
//
// The verdict vocabulary is the predicate's own, in two stages. MALFORMED is a
// defect in the carried bytes, decided before any trust input is read. INVALID
// is a coherent statement whose claims its own rules refuse. The order the rules
// run in is therefore load-bearing, not incidental: the manifest names ONE code
// per reject member, and that code is the FIRST refusal, so a reordering here
// changes the answer for members that carry more than one fault.
//
// Where a member is present with the wrong JSON type, the accessors below read
// it as absent rather than refusing on the type. The reference rail reaches the
// same inputs as a Python KeyError or TypeError and reports them under one
// catch-all code; neither spelling is exercised by this corpus, whose members
// are all well-typed, and the difference is recorded here rather than left for a
// reader to discover from a diff of two refusals.
type observedEffect struct{}

func (observedEffect) Suite() string { return "observed-effect-conformance" }

// The two-stage verdict vocabulary, and the third state an indeterminate member
// is graded against.
const (
	oeValid         = "valid"
	oeMalformed     = "malformed"
	oeInvalid       = "invalid"
	oeIndeterminate = "indeterminate"
)

// The closed vocabularies. Fail-closed on an unknown value is a rule of the
// predicate rather than a convenience: a verifier that passes a value it does
// not recognise has decided the member is fine on the strength of not having
// read it.
var (
	oeTiers          = map[string]bool{"voluntary": true, "authoritative": true}
	oeMutations      = map[string]bool{"observed": true, "none": true}
	oeVantages       = map[string]bool{"below-observed": true, "peer": true, "self": true}
	oeBaseResolution = map[string]bool{"supplied": true, "recorded-parent": true, "empty-tree": true}
	oeReadStates     = map[string]bool{"bytes-read": true, "no-bytes-read": true, "unavailable": true}
	oeAgreements     = map[string]bool{"agree": true, "disagree": true, "one-sided": true}
	oeHashAlgorithms = map[string]bool{"sha256": true, "sha1": true}
)

// oeGlobMetacharacters is the set a path scope entry may not contain. A scope
// that can match more than one path is a scope whose coverage cannot be decided
// from the record.
const oeGlobMetacharacters = "*?[]{}!"

// oeStatementType is the in-toto Statement version every member carries.
const oeStatementType = "https://in-toto.io/Statement/v1"

// oeEmptyTree is the empty-tree object name per hash algorithm, COMPUTED here
// rather than pinned. The corpus publishes both constants in its manifest and
// one member exists to catch a verifier that accepts either one for either
// algorithm, so a reader that read the constants out of the manifest would be
// checking the manifest against itself.
//
// SHA-1 appears because git names an empty tree with it and a repository that
// has not migrated still does. It is used here to reproduce that name and for
// nothing else: no signature, no integrity decision and no trust input passes
// through it, so gosec's weak-hash rules are false positives on this call and
// are suppressed at the two places they fire rather than globally.
var oeEmptyTree = map[string]string{
	"sha1":   oeSHA1Hex([]byte("tree 0\x00")),
	"sha256": sha([]byte("tree 0\x00")),
}

func oeSHA1Hex(body []byte) string {
	sum := sha1.Sum(body) // #nosec G401 -- reproducing a git object name, not hashing for security; see oeEmptyTree
	return hex.EncodeToString(sum[:])
}

// oeBlob is the one blob this corpus narrates. It is stated here for the reason
// the reference rail states it too: the range-preimage rule is only checked
// against bytes the checking rail holds, and a rail that read them from the
// corpus would be asking the corpus whether the corpus is right.
func oeBlob() []byte {
	return []byte(strings.Repeat("port: 8080\nmode: strict\n", 8))
}

func oeBlobs() map[string][]byte {
	blob := oeBlob()
	return map[string][]byte{sha(blob): blob}
}

// oeFault is one rule's refusal: the stage it belongs to and the code the
// manifest names it by.
type oeFault struct {
	verdict string
	code    string
}

func oeMalformedAt(code string) *oeFault { return &oeFault{verdict: oeMalformed, code: code} }
func oeInvalidAt(code string) *oeFault   { return &oeFault{verdict: oeInvalid, code: code} }

// oeOutcome is what a verifier answers for one member.
type oeOutcome struct {
	verdict string
	codes   []string
}

// oeObj is a decoded JSON object. The predicate is read as a map rather than
// into a struct because half of these rules are about a member being ABSENT, and
// a struct field cannot tell an absent member from one carrying its zero value.
type oeObj map[string]any

func (o oeObj) has(name string) bool {
	_, present := o[name]
	return present
}

func (o oeObj) obj(name string) oeObj {
	nested, _ := o[name].(map[string]any)
	return oeObj(nested)
}

func (o oeObj) arr(name string) []any {
	items, _ := o[name].([]any)
	return items
}

func (o oeObj) str(name string) string {
	text, _ := o[name].(string)
	return text
}

func (o oeObj) flag(name string) bool {
	value, _ := o[name].(bool)
	return value
}

// integer reads a member that has to be a whole number. The decoder keeps every
// number as json.Number so that 64 and 64.0 stay distinguishable: the predicate
// requires an integer offset, and a rail that routed both through float64 would
// accept a fractional byte offset as a whole one.
func (o oeObj) integer(name string) (int64, bool) {
	number, ok := o[name].(json.Number)
	if !ok {
		return 0, false
	}
	text := number.String()
	if strings.ContainsAny(text, ".eE") {
		return 0, false
	}
	value, err := number.Int64()
	if err != nil {
		return 0, false
	}
	return value, true
}

func oeRow(item any) oeObj {
	row, _ := item.(map[string]any)
	return oeObj(row)
}

// oeRequire refuses the first absent member by name. No member of this predicate
// has a default and no verifier may supply one, so the code carries the member:
// "the record is incomplete" is not something an implementer can act on.
func oeRequire(o oeObj, names ...string) *oeFault {
	for _, name := range names {
		if !o.has(name) {
			return oeMalformedAt("required-member-absent:" + name)
		}
	}
	return nil
}

// oeRule is one rule of the predicate. The blob set is passed to every rule
// rather than to the one that reads it, so that the ordered list below is a list
// of rules and not a list of rules plus a special case.
type oeRule func(pred oeObj, blobs map[string][]byte) *oeFault

// oeRules is the predicate's rules in the order they decide. Stage one precedes
// stage two, and within a stage the order is the one the corpus's codes were
// recorded under.
var oeRules = []oeRule{
	oeRuleRequiredMembers,
	oeRuleClosedVocabularies,
	oeRuleIntervalOrder,
	oeRuleBaseVocabulary,
	oeRuleEmptyTreeConstant,
	oeRulePathScopeLiteral,
	oeRuleMutationCoherence,
	oeRuleWriteChain,
	oeRuleReadBindings,
	oeRuleRangePreimage,
	oeRuleReadChain,
	oeRuleCoverageCoherence,
	oeRuleCommitmentDigest,
	oeRuleAgreementDerivable,
	oeRuleCommitmentOrder,
	oeRuleCommitmentKeyidDisjoint,
	oeRuleWriteScope,
	oeRuleTierRecompute,
}

func oeRuleRequiredMembers(pred oeObj, _ map[string][]byte) *oeFault {
	if fault := oeRequire(pred,
		"intervalId", "tier", "mutation", "hashAlgorithm", "interval", "pathScope",
		"authorityDigest", "observation", "reads", "writes", "dualValues",
		"doesNotAssert", "issuedAt"); fault != nil {
		return fault
	}
	if fault := oeRequire(pred.obj("interval"),
		"beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"); fault != nil {
		return fault
	}
	return oeRequire(pred.obj("observation"), "vantage", "coverage", "observedSigners")
}

func oeRuleClosedVocabularies(pred oeObj, _ map[string][]byte) *oeFault {
	if !oeTiers[pred.str("tier")] {
		return oeMalformedAt("tier-unknown")
	}
	if !oeMutations[pred.str("mutation")] {
		return oeMalformedAt("mutation-unknown")
	}
	if !oeHashAlgorithms[pred.str("hashAlgorithm")] {
		return oeMalformedAt("hash-algorithm-unknown")
	}
	if !oeVantages[pred.obj("observation").str("vantage")] {
		return oeMalformedAt("vantage-unknown")
	}
	return nil
}

// oeRuleIntervalOrder compares the timestamps as strings. Every one of them is
// a Zulu RFC 3339 instant of fixed width, for which lexical order IS temporal
// order, and parsing them into a time would let a record choose its own offset
// and therefore its own ordering.
func oeRuleIntervalOrder(pred oeObj, _ map[string][]byte) *oeFault {
	interval := pred.obj("interval")
	if interval.str("openedAt") >= interval.str("sealedAt") {
		return oeMalformedAt("interval-not-ordered")
	}
	if pred.str("issuedAt") < interval.str("sealedAt") {
		return oeMalformedAt("issued-before-sealed")
	}
	return nil
}

func oeRuleBaseVocabulary(pred oeObj, _ map[string][]byte) *oeFault {
	if !oeBaseResolution[pred.obj("interval").str("baseResolution")] {
		return oeMalformedAt("base-resolution-unknown")
	}
	return nil
}

// oeRuleEmptyTreeConstant requires the constant for the DECLARED algorithm, not
// either of the two. A verifier that accepts both accepts a record whose base
// state is named under one hash and whose roots are computed under another.
func oeRuleEmptyTreeConstant(pred oeObj, _ map[string][]byte) *oeFault {
	interval := pred.obj("interval")
	if interval.str("baseResolution") != "empty-tree" {
		return nil
	}
	if interval.str("beforeRoot") != oeEmptyTree[pred.str("hashAlgorithm")] {
		return oeMalformedAt("empty-tree-constant-wrong-algorithm")
	}
	return nil
}

func oeRulePathScopeLiteral(pred oeObj, _ map[string][]byte) *oeFault {
	for _, item := range pred.arr("pathScope") {
		entry, ok := item.(string)
		if !ok || !strings.HasPrefix(entry, "/") {
			return oeMalformedAt("path-scope-not-absolute")
		}
		if strings.ContainsAny(entry, oeGlobMetacharacters) {
			return oeMalformedAt("path-scope-glob-metacharacter")
		}
	}
	return nil
}

// oeRuleMutationCoherence is the rule a record whose own carried evidence
// refutes its own claim fails. It is stage one deliberately: a contradiction
// between the mutation claim and the write set is a defect in the bytes, and
// deciding it before any trust input is read is what stops a verifier reporting
// the claim it was handed.
func oeRuleMutationCoherence(pred oeObj, _ map[string][]byte) *oeFault {
	interval := pred.obj("interval")
	if pred.str("mutation") == "none" {
		if len(pred.arr("writes")) > 0 {
			return oeMalformedAt("mutation-contradicted-by-writes")
		}
		if interval.str("beforeRoot") != interval.str("afterRoot") {
			return oeMalformedAt("mutation-none-with-moved-root")
		}
		return nil
	}
	if len(pred.arr("writes")) == 0 {
		return oeMalformedAt("mutation-observed-without-writes")
	}
	return nil
}

// oeRuleWriteChain requires the ordered composition to carry beforeRoot to
// afterRoot. A set of writes that does not compose is a set of assertions about
// unrelated states, and the interval it claims to describe is then unverifiable
// from the record.
func oeRuleWriteChain(pred oeObj, _ map[string][]byte) *oeFault {
	interval := pred.obj("interval")
	writes := pred.arr("writes")
	if len(writes) == 0 {
		return nil
	}
	cursor := interval.str("beforeRoot")
	for _, item := range writes {
		row := oeRow(item)
		if fault := oeRequire(row, "path", "preStateDigest", "postStateDigest", "inScope"); fault != nil {
			return fault
		}
		if row.str("preStateDigest") != cursor {
			return oeMalformedAt("write-chain-broken")
		}
		cursor = row.str("postStateDigest")
	}
	if cursor != interval.str("afterRoot") {
		return oeMalformedAt("write-chain-does-not-reach-after-root")
	}
	return nil
}

func oeRuleReadBindings(pred oeObj, _ map[string][]byte) *oeFault {
	for _, item := range pred.arr("reads") {
		row := oeRow(item)
		if fault := oeRequire(row, "path", "preStateDigest", "blobDigest", "readState"); fault != nil {
			return fault
		}
		if !oeReadStates[row.str("readState")] {
			return oeMalformedAt("read-state-unknown")
		}
		if row.str("readState") != "bytes-read" {
			// A read that carries no bytes may not carry a range over them: a
			// range beside "unavailable" is a binding to something the record
			// says it did not see.
			if row.has("byteRange") || row.has("rangeDigest") {
				return oeMalformedAt("read-state-carries-range")
			}
			continue
		}
		if fault := oeReadRange(row); fault != nil {
			return fault
		}
	}
	return nil
}

// oeReadRange checks the byte range of one bytes-read row. It is its own
// function because oeRuleReadBindings is otherwise a rule with two subjects, and
// the branch count of the two together is what a reader has to hold at once.
func oeReadRange(row oeObj) *oeFault {
	if fault := oeRequire(row, "byteRange", "rangeDigest"); fault != nil {
		return fault
	}
	span := row.obj("byteRange")
	if fault := oeRequire(span, "start", "end"); fault != nil {
		return fault
	}
	start, startOK := span.integer("start")
	end, endOK := span.integer("end")
	if !startOK || !endOK {
		return oeMalformedAt("byte-range-not-integer")
	}
	if start < 0 {
		return oeMalformedAt("byte-range-negative")
	}
	if end <= start {
		return oeMalformedAt("byte-range-empty")
	}
	return nil
}

// oeRuleRangePreimage recomputes the range digest over the blob length and BOTH
// offsets, never over the range bytes alone. A digest over the bytes alone is
// the same digest for the same run of bytes anywhere in any file, so it binds
// the content and not the read.
//
// A verifier that does not hold the blob cannot check this, which is why the
// predicate calls three of the four read bindings checkable rather than four. A
// row whose blob is absent here is therefore skipped rather than refused.
func oeRuleRangePreimage(pred oeObj, blobs map[string][]byte) *oeFault {
	for _, item := range pred.arr("reads") {
		row := oeRow(item)
		if row.str("readState") != "bytes-read" {
			continue
		}
		blob, held := blobs[row.str("blobDigest")]
		if !held {
			continue
		}
		span := row.obj("byteRange")
		start, _ := span.integer("start")
		end, _ := span.integer("end")
		if start < 0 || end < start || end > int64(len(blob)) {
			return oeMalformedAt("range-digest-preimage-wrong")
		}
		preimage := fmt.Sprintf("%d\x00%d\x00%d\x00", len(blob), start, end)
		if row.str("rangeDigest") != sha(append([]byte(preimage), blob[start:end]...)) {
			return oeMalformedAt("range-digest-preimage-wrong")
		}
	}
	return nil
}

// oeRuleReadChain requires a read's pre-state to be a state this interval
// actually passed through. A read bound to a state outside the chain is a read
// of some other interval, reported inside this one.
func oeRuleReadChain(pred oeObj, _ map[string][]byte) *oeFault {
	reachable := map[string]bool{pred.obj("interval").str("beforeRoot"): true}
	for _, item := range pred.arr("writes") {
		reachable[oeRow(item).str("postStateDigest")] = true
	}
	for _, item := range pred.arr("reads") {
		if !reachable[oeRow(item).str("preStateDigest")] {
			return oeMalformedAt("read-pre-state-not-in-interval")
		}
	}
	return nil
}

// oeRuleCoverageCoherence refuses a record that claims complete coverage of its
// path scope and names a gap inside that scope. The two statements cannot both
// be true, and a verifier that reads only the first believes the one the
// producer would rather it read.
func oeRuleCoverageCoherence(pred oeObj, _ map[string][]byte) *oeFault {
	coverage := pred.obj("observation").obj("coverage")
	if fault := oeRequire(coverage, "scopeComplete", "gaps"); fault != nil {
		return fault
	}
	if !coverage.flag("scopeComplete") {
		return nil
	}
	if oeGapInScope(coverage.arr("gaps"), pred.arr("pathScope")) {
		return oeMalformedAt("coverage-self-contradictory")
	}
	return nil
}

// oeGapInScope reports whether any declared gap falls inside any declared scope.
func oeGapInScope(gaps, scopes []any) bool {
	for _, gapItem := range gaps {
		gap, _ := gapItem.(string)
		for _, scopeItem := range scopes {
			scope, _ := scopeItem.(string)
			if strings.HasPrefix(gap, scope) {
				return true
			}
		}
	}
	return false
}

// oeRuleCommitmentDigest recomputes the commitment over four members, not two.
// authorityDigest is in the preimage so that an observer cannot select a
// permissive authority after the interval closed, and intervalId is in it so
// that one signed commitment cannot serve two intervals sharing a before-root.
// Both attacks were open while the preimage carried only the root and the nonce.
func oeRuleCommitmentDigest(pred oeObj, _ map[string][]byte) *oeFault {
	commitment := pred.obj("observation").obj("priorCommitment")
	if commitment == nil {
		return nil
	}
	if fault := oeRequire(commitment,
		"committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig"); fault != nil {
		return fault
	}
	preimage, err := oeCanonical(map[string]string{
		"authorityDigest": pred.str("authorityDigest"),
		"beforeRoot":      pred.obj("interval").str("beforeRoot"),
		"intervalId":      pred.str("intervalId"),
		"witnessNonce":    commitment.str("witnessNonce"),
	})
	if err != nil {
		return oeMalformedAt("commitment-preimage-uncanonicalizable")
	}
	if commitment.str("commitmentDigest") != sha(preimage) {
		return oeMalformedAt("commitment-digest-mismatch")
	}
	return nil
}

// oeCanonical is the RFC 8785 form of the commitment preimage. The repository's
// own canonicalizer does the work: a second spelling of one canonical form is
// the drift every digest in this tree is exposed to.
func oeCanonical(members map[string]string) ([]byte, error) {
	body, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	return aee.Canonicalize(body)
}

// oeRuleAgreementDerivable requires the agreement label to follow from the two
// values the row carries. A label a reader has to take on trust is the thing a
// dual-value record exists to remove.
func oeRuleAgreementDerivable(pred oeObj, _ map[string][]byte) *oeFault {
	for _, item := range pred.arr("dualValues") {
		row := oeRow(item)
		if fault := oeRequire(row, "fact", "observedValue", "reportedValue", "agreement"); fault != nil {
			return fault
		}
		if !oeAgreements[row.str("agreement")] {
			return oeMalformedAt("agreement-unknown")
		}
		if row.str("agreement") != oeDerivedAgreement(row) {
			return oeMalformedAt("agreement-not-derivable")
		}
	}
	return nil
}

func oeDerivedAgreement(row oeObj) string {
	observed, reported := row.str("observedValue"), row.str("reportedValue")
	switch {
	case observed == "" || reported == "":
		return "one-sided"
	case observed == reported:
		return "agree"
	default:
		return "disagree"
	}
}

// oeRuleCommitmentOrder is stage two: a commitment made after the interval
// opened commits to nothing the interval had not already shown the committer.
func oeRuleCommitmentOrder(pred oeObj, _ map[string][]byte) *oeFault {
	commitment := pred.obj("observation").obj("priorCommitment")
	if commitment == nil {
		return nil
	}
	if commitment.str("committedAt") >= pred.obj("interval").str("openedAt") {
		return oeInvalidAt("commitment-not-prior")
	}
	return nil
}

// oeRuleCommitmentKeyidDisjoint is the offline discriminator: the committing key
// may not be one of the keys that signed what was observed. The predicate states
// it is necessary and says plainly that it is not sufficient.
func oeRuleCommitmentKeyidDisjoint(pred oeObj, _ map[string][]byte) *oeFault {
	observation := pred.obj("observation")
	commitment := observation.obj("priorCommitment")
	if commitment == nil {
		return nil
	}
	keyid := commitment.str("keyid")
	for _, item := range observation.arr("observedSigners") {
		signer, _ := item.(string)
		if signer == keyid {
			return oeInvalidAt("commitment-keyid-not-disjoint")
		}
	}
	return nil
}

func oeRuleWriteScope(pred oeObj, _ map[string][]byte) *oeFault {
	scopes := pred.arr("pathScope")
	for _, item := range pred.arr("writes") {
		row := oeRow(item)
		covered := oeCoveredByScope(row.str("path"), scopes)
		if covered != row.flag("inScope") {
			return oeInvalidAt("write-in-scope-mislabelled")
		}
		if !covered && pred.str("tier") == "authoritative" {
			return oeInvalidAt("write-outside-path-scope")
		}
	}
	return nil
}

func oeCoveredByScope(path string, scopes []any) bool {
	for _, item := range scopes {
		scope, _ := item.(string)
		if strings.HasPrefix(path, scope) {
			return true
		}
	}
	return false
}

// oeRuleTierRecompute recomputes the tier and never reads it as a claim. A
// record asking to be read as authoritative on its own say-so is the whole
// failure this predicate exists to close, so a mismatch is INVALID rather than a
// quiet downgrade to the tier the record would have earned.
func oeRuleTierRecompute(pred oeObj, _ map[string][]byte) *oeFault {
	clauses := oeAuthoritativeClauses(pred)
	derived := "authoritative"
	for _, clause := range clauses {
		if !clause.held {
			derived = "voluntary"
		}
	}
	if pred.str("tier") == derived {
		return nil
	}
	if pred.str("tier") == "authoritative" {
		for _, clause := range clauses {
			if !clause.held {
				return oeInvalidAt(clause.code)
			}
		}
	}
	return oeInvalidAt("tier-recompute-mismatch")
}

// oeClause is one condition of the authoritative tier and the code its failure
// is reported under. They are a slice rather than a map because the first
// unheld clause is the reported one, so the order is part of the contract.
type oeClause struct {
	code string
	held bool
}

// oeAuthoritativeClauses carries no mutation-shape clause, and the absence is
// deliberate. An earlier draft had one and the corpus's mutation sweep proved it
// unreachable: a record whose mutation claim disagrees with its write set is
// already malformed at stage one, which runs first. A clause no input can reach
// is worse than an absent one, because it makes the rule it duplicates look
// measured when nothing measures it.
func oeAuthoritativeClauses(pred oeObj) []oeClause {
	observation := pred.obj("observation")
	coverage := observation.obj("coverage")
	scopes := pred.arr("pathScope")
	return []oeClause{
		{"authoritative-vantage-not-independent", observation.str("vantage") == "below-observed"},
		{"authoritative-prior-commitment-absent", observation.obj("priorCommitment") != nil},
		{"authoritative-empty-path-scope", len(scopes) > 0},
		{"authoritative-coverage-incomplete",
			coverage.flag("scopeComplete") || !oeGapInScope(coverage.arr("gaps"), scopes)},
	}
}

// oeVerify is the verifier: one member's bytes in, a verdict and its codes out.
func oeVerify(raw []byte, observerPublicKey string, blobs map[string][]byte) oeOutcome {
	envelope, fault := oeDecode(raw)
	if fault != nil {
		return oeOutcome{verdict: fault.verdict, codes: []string{fault.code}}
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.str("payload"))
	if err != nil {
		return oeOutcome{verdict: oeMalformed, codes: []string{"not-parseable"}}
	}
	statement, fault := oeDecode(payload)
	if fault != nil {
		return oeOutcome{verdict: fault.verdict, codes: []string{fault.code}}
	}
	if fault := oeApplyRules(statement, blobs); fault != nil {
		return oeOutcome{verdict: fault.verdict, codes: []string{fault.code}}
	}
	return oeVerifyEnvelope(envelope, payload, observerPublicKey)
}

// oeDecode parses one JSON document and refuses a duplicate member anywhere in
// it. Two members of one name mean two readers can take two different values
// from bytes that carry one signature, which is a signature over a document with
// no single meaning.
//
// The duplicate scan is stated here rather than borrowed from aee.CheckIJSON,
// and the reason is a defect that borrowing produced. That checker enforces the
// whole I-JSON profile the AEE predicate pins, which includes refusing every
// non-integer number so that cross-language float formatting cannot split its
// rails. This predicate pins no such rule, so the borrowed checker refused a
// payload carrying a fractional byte offset as unparseable -- and thereby made
// this predicate's own byte-range-not-integer rule UNREACHABLE, since no input
// could ever get past the parse to reach it. A checker whose profile is stricter
// than the rules it screens does not add strictness; it hides the rules behind
// it, and the rule it hid was one the corpus exists to exercise.
func oeDecode(raw []byte) (oeObj, *oeFault) {
	if err := oeCheckDuplicates(raw); err != nil {
		if errors.Is(err, errOEDuplicateMember) {
			return nil, oeMalformedAt("duplicate-member")
		}
		return nil, oeMalformedAt("not-parseable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return nil, oeMalformedAt("not-parseable")
	}
	return oeObj(document), nil
}

// errOEDuplicateMember is the one fault the scan below distinguishes from a
// plain parse error, because the predicate names it by its own code.
var errOEDuplicateMember = errors.New("duplicate object member")

// oeCheckDuplicates walks raw and refuses the first object carrying one member
// name twice. Go's decoder keeps the LAST value for a repeated name and reports
// nothing, so without this walk a duplicate is not a refusal here: it is a
// silent choice of which of the two values this rail reads.
func oeCheckDuplicates(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := oeWalkValue(decoder); err != nil {
		return err
	}
	// Trailing content after one complete document is not a document.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the document")
	}
	return nil
}

func oeWalkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isContainer := token.(json.Delim)
	if !isContainer {
		return nil
	}
	if delimiter == '{' {
		return oeWalkObject(decoder)
	}
	return oeWalkArray(decoder)
}

func oeWalkObject(decoder *json.Decoder) error {
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, isName := token.(string)
		if !isName {
			return errors.New("an object member name that is not a string")
		}
		if seen[name] {
			return errOEDuplicateMember
		}
		seen[name] = true
		if err := oeWalkValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token() // the closing brace
	return err
}

func oeWalkArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := oeWalkValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token() // the closing bracket
	return err
}

// oeApplyRules runs the predicate's rules in order and returns the FIRST
// refusal, which is the code the manifest names.
func oeApplyRules(statement oeObj, blobs map[string][]byte) *oeFault {
	if statement.str("_type") != oeStatementType {
		return oeMalformedAt("statement-type-unexpected")
	}
	predicate := statement.obj("predicate")
	if predicate == nil {
		return oeMalformedAt("required-member-absent:predicate")
	}
	for _, rule := range oeRules {
		if fault := rule(predicate, blobs); fault != nil {
			return fault
		}
	}
	return nil
}

// oeVerifyEnvelope is the last stage and runs only once every rule has held. A
// signature checked before the bytes it covers have been read is a signature
// over a document the verifier has not decided it can read.
func oeVerifyEnvelope(envelope oeObj, payload []byte, observerPublicKey string) oeOutcome {
	signatures := envelope.arr("signatures")
	if len(signatures) == 0 {
		return oeOutcome{verdict: oeMalformed, codes: []string{"envelope-signature-unreadable"}}
	}
	signature, err := base64.StdEncoding.DecodeString(oeRow(signatures[0]).str("sig"))
	if err != nil {
		return oeOutcome{verdict: oeMalformed, codes: []string{"envelope-signature-unreadable"}}
	}
	key, err := hex.DecodeString(observerPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return oeOutcome{verdict: oeMalformed, codes: []string{"envelope-signature-unreadable"}}
	}
	preimage := aee.PAE(envelope.str("payloadType"), payload)
	if !ed25519.Verify(ed25519.PublicKey(key), preimage, signature) {
		return oeOutcome{verdict: oeInvalid, codes: []string{"envelope-signature-invalid"}}
	}
	return oeOutcome{verdict: oeValid}
}

// oeManifest is the corpus's manifest, as this reader reads it.
type oeManifest struct {
	Conditions   map[string]string `json:"conditions"`
	CorpusDigest string            `json:"corpusDigest"`
	Counts       map[string]int    `json:"counts"`
	EmptyTree    map[string]string `json:"emptyTree"`
	Keys         map[string]struct {
		Keyid     string `json:"keyid"`
		PublicKey string `json:"publicKey"`
	} `json:"keys"`
	Vectors []oeVector `json:"vectors"`
}

type oeVector struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Slug       string   `json:"slug"`
	Parent     string   `json:"parent"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
	Readings []struct {
		Verdict   string `json:"verdict"`
		Rationale string `json:"rationale"`
	} `json:"readings"`
}

func (o observedEffect) Judge(dir string, raw []byte) (*Result, error) {
	var manifest oeManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	if len(manifest.Vectors) == 0 {
		return nil, fmt.Errorf("%s/MANIFEST.json carries no vectors", dir)
	}
	observer := manifest.Keys["observer"].PublicKey
	if observer == "" {
		return nil, fmt.Errorf(
			"%s/MANIFEST.json names no keys.observer.publicKey, so no member's signature "+
				"can be checked and a clean verdict here would mean nothing", dir)
	}
	result := &Result{}
	blobs := oeBlobs()
	seen := map[string]bool{}
	for _, vector := range manifest.Vectors {
		member := Member{ID: vector.ID, Kind: vector.Kind}
		if seen[vector.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[vector.ID] = true
		o.judgeMember(dir, vector, observer, blobs, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, o.corpusFindings(dir, &manifest)...)
	return result, nil
}

// judgeMember replays one member and records what it owes.
func (o observedEffect) judgeMember(
	dir string, vector oeVector, observer string, blobs map[string][]byte, out *Member,
) {
	if vector.File == "" {
		out.Findings = append(out.Findings, "MANIFEST row declares no file")
		return
	}
	body, err := readIn(dir, vector.File)
	if err != nil {
		out.Findings = append(out.Findings, "vector body missing: "+err.Error())
		return
	}
	// The identifier is the digest of these bytes, so this is the check that
	// turns any edit to a member into a finding NAMING that member rather than
	// only a corpus digest that no longer matches.
	if got := idFromBytes(body); got != vector.ID {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"file bytes do not hash to the identifier: %s names %s", vector.ID, got))
	}
	outcome := oeVerify(body, observer, blobs)
	switch vector.Kind {
	case "accept":
		o.checkAccept(outcome, out)
	case "reject":
		o.checkReject(vector, outcome, out)
	case oeIndeterminate:
		o.checkIndeterminate(vector, outcome, out)
	default:
		out.Findings = append(out.Findings, fmt.Sprintf(
			"MANIFEST lists this member under kind %q, which this reader does not replay. "+
				"A kind nobody taught the reader about is refused by name rather than "+
				"replayed as an accept.", vector.Kind))
	}
}

func (observedEffect) checkAccept(outcome oeOutcome, out *Member) {
	if outcome.verdict != oeValid {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"expected valid, got %s %v", outcome.verdict, outcome.codes))
	}
}

func (observedEffect) checkReject(vector oeVector, outcome oeOutcome, out *Member) {
	want := vector.Expected
	if outcome.verdict != want.Verdict {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"expected %s, got %s %v", want.Verdict, outcome.verdict, outcome.codes))
		return
	}
	if len(want.Codes) == 0 {
		return
	}
	if strings.Join(outcome.codes, ",") != strings.Join(want.Codes, ",") {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"expected codes %v, got %v. A member refused for the wrong reason is a rule "+
				"nothing exercises, whatever the verdict says", want.Codes, outcome.codes))
	}
}

// checkIndeterminate grades a member the predicate settles no rule for. What is
// required is that the rail take one of the readings the corpus declares; which
// one it takes is the corpus's own recorded open question.
func (observedEffect) checkIndeterminate(vector oeVector, outcome oeOutcome, out *Member) {
	if len(vector.Readings) < 2 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %d reading(s); a member with fewer than two is a reject member",
			len(vector.Readings)))
		return
	}
	for _, reading := range vector.Readings {
		if reading.Verdict == outcome.verdict {
			return
		}
	}
	declared := make([]string, 0, len(vector.Readings))
	for _, reading := range vector.Readings {
		declared = append(declared, reading.Verdict)
	}
	out.Findings = append(out.Findings, fmt.Sprintf(
		"this rail took the reading %q, which is outside the declared set %v. An "+
			"undeclared reading is added to the member by name, never by widening the set",
		outcome.verdict, sortedStrings(declared)))
}

// corpusFindings are the findings that belong to no single member.
func (o observedEffect) corpusFindings(dir string, manifest *oeManifest) []string {
	var findings []string
	measured := map[string]int{}
	for _, vector := range manifest.Vectors {
		measured[vector.Kind]++
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		findings = append(findings, bad)
	}
	findings = append(findings, o.conditionFindings(manifest)...)
	findings = append(findings, o.parentFindings(manifest)...)
	findings = append(findings, o.constantFindings(manifest)...)
	return append(findings, o.digestFindings(dir, manifest)...)
}

// conditionFindings is the check that makes a corpus of refusals scoreable. A
// condition exercised only by reject members gives full marks to a verifier
// that refuses everything, and one exercised only by accept members gives full
// marks to a verifier that implements nothing for it.
func (observedEffect) conditionFindings(manifest *oeManifest) []string {
	accepted, rejected, undecided := map[string]bool{}, map[string]bool{}, map[string]bool{}
	buckets := map[string]map[string]bool{
		"accept": accepted, "reject": rejected, oeIndeterminate: undecided,
	}
	used := map[string]bool{}
	for _, vector := range manifest.Vectors {
		for _, condition := range vector.Conditions {
			used[condition] = true
			if bucket := buckets[vector.Kind]; bucket != nil {
				bucket[condition] = true
			}
		}
	}
	var findings []string
	for _, condition := range orphanTwins(accepted, rejected) {
		// A condition carried only by an indeterminate member is exempt by
		// construction: the predicate states no rule for it, so there is no
		// implementation for a refuse-everything strategy to skip.
		if undecided[condition] {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"condition %s is exercised only by reject members, so refusing everything "+
				"scores full marks on it", condition))
	}
	for _, condition := range declaredMinusUsed(manifest.Conditions, used) {
		findings = append(findings, fmt.Sprintf(
			"condition %s is declared and no member exercises it", condition))
	}
	for _, condition := range sortedKeys(used) {
		if _, declared := manifest.Conditions[condition]; !declared {
			findings = append(findings, fmt.Sprintf(
				"condition %s is used by a member and the manifest does not declare it",
				condition))
		}
	}
	return append(findings, oeConditionsWithNoReject(accepted, rejected, undecided)...)
}

func oeConditionsWithNoReject(accepted, rejected, undecided map[string]bool) []string {
	var bare []string
	for condition := range accepted {
		if !rejected[condition] && !undecided[condition] {
			bare = append(bare, condition)
		}
	}
	sort.Strings(bare)
	findings := make([]string, 0, len(bare))
	for _, condition := range bare {
		findings = append(findings, fmt.Sprintf(
			"condition %s has no reject member, so a verifier that implements nothing "+
				"for it scores full marks", condition))
	}
	return findings
}

// parentFindings requires every reject member to name the accept member it is
// one mutation from. Without the parent a reader cannot tell a member that
// tests a rule from a member that is simply broken.
func (observedEffect) parentFindings(manifest *oeManifest) []string {
	ids := map[string]bool{}
	for _, vector := range manifest.Vectors {
		ids[vector.ID] = true
	}
	var findings []string
	for _, vector := range manifest.Vectors {
		if vector.Kind != "reject" {
			continue
		}
		switch {
		case vector.Parent == "":
			findings = append(findings, fmt.Sprintf(
				"%s is a reject member and names no parent, so nothing says which accepted "+
					"member it is one mutation from", vector.ID))
		case !ids[vector.Parent]:
			findings = append(findings, fmt.Sprintf(
				"%s names parent %s, which is not a member of this corpus",
				vector.ID, vector.Parent))
		}
	}
	return findings
}

// constantFindings checks the manifest's published empty-tree constants against
// the ones computed here. A corpus that publishes a wrong constant is a corpus
// whose own wrong-constant member cannot be told from a correct one.
func (observedEffect) constantFindings(manifest *oeManifest) []string {
	var findings []string
	for _, algorithm := range sortedKeys(oeEmptyTree) {
		declared, present := manifest.EmptyTree[algorithm]
		if !present {
			findings = append(findings, fmt.Sprintf(
				"the manifest publishes no empty-tree constant for %s", algorithm))
			continue
		}
		if declared != oeEmptyTree[algorithm] {
			findings = append(findings, fmt.Sprintf(
				"the manifest's empty-tree constant for %s is %s and the computed one is %s",
				algorithm, short(declared), short(oeEmptyTree[algorithm])))
		}
	}
	return findings
}

func (observedEffect) digestFindings(dir string, manifest *oeManifest) []string {
	ids := make([]string, 0, len(manifest.Vectors))
	files := make([]string, 0, len(manifest.Vectors))
	for _, vector := range manifest.Vectors {
		ids = append(ids, vector.ID)
		files = append(files, vector.File)
	}
	recomputed, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return []string{"the corpus digest could not be recomputed: " + err.Error()}
	}
	if manifest.CorpusDigest != recomputed {
		return []string{fmt.Sprintf(
			"corpusDigest does not match the members on disk (manifest %s, recomputed %s)",
			short(manifest.CorpusDigest), short(recomputed))}
	}
	return nil
}
