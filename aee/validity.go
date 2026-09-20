package aee

// GATE 1 — coverage validity (spec:req-fields-coverage-validity-derived-carried-bytes@d0ffa1e57be1f4e6). A consumption precondition, not
// an optional lint: a consumer that consumes result, credits any row, or
// applies either strength ordering MUST evaluate these first, and on failure
// the attestation is INVALID and its result MUST NOT be consumed.
//
// Everything here reads record payloads but never consumer policy, so it is
// a pure function of the carried statement (spec:req-fields-coverage-validity-derived-carried-bytes-2@c6e2553188dd254a). It reads exactly
// one thing about signatures: how many entries the array carries, which needs
// no key material and so costs the layer none of its purity. Signature
// verification — the one trust-relative step — remains the evidence tier's
// separate question (tier.go); a signature that fails to verify is never a
// validity failure code.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Reserved payload members (spec:req-fields-fields-divide-identity-whose-signature-2@fda9d561e208e9e4).
const (
	memberRunBinding    = "aeeRunBinding"
	memberKind          = "aeeKind"
	memberMethod        = "aeeMethod"
	memberArmedAt       = "armedAt"
	memberPostureDigest = "aeePostureDigest"
	memberStillArmed    = "aeeStillArmed"
	memberDropCount     = "aeeDropCount"
	memberDropBound     = "aeeDropBound"

	// The four members carrying the commitments 0.7 adds (spec:req-fields-moat-drop-drop-containment-layer@5c9e1e0b596d6f4e).
	// Each is required on exactly one kind, and a record missing or malforming
	// the member its kind requires covers nothing, on the same terms as a
	// missing armedAt.
	memberPayloadCommitment = "aeePayloadCommitment"
	memberAssessedAttacks   = "aeeAssessedAttacks"
	memberObservedSet       = "aeeObservedSet"
	memberObservedAttacks   = "aeeObservedAttacks"

	// Optional arming-payload run-chaining members.
	memberRunSeq         = "aeeRunSeq"
	memberPrevRunBinding = "aeePrevRunBinding"
	memberChainScope     = "aeeChainScope"
	// Optional explicit binding-version declaration (read-first).
	memberBindingVersion = "aeeBindingVersion"
)

const jsonMediaTypeSuffix = "+json"

// recordState is the shared per-record decode state: the statement-level
// checks need every record's PAE bytes for the batchRoot; the per-row checks
// need the decoded payload of referenced records.
type recordState struct {
	payloadBytes []byte
	pae          []byte
	decodeErr    bool
}

// Gate1 evaluates coverage validity and returns every violation found, in a
// pinned deterministic order. It must only run on statements that passed
// GATE 0 (it relies on GATE 0's presence and digest-shape guarantees).
func Gate1(s *Statement) []Code {
	_, _, _, codes := gate1WithContext(s)
	return codes
}

// gate1WithContext runs GATE 1 and additionally returns the memoized artifacts
// it necessarily builds along the way -- the decoded per-record states, the
// derived run binding, and the parsed issuedAt -- so Evaluate can seal them
// into an EvalContext instead of DeriveTiers and CheckRecordSignatures each
// re-deriving them (the triple-recompute drift risk). Behavior is identical to
// the previous inline Gate1: the returned codes are unchanged.
func gate1WithContext(s *Statement) (states []recordState, binding string, issuedAt time.Time, codes []Code) {
	p := s.Predicate

	states, stCodes := checkRecordsStatementLevel(p)
	for _, c := range stCodes {
		codes = appendCode(codes, c)
	}

	// An out-of-range observationRefs index is a structural integrity fault on
	// ANY row, regardless of basis and including rows nothing normative reads,
	// fail-closed and independent of any gate. Checked before the substrate-row
	// path so an artifact-only statement with a dangling ref is still rejected.
	// Reserved for statements where records exist: with no records the
	// records-absent precedence owns the reject (a ref cannot resolve to a
	// record set that is not there).
	if len(p.Records) > 0 && anyObservationRefOutOfRange(p) {
		codes = appendCode(codes, CodeRefOutOfRange)
	}

	// The 0.7 requirements written over every row. They are evaluated on BOTH
	// paths, because three of the five are stated over every row rather than
	// only over a basis: substrate row, and they are evaluated LAST on each,
	// because they describe a consequence rather than a cause: a row whose refs
	// are empty or malformed leaves the record it used to resolve orphaned, and
	// the code a reader wants first is the one naming what the producer did.
	if !hasSubstrateRows(p) {
		for _, c := range gate1CommitmentsAnyBasis(p, states) {
			codes = appendCode(codes, c)
		}
		return states, "", time.Time{}, codes
	}

	// Registry precedence pin 2: when observationRecords is absent entirely,
	// report records-absent; ref-out-of-range is reserved for statements
	// where records exist.
	if !p.RecordsPresent {
		return states, "", time.Time{}, appendCode(codes, CodeRecordsAbsent)
	}

	binding = deriveStatementBinding(s)
	var err error
	issuedAt, err = parseTimestamp(p.IssuedAt)
	if err != nil {
		// GATE 0 already rejected this; defensive only.
		return states, binding, issuedAt, appendCode(codes, CodeIssuedAtMalformed)
	}

	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.IsSubstrate() {
			continue
		}
		rowCodes, _ := checkSubstrateRow(p, row, states, binding, issuedAt)
		for _, c := range rowCodes {
			codes = appendCode(codes, c)
		}
	}
	for _, c := range gate1CommitmentsAnyBasis(p, states) {
		codes = appendCode(codes, c)
	}
	for _, c := range gate1CommitmentsSubstrate(p, states, binding, issuedAt) {
		codes = appendCode(codes, c)
	}
	return states, binding, issuedAt, codes
}

// checkRecordsStatementLevel runs the record-set checks that hold for the
// whole statement whenever observationRecords is non-empty, BEFORE any row
// logic: signature-entry presence (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5), batchRoot presence
// (spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5), duplicate-record rejection (spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5), root recomputation
// (spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5), and the orphaned-root case (a batchRoot with no records to
// recompute over, spec:req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5).
func checkRecordsStatementLevel(p *Predicate) ([]recordState, []Code) {
	var codes []Code
	states := make([]recordState, len(p.Records))

	if !p.RecordsPresent || len(p.Records) == 0 {
		if p.BatchRootPresent {
			codes = appendCode(codes, CodeBatchRootOrphaned)
		}
		return states, codes
	}

	// Envelope shape before payload bytes: a record's signatures member MUST
	// carry at least one entry. Checked here rather than at the tier because
	// counting array entries reads no key material, so the check keeps this
	// layer a pure function of the carried statement.
	//
	// Asked once over the whole record set, and asked BEFORE the decode loop
	// below rather than inside it. Both are load-bearing. The verify-then-read
	// discipline puts a record's signature ahead of its payload (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5),
	// so a record with no signature at all is settled before the bytes it
	// carries are read; and a count evaluated per record inside the loop would
	// make the reported code depend on which record in the array happened to
	// carry which fault, which no vector carrying a single fault can detect.
	//
	// This is a READING, not a rule the specification states: it carries no
	// failure-code vocabulary and calls the sequencing of its own two stages
	// informative (spec:req-verification-verifier-proceeds-two-stages-stage@001da26fd6fb6158), so a rail that counts per record is
	// conformant and names the other condition. The corpus records the choice
	// rather than pinning it, in the indeterminate family ind-001 / ind-002,
	// which admits every reading it declares and refuses only a rail whose
	// answers no single reading explains.
	if anyRecordSignaturesEmpty(p) {
		codes = appendCode(codes, CodeRecordSignaturesEmpty)
	}

	decodeFailed := false
	leaves := make([][32]byte, len(p.Records))
	for i := range p.Records {
		payload, err := base64.StdEncoding.Strict().DecodeString(p.Records[i].PayloadB64)
		if err != nil {
			states[i].decodeErr = true
			decodeFailed = true
			codes = appendCode(codes, CodeRecordUndecodable)
			continue
		}
		states[i].payloadBytes = payload
		states[i].pae = PAE(p.Records[i].PayloadType, payload)
		leaves[i] = LeafHash(states[i].pae)
	}

	// The duplicate scan runs over the records that DECODED, and does not wait
	// for all of them to.
	//
	// It used to sit inside the `!decodeFailed` guard below, beside the batch
	// root, and one record failing base64 therefore suppressed both. Suppressing
	// the ROOT is right: an undecodable record leaves the zero value in `leaves`,
	// so a root computed over it would be a root over a leaf that does not exist.
	// Suppressing the DUPLICATE scan is not. The records that decoded still carry
	// whatever duplicate they carried, this contract is compared as a SET OF
	// CODES, and a statement holding a duplicate plus one undecodable record
	// reported `record-undecodable` and silently dropped `duplicate-record`.
	//
	// Scanning `leaves` wholesale is what the guard was avoiding and is still
	// wrong: two undecodable records both hold the zero value and would read as a
	// duplicate of each other, which is a finding about this loop rather than
	// about the statement. So the scan skips the entries that never decoded.
	seen := map[[32]byte]bool{}
	for i := range p.Records {
		if states[i].decodeErr {
			continue
		}
		if seen[leaves[i]] {
			codes = appendCode(codes, CodeDuplicateRecord)
			break
		}
		seen[leaves[i]] = true
	}

	if !decodeFailed {
		root := MerkleRoot(leaves)
		if !p.BatchRootPresent {
			codes = appendCode(codes, CodeBatchRootMissing)
		} else if p.BatchRoot != hex.EncodeToString(root[:]) {
			codes = appendCode(codes, CodeBatchRootMismatch)
		}
	}
	return states, codes
}

// anyRecordSignaturesEmpty reports whether any observation record carries no
// signature entry at all. A record is a DSSE envelope, and the spec requires
// its signatures member to carry at least one entry, so an absent member, an
// empty array and a value that is not an array are one fault: zero entries.
// All three land here, because a missing member decodes to a nil slice and
// RecordSignatures decodes a non-array to the same nil.
//
// What this does NOT do, stated plainly so nobody reads more into it: it
// proves nothing whatsoever about the signatures it counts. A producer who
// fills the array with plausible-looking garbage bytes passes it, and is
// caught only by real signature verification against a consumer-pinned key at
// GATE 2. The check converts "admits a statement carrying zero signatures"
// into "admits one whose signatures are structurally present but unchecked" —
// a narrow improvement, not a substitute for verification.
//
// It is worth having because the zero case is otherwise invisible at this
// layer. Stripping every signatures entry from every record leaves batchRoot
// unchanged (a leaf is H(0x00||PAE) and the PAE pre-image spans only
// payloadType and payload), leaves the statement valid, and leaves result at
// whatever it was; only the derived evidence tier drops. A consumer gating on
// result alone therefore admitted an entirely unsigned attestation. Being
// byte-pure, this closes the literal zero-signature case in every deployment,
// including ones that cannot do curve math at all.
func anyRecordSignaturesEmpty(p *Predicate) bool {
	for i := range p.Records {
		if len(p.Records[i].Signatures) == 0 {
			return true
		}
	}
	return false
}

// payloadAnalysis is the outcome of the byte-level checks every REFERENCED
// payload must pass (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5): canonical RFC 8785 + I-JSON RFC 7493
// object, +json media type, reserved members, run binding equality.
type payloadAnalysis struct {
	codes     []Code
	kind      string
	method    string
	obj       *jsonObject
	hasKind   bool
	hasMethod bool
}

func analyzePayload(rec *Record, state *recordState, binding string) payloadAnalysis {
	var a payloadAnalysis
	if state.decodeErr {
		a.codes = appendCode(a.codes, CodeRecordUndecodable)
		return a
	}

	v, err := parseJSONValue(state.payloadBytes)
	if err != nil {
		// Duplicate members and unsafe integers are the I-JSON profile
		// faults; any other parse failure means the payload is not a
		// parseable JSON value at all — the same covers-nothing class.
		a.codes = appendCode(a.codes, CodePayloadNotIJSON)
		return a
	}
	obj, ok := v.(*jsonObject)
	if !ok {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
		return a
	}
	a.obj = obj

	canon, err := Canonicalize(state.payloadBytes)
	if err != nil || !bytes.Equal(canon, state.payloadBytes) {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
	}
	// BMP-only string profile: a supplementary-plane member name anywhere in
	// the covering payload makes it cover nothing, the same handling as
	// non-canonical bytes. A payload can pass the byte-equality check above
	// under both the UTF-16 and the code-point member order when the two
	// orders happen to agree on its names; rejecting non-BMP names outright
	// removes the only inputs on which the two orders can disagree.
	if hasSupplementaryMemberName(obj) {
		a.codes = appendCode(a.codes, CodePayloadNotCanonical)
	}
	if !strings.HasSuffix(rec.PayloadType, jsonMediaTypeSuffix) {
		a.codes = appendCode(a.codes, CodePayloadMediaType)
	}

	rb, hasRB := objString(obj, memberRunBinding)
	a.kind, a.hasKind = objString(obj, memberKind)
	a.method, a.hasMethod = objString(obj, memberMethod)
	if !hasRB || !a.hasKind || !a.hasMethod {
		a.codes = appendCode(a.codes, CodePayloadMissingReserved)
		return a
	}
	if rb != binding {
		a.codes = appendCode(a.codes, CodeRunBindingMismatch)
	}
	return a
}

// recordEval is a referenced record's covering evaluation: whether it
// satisfies its declared aeeKind's constraints (spec:req-fields-fields-divide-identity-whose-signature-3@ab95391e07e8db81), and the
// kind-specific code to report when it does not. A record violating any
// constraint of its declared kind covers nothing (spec:req-fields-actuallayer-names-enforcement-layer-acted@fcb00b09c3b370f0); a record
// whose kind is unrecognized covers nothing and is otherwise ignored
// (spec:req-fields-arming-record-s-payload-additionally-2@5a96403832635f13).
type recordEval struct {
	kind     string
	method   string
	valid    bool
	failCode Code
	// coversNothingCode is set on a record whose KIND covers nothing whatever
	// its payload says: an unrecognized kind, or one of the two the document
	// registers as non-covering. It is the code a row's refusal takes when the
	// row resolved such a record and nothing of the class it needed, and it
	// carries the kind's own name so the two producer errors stay apart. It is
	// distinct from failCode, which reports a record of the RIGHT class whose
	// constraints were not met.
	coversNothingCode Code
}

// declaredAttacks is the set of attack identifiers the carried
// corpus.manifest.classes declares. Two kinds now carry arrays of them, and a
// record naming an identifier the manifest does not declare covers nothing
// (spec:req-fields-what-neither-kind-used-claim@0af0cebb0785e202,req-fields-comparison-subset-rather-than-equality@b518035679b715d4), so the set is an input to the kind evaluation
// rather than a statement rule applied afterwards.
func evaluateKind(a payloadAnalysis, pinnedPosture string, armingPostures []string, issuedAt time.Time, declaredAttacks map[string]bool) recordEval {
	ev := recordEval{kind: a.kind, method: a.method}
	methodKnown := a.method == MethodIntercepted || a.method == MethodReconstructed

	switch a.kind {
	case KindInterception:
		// An out-of-vocabulary aeeMethod cannot participate in the method cap,
		// so the record covers nothing. From 0.7 the kind also requires
		// aeePayloadCommitment (spec:req-fields-neither-kind-carries-constraints-because@09116e23544e2120): absent takes the missing-reserved
		// code every other absent reserved member takes, present-but-malformed
		// takes its own, because a producer told "missing" for a value it
		// plainly carries has been told the wrong thing about its own record.
		ev.failCode = CodePayloadMissingReserved
		values, hasCommitment := objStringArray(a.obj, memberPayloadCommitment)
		if _, present := a.obj.values[memberPayloadCommitment]; present && !commitmentArrayOK(values) {
			ev.failCode = CodePayloadCommitmentMalformed
			return ev
		}
		ev.valid = methodKnown && hasCommitment
	case KindArming:
		ev.failCode = CodeArmingCoversNothing
		ev.valid = armingConstraintsMet(a, pinnedPosture, issuedAt, declaredAttacks)
	case KindSealed:
		ev.failCode = CodeSealedCoversNothing
		ev.valid = sealedConstraintsMet(a, pinnedPosture, armingPostures, declaredAttacks)
	case KindExamination:
		ev.failCode = CodeExaminationCoversNothing
		ev.valid = a.method == MethodReconstructed
	case KindMoatDrop:
		// Registered non-covering (spec:req-fields-aeerunbinding-string-run-binding-digest@19184ed4961dd3e4). ev.valid stays false with no
		// constraint consulted: the kind covers nothing in every state, so there
		// is no member whose value could move the outcome, and reading one to
		// decide would invent a consequence the document does not define.
		ev.coversNothingCode = CodeMoatDropCoversNothing
	case KindUncommittedObservation:
		ev.coversNothingCode = CodeUncommittedObservationCoversNothing
	default:
		ev.coversNothingCode = CodeRecordKindUnknownCoversNothing
	}
	return ev
}

// armingConstraintsMet reports whether an arming payload satisfies every
// constraint of its kind. A record violating any of them covers nothing.
func armingConstraintsMet(a payloadAnalysis, pinnedPosture string, issuedAt time.Time, declaredAttacks map[string]bool) bool {
	// Read-first binding-version declaration: an arming payload MAY carry an
	// explicit aeeBindingVersion. A verifier reads it before deriving and
	// rejects fail-closed (the record covers nothing) a value it does not
	// implement, distinguishably from a run-binding digest mismatch. Absent
	// defaults to the implemented version; the derivation is unchanged.
	if bv, ok := objString(a.obj, memberBindingVersion); ok && bv != BindingVersion {
		return false
	}
	armedAt, hasArmedAt := objString(a.obj, memberArmedAt)
	posture, hasPosture := objString(a.obj, memberPostureDigest)
	if !hasArmedAt || !hasPosture || a.method != MethodIntercepted {
		return false
	}
	// armedAt carries the timestamp profile issuedAt defines (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5), so
	// the same parse enforces it. A spelling outside the profile names a valid
	// instant no later than issuedAt and still makes the arming record cover
	// nothing, which is why the profile is part of the parse rather than a
	// separate test a later reader can forget to copy.
	t, err := parseTimestamp(armedAt)
	if err != nil || t.After(issuedAt) || posture != pinnedPosture {
		return false
	}
	if !armingChainSyntaxValid(a.obj) {
		return false
	}
	// aeeAssessedAttacks is required on the kind from 0.7 (spec:req-fields-neither-kind-carries-constraints-because-2@07ab497d65ebb3b5). The
	// subset comparison against the carried coverage is a statement rule and
	// lives in commitments.go; what the kind requires is that the array is
	// there and well formed.
	declared, ok := objStringArray(a.obj, memberAssessedAttacks)
	return ok && attackIDArrayOK(declared, declaredAttacks)
}

// sealedConstraintsMet reports whether a sealed payload satisfies every
// constraint of its kind.
func sealedConstraintsMet(a payloadAnalysis, pinnedPosture string, armingPostures []string, declaredAttacks map[string]bool) bool {
	stillArmed, hasStillArmed := objBool(a.obj, memberStillArmed)
	dropCount, hasDropCount := objInt(a.obj, memberDropCount)
	posture, hasPosture := objString(a.obj, memberPostureDigest)
	if !hasStillArmed || !stillArmed || !hasDropCount || !hasPosture || a.method != MethodIntercepted {
		return false
	}
	if dropCount != 0 {
		bound, hasBound := objInt(a.obj, memberDropBound)
		if !hasBound || dropCount < 0 || dropCount > bound {
			return false
		}
	}
	// The two sealed posture equalities are jointly enforced: the seal's posture
	// must equal the pinned networkPosture digest AND every referenced arming
	// record's posture claim (spec:req-fields-dsse-envelope-per-observation-payload@b25ccffb96b860aa).
	if posture != pinnedPosture {
		return false
	}
	for _, ap := range armingPostures {
		if posture != ap {
			return false
		}
	}
	// aeeObservedSet and aeeObservedAttacks are required on the kind from 0.7
	// (spec:req-fields-both-registrations-verdict-preserving-what@3f3cfef70326695f,req-fields-comparison-subset-rather-than-equality@b518035679b715d4). The equality of the first against the
	// recompute and the caught-row obligation of the second are statement rules
	// and live in commitments.go; what the kind requires is that both are there
	// in the shapes it names.
	if observed, ok := objString(a.obj, memberObservedSet); !ok || !IsLowerHex64(observed) {
		return false
	}
	attacks, ok := objStringArray(a.obj, memberObservedAttacks)
	return ok && attackIDArrayOK(attacks, declaredAttacks)
}

// chainScopeVocabulary is the closed set of aeeChainScope dimension tokens.
// Each token pins a projection to a value already carried on the wire
// (subject -> subject[0].digest.sha256, corpus ->
// observationEnvironment.corpus.digest, networkPosture ->
// networkPosture.digest.sha256). Minor versions MAY append tokens; an
// unrecognized token fails closed.
var chainScopeVocabulary = map[string]bool{
	"subject":        true,
	"corpus":         true,
	"networkPosture": true,
}

// armingChainSyntaxValid checks the optional run-chaining members an arming
// payload MAY carry: aeeRunSeq, aeePrevRunBinding, aeeChainScope. They are
// syntax-checked here in the reserved-member walk and nothing else normative
// reads them (the coverage validity requirements, the result recompute, and
// the evidence tier are unchanged); their cross-attestation gap/fork
// semantics are consumer policy over whatever set a producer publishes.
//
// Syntax: aeeRunSeq is a positive safe-range integer; aeeChainScope is a
// duplicate-free array of tokens from the closed chainScopeVocabulary, sorted
// in observationVocabulary.labels canonical order (UTF-16 code-unit),
// REQUIRED whenever aeeRunSeq is present; aeePrevRunBinding is a lowercase
// 64-hex string, present exactly when aeeRunSeq is greater than 1 (a genesis
// record, aeeRunSeq 1, carries no predecessor). A chain member present without
// aeeRunSeq is rejected fail-closed: the members are defined only as a set
// anchored on the sequence number, and a reserved aee member with
// unsatisfiable syntax can only weaken coverage, never create it.
func armingChainSyntaxValid(obj *jsonObject) bool {
	_, seqPresent := obj.values[memberRunSeq]
	_, prevPresent := obj.values[memberPrevRunBinding]
	_, scopePresent := obj.values[memberChainScope]
	if !seqPresent {
		return !prevPresent && !scopePresent
	}
	seq, seqIsInt := objInt(obj, memberRunSeq)
	if !seqIsInt || seq < 1 {
		return false
	}
	scope, ok := objStringArray(obj, memberChainScope)
	if !ok {
		return false
	}
	for _, tok := range scope {
		if !chainScopeVocabulary[tok] {
			return false
		}
	}
	if !isSortedNoDuplicates(scope) {
		return false
	}
	if seq == 1 {
		return !prevPresent
	}
	prev, ok := objString(obj, memberPrevRunBinding)
	return ok && IsLowerHex64(prev)
}

// anyObservationRefOutOfRange reports whether any row, regardless of basis,
// carries a present, well-formed observationRefs index that is out of range
// for observationRecords. An out-of-range index is a structural integrity
// fault that makes the statement invalid, fail-closed and independent of any
// gate (spec: observationRefs field definition). Malformed refs (RefsErr) are
// a separate code and are skipped here.
func anyObservationRefOutOfRange(p *Predicate) bool {
	for i := range p.Rows {
		row := &p.Rows[i]
		if !row.RefsPresent || row.RefsErr != nil {
			continue
		}
		for _, idx := range row.Refs {
			if idx < 0 || idx >= len(p.Records) {
				return true
			}
		}
	}
	return false
}

// classRequirement is one class-match requirement of a row (spec:req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c).
type classRequirement struct {
	kind        string
	genericCode Code
}

// rowFailsClosed reports whether a row's closed-vocabulary members leave it
// unclassifiable: an out-of-vocabulary containmentObserved label, or a missing
// or out-of-vocabulary method or attribution (spec:req-fields-expectedpayloads-aeepayloadcommitment-attribution-bind-permut@580f5b43bf5b03e0,req-fields-method-states-how-row-s@d35548444900b334). Such a
// substrate row cannot satisfy the class-match requirement and is therefore
// invalid. attribution joined the list at 0.7 and joins it HERE rather than in
// a rule of its own, because the specification states the three closed row
// vocabularies as one rule with one consequence.
// The guard is written as an `if` over three disjuncts rather than as one
// returned expression, and that is a measurement decision rather than a style
// one. The forcing campaign enumerates a mutation site per DISJUNCT of an `if`
// and only whole-expression sites on a `return`, so a returned form proves the
// corpus forces the guard while proving nothing about which of the three
// vocabularies it forces. Extracting this helper collapsed exactly that
// granularity once already, and the ratchet caught it.
func rowFailsClosed(row *Row, labelCaught, labelClean bool) bool {
	methodValid := row.Method != nil &&
		(*row.Method == MethodIntercepted || *row.Method == MethodReconstructed)
	attributionValid := row.Attribution != nil &&
		(*row.Attribution == AttributionPinned || *row.Attribution == AttributionPaired)
	if (!labelCaught && !labelClean) || !methodValid || !attributionValid {
		return true
	}
	return false
}

// checkSubstrateRow evaluates one basis: substrate row. It returns the
// row's validity codes and, when the row is valid, the indexes of its
// covering records (the referenced records of the class(es) the row's
// class-match rule requires — extras are payload-checked but neither cap
// nor tier-gate).
func checkSubstrateRow(p *Predicate, row *Row, states []recordState, binding string, issuedAt time.Time) ([]Code, []int) {
	var codes []Code
	voc := p.Env.Vocabulary

	labelCaught := isCaughtLabel(voc, row.ContainmentObserved)
	labelClean := isCleanLabel(voc, row.ContainmentObserved)
	if rowFailsClosed(row, labelCaught, labelClean) {
		return appendCode(codes, CodeFailClosedSubstrateRow), nil
	}

	// observationRefs shape (spec:req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c).
	if !row.RefsPresent {
		return appendCode(codes, CodeRefsEmpty), nil
	}
	if row.RefsErr != nil {
		return appendCode(codes, CodeRefMalformed), nil
	}
	if len(row.Refs) == 0 {
		return appendCode(codes, CodeRefsEmpty), nil
	}
	uniqueRefs := make([]int, 0, len(row.Refs))
	seen := map[int]bool{}
	for _, idx := range row.Refs {
		if idx >= len(p.Records) {
			codes = appendCode(codes, CodeRefOutOfRange)
			continue
		}
		if !seen[idx] {
			seen[idx] = true
			uniqueRefs = append(uniqueRefs, idx)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Every referenced payload must pass the byte-level checks (spec:req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c).
	analyses := map[int]payloadAnalysis{}
	for _, idx := range uniqueRefs {
		a := analyzePayload(&p.Records[idx], &states[idx], binding)
		analyses[idx] = a
		for _, c := range a.codes {
			codes = appendCode(codes, c)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Kind constraints + class-match (spec:req-fields-actuallayer-names-enforcement-layer-acted-2@37221bc432684004,req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c).
	pinnedPosture := p.Env.NetworkPosture.Sha256()
	var armingPostures []string
	for _, idx := range uniqueRefs {
		a := analyses[idx]
		if a.kind == KindArming {
			if posture, ok := objString(a.obj, memberPostureDigest); ok {
				armingPostures = append(armingPostures, posture)
			}
		}
	}

	evals := map[int]recordEval{}
	// The first resolved record, in reference order, whose kind covers nothing
	// at all. Taking the first rather than ranking the kinds keeps the
	// diagnostic deterministic without inventing a precedence between a kind
	// that covers nothing by registration and one this verifier cannot read;
	// the document states no order between them and neither can be made to
	// cover, so the choice is a display and never a verdict.
	coversNothing := Code("")
	for _, idx := range uniqueRefs {
		ev := evaluateKind(analyses[idx], pinnedPosture, armingPostures, issuedAt, declaredAttackIDs(p))
		evals[idx] = ev
		if coversNothing == "" {
			coversNothing = ev.coversNothingCode
		}
	}

	var reqs []classRequirement
	switch {
	case *row.Method == MethodReconstructed:
		reqs = append(reqs, classRequirement{KindExamination, CodeReconstructedRowUncovered})
	case labelCaught: // method: intercepted
		reqs = append(reqs, classRequirement{KindInterception, CodeCaughtRowUncovered})
	default: // clean row, method: intercepted
		reqs = append(reqs, classRequirement{KindArming, CodeCleanRowUncovered})
		reqs = append(reqs, classRequirement{KindSealed, CodeCleanRowUncovered})
	}

	var covering []int
	for _, req := range reqs {
		satisfied := false
		candidateFail := Code("")
		for _, idx := range uniqueRefs {
			ev := evals[idx]
			if ev.kind != req.kind {
				continue
			}
			if ev.valid {
				satisfied = true
				covering = append(covering, idx)
			} else if candidateFail == "" {
				candidateFail = ev.failCode
			}
		}
		if satisfied {
			continue
		}
		switch {
		case candidateFail != "":
			codes = appendCode(codes, candidateFail)
		case coversNothing != "":
			codes = appendCode(codes, coversNothing)
		default:
			codes = appendCode(codes, req.genericCode)
		}
	}
	if len(codes) > 0 {
		return codes, nil
	}

	// Method cap (spec:req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c): the row's method is no stronger than the
	// weakest signed aeeMethod across its COVERING records (reconstructed is
	// weaker than intercepted). Registry precedence pin 3: records that
	// cover nothing do not participate in the cap.
	capMethod := MethodIntercepted
	for _, idx := range covering {
		if evals[idx].method == MethodReconstructed {
			capMethod = MethodReconstructed
		}
	}
	if *row.Method == MethodIntercepted && capMethod == MethodReconstructed {
		codes = appendCode(codes, CodeMethodCapExceeded)
	}
	if len(codes) > 0 {
		return codes, nil
	}
	return nil, covering
}

// objString reads a string member from a parsed payload object.
func objString(obj *jsonObject, key string) (string, bool) {
	if obj == nil {
		return "", false
	}
	v, ok := obj.values[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// objStringArray reads an array-of-strings member from a parsed payload
// object. ok is false if the member is absent or is not a JSON array whose
// every element is a string.
func objStringArray(obj *jsonObject, key string) ([]string, bool) {
	if obj == nil {
		return nil, false
	}
	v, ok := obj.values[key]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, el := range arr {
		s, ok := el.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// objBool reads a boolean member; a string "true" is NOT a boolean.
func objBool(obj *jsonObject, key string) (bool, bool) {
	if obj == nil {
		return false, false
	}
	v, ok := obj.values[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// objInt reads an integer member; non-integer numbers are rejected.
func objInt(obj *jsonObject, key string) (int64, bool) {
	if obj == nil {
		return 0, false
	}
	v, ok := obj.values[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}
