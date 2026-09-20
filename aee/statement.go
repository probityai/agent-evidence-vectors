package aee

// GATE 0 — statement well-formedness. Runs FIRST at both verify and emit:
// the emit seam refuses to sign a statement this gate rejects, so a producer
// pipeline cannot emit what the suite rejects.
//
// Everything here is a pure function of carried bytes: no signatures, no
// consumer policy. Checks that need the observation records themselves
// (batchRoot, duplicate records, per-row coverage) live in GATE 1.

import (
	"bytes"
	"errors"
	"sort"
	"time"
)

const rejectedSnakeCaseSpelling = "does_not_assert"

var errTimestampOffset = errors.New("zone designator is not a zero UTC offset")

// parseTimestamp parses a value carried under the predicate's Timestamp field
// type: RFC 3339 with uppercase designators and a zero UTC offset (spec:req-fields-precedent-informative-reserved-members-inside@535994a66179a0d9).
// time.RFC3339 already refuses the lowercase `t` and `z` RFC 3339 also admits,
// and it accepts any numeric offset, so the zone is the half that has to be
// checked here. `Z`, `+00:00` and `-00:00` all report a zero offset, which is
// the admitted set.
//
// Both timestamps the predicate carries run through this one function. The
// profile used to be written on armedAt alone and checked at that call site
// alone, which left issuedAt admitting `+05:00` on every rail while the same
// instant was refused a few fields away.
func parseTimestamp(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, err
	}
	if _, off := t.Zone(); off != 0 {
		return time.Time{}, errTimestampOffset
	}
	return t, nil
}

// Gate0 evaluates statement well-formedness and returns every violation
// found, in a pinned deterministic order (the first code is the primary
// code). An empty slice means the statement passed GATE 0.
func Gate0(s *Statement) []Code {
	var codes []Code
	p := s.Predicate

	// 1. Statement envelope types (spec:req-statement-schema@6a9adc2545078f65; both halves of condition
	//    coverage: _type and predicateType).
	if s.Type != StatementType {
		codes = appendCode(codes, CodeStatementTypeUnsupported)
	}
	if s.PredicateType != PredicateType {
		codes = appendCode(codes, CodePredicateTypeUnsupported)
	}

	// 2. Faults recorded while decoding members.
	for _, c := range s.ParseCodes {
		codes = appendCode(codes, c)
	}

	// 3. Rejected snake_case spelling: single canonicalization per content
	//    (spec:req-fields-precedent-informative-reserved-members-inside@535994a66179a0d9).
	if _, ok := p.Raw[rejectedSnakeCaseSpelling]; ok {
		codes = appendCode(codes, CodeMemberSpelling)
	}

	// 4. result vocabulary (spec:req-fields-result-string-required-fail-degraded@efb1dcd61c2e1d19).
	if !p.ResultPresent || !isResultToken(p.Result) {
		codes = appendCode(codes, CodeResultVocabulary)
	}

	// 5. observationEnvironment members (spec:req-fields-limit-common-all-four-stronger@5e7dea1f752df369). observationVocabulary
	//    absence carries its own code; the other four report
	//    environment-incomplete.
	env := p.Env
	if env == nil {
		codes = appendCode(codes, CodeEnvironmentIncomplete)
		codes = appendCode(codes, CodeVocabularyMissing)
	} else {
		if env.Substrate == nil || env.Corpus == nil || env.CatchPolicy == nil || env.NetworkPosture == nil {
			codes = appendCode(codes, CodeEnvironmentIncomplete)
		}
		if env.Vocabulary == nil {
			codes = appendCode(codes, CodeVocabularyMissing)
		}
		// The posture registry is closed and its violation is a malformed
		// statement, not a fail-closed row: nothing on a row carries it. The
		// check runs only when the member is present, so an absent
		// networkPosture keeps reporting environment-incomplete alone rather
		// than gaining a second code for the same absence. It runs after the
		// two absence checks above so the primary code for a statement missing
		// several environment members stays the one naming the absence.
		if env.NetworkPosture != nil && !EgressPostures[env.NetworkPosture.Posture] {
			codes = appendCode(codes, CodePostureVocabulary)
		}
	}

	// 6. Vocabulary shape, subset, digest (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
	if env != nil && env.Vocabulary != nil {
		codes = gate0Vocabulary(env.Vocabulary, codes)
	}

	// 7. Corpus manifest digest + duplicate attack ids (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7,req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
	if env != nil && env.Corpus != nil {
		codes = gate0Corpus(env.Corpus, codes)
	}

	// 8. coverage presence (spec:req-fields-networkposture-posture-vocabulary-closed-four@70e087cfa806b7ae).
	if !p.CoveragePresent {
		codes = appendCode(codes, CodeCoverageMissing)
	}

	// 9. attackResults presence (required member, spec:req-fields-set-closed-rather-than-illustrative@b18e334448088624).
	if !p.RowsPresent {
		codes = appendCode(codes, CodeStatementMalformed)
	}

	// 9b. subject cardinality is unconditional (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530): subject MUST
	//     contain exactly one entry on a statement of ANY basis. Only the
	//     binding-digest-input requirement stays substrate-scoped (checked
	//     in gate0SubstrateBindingInputs).
	if len(s.Subject) != 1 {
		codes = appendCode(codes, CodeSubjectCardinality)
	}

	// 10. Per-row actualLayer altitude (spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5): a missing member is a
	//     malformed statement; a clean row must carry the literal "none".
	vocabOK := env != nil && env.Vocabulary != nil && !containsVocabularyCodes(codes)
	for i := range p.Rows {
		row := &p.Rows[i]
		if row.ActualLayer == nil {
			codes = appendCode(codes, CodeMissingActualLayer)
			continue
		}
		if vocabOK && isCleanLabel(env.Vocabulary, row.ContainmentObserved) && *row.ActualLayer != ActualLayerNone {
			codes = appendCode(codes, CodeCleanRowLayerNotNone)
		}
	}

	// 11. Coverage integrity at attack granularity (spec:req-fields-coverage-object-required-coverage-bound@8e3b5d6f5d2bec5f): every row
	//     attackId appears in the manifest, and the union of row attackIds
	//     exactly equals the manifest's attackIds for the assessed classes.
	if env != nil && env.Corpus != nil && env.Corpus.Classes != nil && p.Coverage != nil {
		codes = gate0CoverageIntegrity(p, env, codes)
	}

	// 12. Substrate-carrying statements: runEntropy, subject cardinality,
	//     and the six binding digest inputs (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530,req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
	if hasSubstrateRows(p) {
		codes = gate0SubstrateBindingInputs(s, codes)
	}

	// 13. issuedAt (spec:req-fields-precedent-informative-reserved-members-inside@535994a66179a0d9).
	if !p.IssuedAtPresent {
		codes = appendCode(codes, CodeIssuedAtMissing)
	} else if _, err := parseTimestamp(p.IssuedAt); err != nil {
		codes = appendCode(codes, CodeIssuedAtMalformed)
	}

	return codes
}

func isResultToken(v string) bool {
	return v == ResultPass || v == ResultPassIndirect || v == ResultDegraded || v == ResultFail
}

func containsVocabularyCodes(codes []Code) bool {
	for _, c := range codes {
		switch c {
		case CodeVocabularyMissing, CodeVocabularyNotCanonical, CodeVocabularyCaughtNotSubset, CodeVocabularyDigestMismatch:
			return true
		}
	}
	return false
}

// gate0Vocabulary checks the observationVocabulary shape, subset, and digest.
//
// Every check here reads DECODED Go strings, and the digest is recomputed from
// them rather than compared against the carried bytes, so none of them can see
// what the wire bytes said. They are sound only because ParseStatement refuses,
// on the raw bytes, any statement whose strings are not Unicode scalar
// sequences (ErrStringNotScalar): that is what guarantees a decoded U+FFFD here
// is one the producer wrote and not one the decoder substituted for an unpaired
// surrogate escape. Without that upstream gate, "\ud800" would reach the
// BMP-only check as a legal BMP scalar and pass, and two distinct escapes would
// arrive as one string. Do not move the string-scalar check into this function:
// by this point the fault has already been erased.
func gate0Vocabulary(v *Vocabulary, codes []Code) []Code {
	if !v.LabelsPresent || !v.CaughtPresent {
		return appendCode(codes, CodeVocabularyNotCanonical)
	}
	if !isSortedNoDuplicates(v.Labels) || !isSortedNoDuplicates(v.Caught) {
		codes = appendCode(codes, CodeVocabularyNotCanonical)
	}
	// BMP-only string profile: a supplementary-plane labels/caught entry
	// makes the statement malformed, the same handling as non-canonical
	// bytes. The UTF-16 sort rule above stays in force as defense in depth;
	// this rejection removes the only inputs on which a UTF-16 rail and a
	// code-point rail could order the vocabulary differently.
	if !vocabularyStringsBMPOnly(v.Labels, v.Caught) {
		codes = appendCode(codes, CodeVocabularyNotCanonical)
	}
	labelSet := stringSet(v.Labels)
	for _, c := range v.Caught {
		if !labelSet[c] {
			codes = appendCode(codes, CodeVocabularyCaughtNotSubset)
			break
		}
	}
	want := SHA256Hex(canonicalVocabulary(v.Labels, v.Caught))
	got := ""
	if v.Digest != nil {
		got = v.Digest["sha256"]
	}
	if got != want {
		codes = appendCode(codes, CodeVocabularyDigestMismatch)
	}
	return codes
}

// canonicalVocabulary builds the JCS bytes of the digest pre-image object
// {"caught": [...], "labels": [...]} (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7).
func canonicalVocabulary(labels, caught []string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"caught":`)
	appendStringArray(&buf, caught)
	buf.WriteString(`,"labels":`)
	appendStringArray(&buf, labels)
	buf.WriteByte('}')
	return buf.Bytes()
}

func appendStringArray(buf *bytes.Buffer, ss []string) {
	buf.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			buf.WriteByte(',')
		}
		appendJCSString(buf, s)
	}
	buf.WriteByte(']')
}

func gate0Corpus(c *Corpus, codes []Code) []Code {
	if len(c.ManifestRaw) == 0 {
		return appendCode(codes, CodeEnvironmentIncomplete)
	}
	canon, err := Canonicalize(c.ManifestRaw)
	if err != nil {
		return appendCode(codes, CodeStatementMalformed)
	}
	if c.Sha256() != SHA256Hex(canon) {
		codes = appendCode(codes, CodeCorpusDigestMismatch)
	}
	// An attackId MUST NOT appear under more than one class (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7);
	// a duplicate inside one class array is the same integrity fault.
	declared := 0
	seen := map[string]bool{}
	for _, class := range sortedKeys(c.Classes) {
		for _, id := range c.Classes[class] {
			declared++
			if seen[id] {
				codes = appendCode(codes, CodeManifestDuplicateAttack)
			}
			seen[id] = true
		}
	}

	// The manifest MUST declare at least one attack identifier across all of
	// its classes. A corpus with no adversarial inputs is not an adversarial
	// corpus, so this is well-formedness and not scoring: scoring it would
	// concede that a zero-attack run is a legitimate statement that merely
	// scores badly.
	//
	// What it closes is a total bypass of the substrate rather than a lie
	// about a run. Zero declared attack identifiers means zero rows; zero
	// rows means zero basis: substrate rows; and with no substrate rows the
	// predicate legally permits runEntropy, observationRecords and batchRoot
	// all to be absent (spec:req-fields-row-per-executed-attack-attackid-2@8177bcb6a7441371,req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7). Every structure that would
	// have required a substrate signature drops out, and coverage integrity
	// then compares an empty union of row attack ids against an empty union
	// of manifest attack ids and passes vacuously — so the statement reaches
	// a valid verdict and a pass result with no substrate behind it at all.
	//
	// The count is over attack identifiers and not over classes: a manifest
	// carrying a real class name with an empty id array ({"classes":{"CO":[]}})
	// declares no attacks just as an empty classes object does, and reads far
	// more plausibly. A manifest that DOES declare an identifier is untouched
	// here, which is what leaves the honest fully-skipped run — every class
	// disclosed under coverage.outOfScope, no rows, result degraded — valid.
	if declared == 0 {
		codes = appendCode(codes, CodeCorpusManifestNoAttacks)
	}
	return gate0ExpectedPayloads(c, seen, codes)
}

// gate0ExpectedPayloads checks the optional corpus.manifest.expectedPayloads
// map (spec:req-fields-caught-row-whose-containmentobserved-label@ac678ffd07ea2cf0): every key is an attack identifier the same manifest's
// classes declares, every array is non-empty, sorted ascending by UTF-16 code
// unit and duplicate-free, and every entry is lowercase 64-hex. A manifest
// violating any of these is malformed.
//
// declaredIDs is the set gate0Corpus already built while walking the classes,
// passed in rather than rebuilt: the two must agree on what "the same manifest
// declares" means, and a second walk is a second chance to disagree.
func gate0ExpectedPayloads(c *Corpus, declaredIDs map[string]bool, codes []Code) []Code {
	if !c.ExpectedPayloadsPresent {
		return codes
	}
	if !c.ExpectedPayloadsShapeOK {
		return appendCode(codes, CodeManifestExpectedPayloadsMalformed)
	}
	for _, id := range sortedKeys(c.ExpectedPayloads) {
		values := c.ExpectedPayloads[id]
		if !declaredIDs[id] || len(values) == 0 || !isSortedNoDuplicates(values) {
			return appendCode(codes, CodeManifestExpectedPayloadsMalformed)
		}
		for _, v := range values {
			if !IsLowerHex64(v) {
				return appendCode(codes, CodeManifestExpectedPayloadsMalformed)
			}
		}
	}
	return codes
}

func gate0CoverageIntegrity(p *Predicate, env *Environment, codes []Code) []Code {
	inManifest := map[string]bool{}
	for _, ids := range env.Corpus.Classes {
		for _, id := range ids {
			inManifest[id] = true
		}
	}
	// Coverage MUST be an exhaustive, disjoint partition of the manifest's
	// classes across assessedClasses / outOfScope / routedElsewhere, each a
	// real manifest class (spec:req-fields-networkposture-posture-vocabulary-closed-four-2@591aef9c088d9164,req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7). Enforcing this closes a
	// fail-open: without it a producer drops a failing class from all three
	// sets (silently omitting it while still reporting pass), or pads
	// assessedClasses with a fabricated class the manifest never carried.
	manifestClasses := map[string]bool{}
	for c := range env.Corpus.Classes {
		manifestClasses[c] = true
	}
	classAcct := map[string]int{}
	for _, c := range p.Coverage.AssessedClasses {
		classAcct[c]++
	}
	for c := range p.Coverage.OutOfScope {
		classAcct[c]++
	}
	for c := range p.Coverage.RoutedElsewhere {
		classAcct[c]++
	}
	partitionOK := true
	for c, n := range classAcct {
		if n != 1 || !manifestClasses[c] { // overlap across the three sets, or not a manifest class
			partitionOK = false
		}
	}
	for c := range manifestClasses {
		if classAcct[c] != 1 { // a manifest class left unaccounted, or double-counted
			partitionOK = false
		}
	}
	if !partitionOK {
		codes = appendCode(codes, CodeCoverageIncomplete)
	}

	expected := map[string]bool{}
	for _, class := range p.Coverage.AssessedClasses {
		for _, id := range env.Corpus.Classes[class] {
			expected[id] = true
		}
	}
	// No two rows may carry the same attackId (spec:req-fields-typing-discipline-predicate-commits-stated@22ef77d9eb2d99d7): "one row per
	// executed attack" is a well-formedness invariant. A duplicate is detected
	// BEFORE the rowID set is built, because the set-equality coverage check
	// below silently collapses duplicates.
	rowIDs := map[string]bool{}
	for i := range p.Rows {
		id := p.Rows[i].AttackID
		if rowIDs[id] {
			codes = appendCode(codes, CodeStatementMalformed)
		}
		rowIDs[id] = true
		if !inManifest[id] {
			codes = appendCode(codes, CodeRowAttackUnknown)
		}
	}
	if !sameStringSet(rowIDs, expected) {
		codes = appendCode(codes, CodeCoverageIncomplete)
	}
	return codes
}

func gate0SubstrateBindingInputs(s *Statement, codes []Code) []Code {
	p := s.Predicate
	env := p.Env

	// runEntropy is required exactly when any row carries basis: substrate
	// (spec:req-fields-further-limit-belongs-member-here@8b73aef98ce43cf7). Its absence reports its member code, never a binding
	// mismatch (registry precedence pin 1).
	if env == nil || env.RunEntropy == nil {
		codes = appendCode(codes, CodeRunEntropyMissing)
	} else if !IsLowerHex64(env.RunEntropy.Sha256()) {
		codes = appendCode(codes, CodeDigestNotCanonical)
	}

	// subject cardinality is checked unconditionally in Gate0 (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530).
	// Here only the subject's binding-digest input is validated, alongside the
	// substrate-scoped digest members below. networkPosture is in that list
	// even though version 2 of the binding no longer reads its digest
	// verbatim: the value is still compared byte for byte against a record's
	// aeePostureDigest, so an uppercase spelling on both sides would otherwise
	// pass unnoticed. The observationVocabulary digest is deliberately NOT in
	// the list, because the vocabulary digest-integrity check recomputes it
	// from the carried arrays and a non-canonical value cannot equal that
	// recompute; adding it here would be a condition that could never be the
	// one to fire.
	if len(s.Subject) >= 1 {
		sha, ok := s.Subject[0].Digest["sha256"]
		if !ok {
			codes = appendCode(codes, CodeSubjectSha256Missing)
		} else if !IsLowerHex64(sha) {
			codes = appendCode(codes, CodeDigestNotCanonical)
		}
	}

	// The remaining binding digest inputs must be lowercase 64-hex
	// (spec:req-wireprofile-run-binding-statement-carrying-least@4a906dd0fb911530). Absent parent members were already reported as
	// environment-incomplete.
	if env != nil {
		for _, digest := range []string{
			env.CatchPolicy.Sha256(),
			env.Corpus.Sha256(),
			env.NetworkPosture.Sha256(),
			env.Substrate.Sha256(),
		} {
			if digest != "" && !IsLowerHex64(digest) {
				codes = appendCode(codes, CodeDigestNotCanonical)
			}
		}
	}
	return codes
}

func hasSubstrateRows(p *Predicate) bool {
	for i := range p.Rows {
		if p.Rows[i].IsSubstrate() {
			return true
		}
	}
	return false
}

func isCleanLabel(v *Vocabulary, label string) bool {
	return stringSet(v.Labels)[label] && !stringSet(v.Caught)[label]
}

func isCaughtLabel(v *Vocabulary, label string) bool {
	return stringSet(v.Caught)[label]
}

func vocabularyStringsBMPOnly(labels, caught []string) bool {
	for _, arr := range [][]string{labels, caught} {
		for _, s := range arr {
			if !isBMPOnly(s) {
				return false
			}
		}
	}
	return true
}

func isSortedNoDuplicates(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if !utf16Less(ss[i-1], ss[i]) {
			return false
		}
	}
	return true
}

func stringSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
