package aee

// The coverage validity requirements 0.7 adds (spec:req-fields-six-further-coverage-validity-requirements@415eace88255cb8a). They sit apart
// from the per-row requirements in validity.go for a reason the specification
// states in the same sentence that introduces them: they hold on the STATEMENT,
// or on every row rather than only on a basis: substrate row. The per-row gate
// runs under `if !row.IsSubstrate() { continue }`, so a rule written there
// would silently acquire the scope that loop has, which is the scope three of
// the five are specifically not written to.
//
// carriedRecordsCover below is a sixth, added after the revision the vendored
// copy is pinned to; its own comment says which anchors it borrows until a
// re-vendor gives it one of its own. Every count in this file's comments is
// the pinned document's, so it says five.
//
// None of these reads a signature or a key, so the layer stays a pure function
// of the carried statement, exactly as the requirements beside them are.

import (
	"bytes"
	"encoding/hex"
	"sort"
	"time"
)

// recordKinds decodes each carried record far enough to read its aeeKind, and
// nothing further. A record whose payload did not decode, does not parse as an
// I-JSON object, or carries no string aeeKind yields "", which no rule below
// matches: those faults are already reported by the paths that own them, and
// naming them again here would give a vector a second code for one fault.
func recordKinds(p *Predicate, states []recordState) []string {
	kinds := make([]string, len(p.Records))
	for i := range p.Records {
		if states[i].decodeErr {
			continue
		}
		v, err := parseJSONValue(states[i].payloadBytes)
		if err != nil {
			continue
		}
		obj, ok := v.(*jsonObject)
		if !ok {
			continue
		}
		if kind, ok := objString(obj, memberKind); ok {
			kinds[i] = kind
		}
	}
	return kinds
}

// payloadObject re-parses one record's payload. Callers have already
// established through recordKinds that the bytes parse to an object.
func payloadObject(state *recordState) *jsonObject {
	v, err := parseJSONValue(state.payloadBytes)
	if err != nil {
		return nil
	}
	obj, _ := v.(*jsonObject)
	return obj
}

// rowResolves reports whether the row resolves at least one in-range
// observationRefs index to a record of the named kind. A row with a malformed
// refs member resolves nothing here: ref-malformed owns that fault.
func rowResolves(row *Row, kinds []string, kind string) bool {
	if !row.RefsPresent || row.RefsErr != nil {
		return false
	}
	for _, idx := range row.Refs {
		if idx >= 0 && idx < len(kinds) && kinds[idx] == kind {
			return true
		}
	}
	return false
}

// gate1CommitmentsAnyBasis evaluates the requirements that hold on a statement
// of ANY basis. Three of the five are written over every row rather than only
// over a basis: substrate row, so they run before the substrate-row path
// returns and they never read the derived run binding -- which an
// artifact-only statement has no obligation to make derivable, since
// runEntropy is required exactly when some row declares that basis.
func gate1CommitmentsAnyBasis(p *Predicate, states []recordState) []Code {
	if !p.RecordsPresent || len(p.Records) == 0 {
		// With no records there is no interception to contradict or to orphan,
		// and a pinned row resolving nothing is already refused by the
		// existence part below, which reads the row rather than the record set.
		return attributionBindings(p, states, nil)
	}
	kinds := recordKinds(p, states)
	var codes []Code
	codes = appendCodes(codes, cleanRowsContradicted(p, kinds))
	codes = appendCodes(codes, interceptionsOrphaned(p, kinds))
	codes = appendCodes(codes, attributionBindings(p, states, kinds))
	return codes
}

// gate1CommitmentsSubstrate evaluates the requirements that read the derived
// run binding, so it runs only on the path that has one.
func gate1CommitmentsSubstrate(p *Predicate, states []recordState, binding string, issuedAt time.Time) []Code {
	if !p.RecordsPresent || len(p.Records) == 0 {
		// A substrate row with no records at all is already owned by
		// records-absent, which fires first and says the same thing about more
		// of the statement.
		return nil
	}
	kinds := recordKinds(p, states)
	var codes []Code
	codes = appendCodes(codes, sealsCommitToCarriedSet(p, states, kinds, binding))
	codes = appendCodes(codes, sealedRecordPresent(p, states, kinds, binding, issuedAt))
	codes = appendCodes(codes, carriedRecordsCover(p, states, kinds, binding, issuedAt))
	codes = appendCodes(codes, sealNamedAttacksCaught(p, states, kinds, binding))
	codes = appendCodes(codes, assessedSetDeclared(p, states, kinds, binding))
	return codes
}

func appendCodes(dst []Code, src []Code) []Code {
	for _, c := range src {
		dst = appendCode(dst, c)
	}
	return dst
}

// cleanRowsContradicted implements the first requirement: a clean row resolves
// no observationRefs index to an interception record (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7). Stated
// over every row, so the loop reads no basis.
func cleanRowsContradicted(p *Predicate, kinds []string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	for i := range p.Rows {
		row := &p.Rows[i]
		if !isCleanLabel(voc, row.ContainmentObserved) {
			continue
		}
		if rowResolves(row, kinds, KindInterception) {
			return []Code{CodeCleanRowContradicted}
		}
	}
	return nil
}

// interceptionsOrphaned implements the second: every carried interception
// record is resolved by at least one observationRefs index on a CAUGHT row
// (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7). One record MAY be resolved by several rows, so the test is
// existence and never a count.
func interceptionsOrphaned(p *Predicate, kinds []string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	resolved := make([]bool, len(p.Records))
	for i := range p.Rows {
		row := &p.Rows[i]
		if !isCaughtLabel(voc, row.ContainmentObserved) {
			continue
		}
		if !row.RefsPresent || row.RefsErr != nil {
			continue
		}
		for _, idx := range row.Refs {
			if idx >= 0 && idx < len(resolved) {
				resolved[idx] = true
			}
		}
	}
	for i := range p.Records {
		if kinds[i] == KindInterception && !resolved[i] {
			return []Code{CodeInterceptionRecordOrphaned}
		}
	}
	return nil
}

// observedSetDigest recomputes the value a sealed record's aeeObservedSet
// commits to (spec:req-fields-both-registrations-verdict-preserving-what@3f3cfef70326695f): the lowercase 64-hex SHA-256 of the RFC 8785
// canonicalization of the duplicate-free array, sorted ascending by UTF-16
// code unit, of the leaf hashes of every interception and examination record.
//
// The entries are lowercase hex, so they are ASCII, so their UTF-16 code-unit
// order and their byte order are the same order. sort.Strings is therefore the
// rule and not an approximation of it -- but the equivalence is a property of
// the value space rather than of the sort, which is why it is written down
// here rather than assumed at the call site.
func observedSetDigest(p *Predicate, states []recordState, kinds []string) string {
	seen := map[string]bool{}
	leaves := make([]string, 0, len(p.Records))
	for i := range p.Records {
		if kinds[i] != KindInterception && kinds[i] != KindExamination {
			continue
		}
		h := LeafHash(states[i].pae)
		leaf := hex.EncodeToString(h[:])
		if seen[leaf] {
			continue
		}
		seen[leaf] = true
		leaves = append(leaves, leaf)
	}
	sort.Strings(leaves)
	var buf bytes.Buffer
	appendStringArray(&buf, leaves)
	return SHA256Hex(buf.Bytes())
}

// sealsCommitToCarriedSet implements the fourth: aeeObservedSet on every
// carried sealed record equals the recompute (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7).
//
// A seal whose member is absent or is not lowercase 64-hex is NOT reported
// here. That record covers nothing by its own kind's constraints, which is a
// different fault with a different code, and reporting both would give one
// mutation two codes.
func sealsCommitToCarriedSet(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	want := ""
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		got, ok := objString(obj, memberObservedSet)
		if !ok || !IsLowerHex64(got) {
			continue
		}
		if want == "" {
			want = observedSetDigest(p, states, kinds)
		}
		if got != want {
			return []Code{CodeObservedSetMismatch}
		}
	}
	return nil
}

// sealedRecordPresent implements the third: a statement carrying at least one
// basis: substrate row carries at least one sealed record satisfying every
// constraint of its kind and whose aeeRunBinding equals the derived binding,
// whether or not any row resolves an index to it (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7).
func sealedRecordPresent(p *Predicate, states []recordState, kinds []string, binding string, issuedAt time.Time) []Code {
	if !hasSubstrateRows(p) {
		return nil
	}
	pinnedPosture := p.Env.NetworkPosture.Sha256()
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		a := analyzePayload(&p.Records[i], &states[i], binding)
		if len(a.codes) > 0 {
			continue
		}
		if evaluateKind(a, pinnedPosture, nil, issuedAt, declaredAttackIDs(p)).valid {
			return nil
		}
	}
	return []Code{CodeSealedRecordAbsent}
}

// isCoveringKind reports whether a kind is one of the four the document
// defines constraints for. The two kinds registered as covering nothing and
// every kind this verifier does not recognize are deliberately outside it:
// neither carries a constraint that could be violated, and sweeping an
// unrecognized kind in would refuse the forward compatibility the document
// grants a minor version to add one (spec:req-fields-aeerunbinding-string-run-binding-digest@19184ed4961dd3e4,req-fields-arming-record-s-payload-additionally@09cfae859933aba4).
func isCoveringKind(kind string) bool {
	switch kind {
	case KindInterception, KindArming, KindSealed, KindExamination:
		return true
	}
	return false
}

// carriedRecordsCover is the universal partner of sealedRecordPresent above:
// every carried record that binds to this run and whose aeeKind names a
// covering kind satisfies every constraint of that kind, whether or not any row
// resolves an observationRefs index to it (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7 for the requirement it
// partners, spec:req-fields-fields-divide-identity-whose-signature-3@ab95391e07e8db81 for the constraints themselves).
//
// Why it exists. The kind constraints were read on exactly two paths, and both
// are chosen by the producer. checkSubstrateRow reads them for the records a
// row's observationRefs resolve, and sealedRecordPresent reads them until it
// finds ONE seal that passes. So a producer holding a sealed record the
// substrate signed with aeeStillArmed false carries it, points the row at a
// second seal, and the statement reads valid / pass with the record that says
// otherwise sitting in observationRecords and committed inside batchRoot. It is
// carried, it is signed under the same substrate key, and nothing reads it.
// Fourteen reject vectors in this corpus flipped to valid on that one edit, and
// the same gap held open for arming (a second arming record), for examination
// (an unreferenced one), and for interception -- where interceptionsOrphaned
// forces a caught row to resolve the record but the per-row gate returns early
// on any row that is not basis: substrate, so an artifact-basis caught row
// satisfies the reference while nothing ever reads the payload.
//
// This is the RULE and not a READING of it: the obligation is stated over the
// carried record, so which rows exist and where they point cannot move it.
//
// Two scope decisions, both taken to make this a pure quantifier flip rather
// than a second predicate that could drift from the first.
//
// The candidate set is exactly the one sealedRecordPresent admits -- a record
// that decodes, parses, passes the byte-level payload checks and whose
// aeeRunBinding equals the derived binding. A record excluded by those filters
// is making no claim about THIS run, or is not readable at all, and either way
// the exclusion costs nothing a byte-pure layer could collect: reaching it
// requires editing a substrate-signed payload, which breaks that record's
// signature and is refused at GATE 2. The defect above needs no edit at all,
// which is why it is a hole here and that one is not.
//
// armingPostures is nil, exactly as sealedRecordPresent passes nil. The seal's
// posture equality against an arming record is stated over the arming records a
// ROW resolves (spec:req-fields-dsse-envelope-per-observation-payload@b25ccffb96b860aa), and a statement-level rule has no row; the
// pinned-posture half of that equality is checked here as it is there. Keeping
// both quantifiers over one predicate is the point -- a second evaluation of a
// seal that could disagree with the first would be a worse defect than the one
// this closes.
//
// The failure code is the kind's own, never a new one. A reader who resolves a
// defective record from a row and a reader who finds it carried beside the rows
// have found the same fault in the same record, and a second spelling would
// oblige a third party to implement two names for one condition.
//
// NOTE on the citations above. The vendored specification predates this
// requirement: spec/predicates/adversarial-execution-evidence.md is pinned to
// the PR revision that states five statement-level requirements, and this is
// the sixth, added in the round-15 revision. The anchors therefore name the
// sibling requirement and the constraint definitions rather than the sentence
// that states this one, which does not exist in the pinned bytes. They move
// onto it in the same pass that re-vendors (scripts/vendor-spec.py), which
// remaps every citation and re-syncs both content ledgers.
func carriedRecordsCover(p *Predicate, states []recordState, kinds []string, binding string, issuedAt time.Time) []Code {
	if !hasSubstrateRows(p) {
		return nil
	}
	pinnedPosture := p.Env.NetworkPosture.Sha256()
	declared := declaredAttackIDs(p)
	var codes []Code
	for i := range p.Records {
		if !isCoveringKind(kinds[i]) {
			continue
		}
		a := analyzePayload(&p.Records[i], &states[i], binding)
		if len(a.codes) > 0 {
			continue
		}
		if ev := evaluateKind(a, pinnedPosture, nil, issuedAt, declared); !ev.valid {
			codes = appendCode(codes, ev.failCode)
		}
	}
	return codes
}

// declaredAttackIDs is the set of attack identifiers the carried
// corpus.manifest.classes declares.
func declaredAttackIDs(p *Predicate) map[string]bool {
	declared := map[string]bool{}
	if p.Env == nil || p.Env.Corpus == nil {
		return declared
	}
	for _, ids := range p.Env.Corpus.Classes {
		for _, id := range ids {
			declared[id] = true
		}
	}
	return declared
}

// attackIDArrayOK is the shared shape rule for the two arrays of attack
// identifiers 0.7 adds, aeeAssessedAttacks and aeeObservedAttacks
// (spec:req-fields-what-neither-kind-used-claim@0af0cebb0785e202,req-fields-comparison-subset-rather-than-equality@b518035679b715d4): duplicate-free, sorted ascending by UTF-16 code
// unit, every entry an identifier the carried manifest declares. The EMPTY
// array satisfies it, which is deliberate on the seal: a substrate holding no
// correspondence declares that on the wire rather than by omission.
func attackIDArrayOK(attacks []string, declared map[string]bool) bool {
	if !isSortedNoDuplicates(attacks) {
		return false
	}
	for _, id := range attacks {
		if !declared[id] {
			return false
		}
	}
	return true
}

// sealNamedAttacksCaught implements the aeeObservedAttacks statement rule
// (spec:req-fields-comparison-subset-rather-than-equality@b518035679b715d4): for every identifier the array names, the
// statement MUST carry a row with that attackId whose containmentObserved is
// in the carried caught set.
//
// The rule reads in ONE direction. A seal omitting an attack licenses nothing
// and in particular does not oblige a clean row, which is what makes a lower
// bound sound without asking the substrate to resolve every ambiguous case.
func sealNamedAttacksCaught(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	voc := p.Env.Vocabulary
	if voc == nil {
		return nil
	}
	caughtIDs := map[string]bool{}
	for i := range p.Rows {
		if isCaughtLabel(voc, p.Rows[i].ContainmentObserved) {
			caughtIDs[p.Rows[i].AttackID] = true
		}
	}
	for i := range p.Records {
		if kinds[i] != KindSealed {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		attacks, ok := objStringArray(obj, memberObservedAttacks)
		if !ok || !attackIDArrayOK(attacks, declaredAttackIDs(p)) {
			continue
		}
		for _, id := range attacks {
			if !caughtIDs[id] {
				return []Code{CodeObservedAttackUncaught}
			}
		}
	}
	return nil
}

// assessedSetDeclared implements the aeeAssessedAttacks statement rule
// (spec:req-fields-what-neither-kind-used-claim@0af0cebb0785e202): the union of the manifest's identifiers for
// the carried coverage.assessedClasses MUST be a subset of the array the
// arming record signed before injection.
//
// A subset and not an equality. An equality would refuse the honest run that
// declared two classes, lost one part-way and disclosed the loss, and would
// buy, against the withdrawal it appears to catch, only the version of that
// withdrawal that leaves the arming record in place.
func assessedSetDeclared(p *Predicate, states []recordState, kinds []string, binding string) []Code {
	if p.Coverage == nil || p.Env == nil || p.Env.Corpus == nil {
		return nil
	}
	assessed := map[string]bool{}
	for _, class := range p.Coverage.AssessedClasses {
		for _, id := range p.Env.Corpus.Classes[class] {
			assessed[id] = true
		}
	}
	for i := range p.Records {
		if kinds[i] != KindArming {
			continue
		}
		obj := payloadObject(&states[i])
		if rb, ok := objString(obj, memberRunBinding); !ok || rb != binding {
			continue
		}
		declared, ok := objStringArray(obj, memberAssessedAttacks)
		if !ok || !attackIDArrayOK(declared, declaredAttackIDs(p)) {
			continue
		}
		declaredSet := stringSet(declared)
		for id := range assessed {
			if !declaredSet[id] {
				return []Code{CodeAssessedSetExceedsDeclaration}
			}
		}
	}
	return nil
}

// attributionBindings implements the fifth requirement (spec:req-fields-clean-row-resolves-observationrefs-index@156f05c55b1207d7), in the
// three parts the specification writes it in. The parts are checked in the
// order they are stated, and the existence part is checked FIRST because it is
// the part the other two are vacuous without: a universally quantified rule
// over an empty set is true, so a producer that deletes the interception
// records keeps the stronger label unless something asks whether any remain.
func attributionBindings(p *Predicate, states []recordState, kinds []string) []Code {
	for i := range p.Rows {
		row := &p.Rows[i]
		if row.Attribution == nil || *row.Attribution != AttributionPinned {
			continue
		}
		if !rowResolves(row, kinds, KindInterception) {
			return []Code{CodeAttributionPinnedRecordless}
		}
		expected := expectedFor(p, row.AttackID)
		if len(expected) == 0 {
			return []Code{CodeAttributionUnpinnable}
		}
		if code := pinMatches(row, states, kinds, expected); code != "" {
			return []Code{code}
		}
	}
	return nil
}

// expectedFor returns the commitment values the carried manifest declares for
// one attack, or nil when it declares none. An absent expectedPayloads map and
// a map with no entry for this attack are the same answer, which is what the
// requirement asks: a row whose attackId carries no such entry MUST declare
// paired.
func expectedFor(p *Predicate, attackID string) []string {
	if p.Env == nil || p.Env.Corpus == nil || p.Env.Corpus.ExpectedPayloads == nil {
		return nil
	}
	return p.Env.Corpus.ExpectedPayloads[attackID]
}

// pinMatches checks the third part: every interception record the row resolves
// carries in its aeePayloadCommitment at least one value from the manifest's
// entry for the row's attack.
func pinMatches(row *Row, states []recordState, kinds []string, expected []string) Code {
	want := stringSet(expected)
	for _, idx := range row.Refs {
		if idx < 0 || idx >= len(kinds) || kinds[idx] != KindInterception {
			continue
		}
		obj := payloadObject(&states[idx])
		values, ok := objStringArray(obj, memberPayloadCommitment)
		if !ok {
			// Absent or wrong-typed: the record covers nothing by its own
			// kind's constraints, and that is the fault reported.
			continue
		}
		matched := false
		for _, v := range values {
			if want[v] {
				matched = true
				break
			}
		}
		if !matched {
			return CodeAttributionPinUnmatched
		}
	}
	return ""
}

// commitmentArrayOK is the shared shape rule for aeePayloadCommitment
// (spec:req-fields-neither-kind-carries-constraints-because@09116e23544e2120): duplicate-free, sorted ascending by UTF-16 code unit,
// non-empty, every entry lowercase 64-hex.
func commitmentArrayOK(values []string) bool {
	if len(values) == 0 || !isSortedNoDuplicates(values) {
		return false
	}
	for _, v := range values {
		if !IsLowerHex64(v) {
			return false
		}
	}
	return true
}
