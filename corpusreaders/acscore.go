package corpora

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func init() { register(acsCore{}) }

// acsCore judges vectors-acs-core/. It is the Go statement of that corpus's
// check_vectors.py: nothing in it has been run against an implementation, so
// the internal checks are the only thing standing between the corpus and a set
// of files that merely look like one.
type acsCore struct{}

func (acsCore) Suite() string { return "acs-core-negative-conformance" }

var (
	acsVerdicts = map[string]bool{"allow": true, "deny": true, "unmeasurable": true}
	acsKinds    = map[string]bool{"accept": true, "reject": true, "indeterminate": true}
	acsBases    = map[string]bool{"substrate": true, "artifact": true}
	acsScopes   = map[string]bool{"SELF": true, "PEER": true, "EXTERNAL": true}
	// The four rungs a coverage claim can stand on. Declared support and
	// effective enforcement are different properties.
	acsCoverage = map[string]bool{"supported": true, "configured": true, "effective": true, "observed": true}
	// The single-step payload subjects a member may carry, enumerated rather
	// than left to a truthiness test: a member with no subject at all is one an
	// implementation cannot answer about, and that is the shape this catches.
	acsSubjects = []string{"action", "context_entry", "record", "request"}
	// acsIDFields are the fields the identifier is a digest over.
	acsIDFields = []string{"kind", "family", "requirements", "payload", "expected"}
)

type acsManifest struct {
	SpecVersion  string                     `json:"specVersion"`
	SpecVendored map[string]acsVendoredFile `json:"specVendored"`
	CodeRegistry map[string]json.Number     `json:"codeRegistry"`
	Families     map[string]json.RawMessage `json:"families"`
	ObservedRuns []json.RawMessage          `json:"observedRuns"`
	Requirements []acsRequirement           `json:"requirements"`
	Counts       map[string]int             `json:"counts"`
	CorpusDigest string                     `json:"corpusDigest"`
	Vectors      []acsVector                `json:"vectors"`
}

type acsVendoredFile struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

type acsRequirement struct {
	ID             string `json:"id"`
	Vendored       string `json:"vendored"`
	Line           int    `json:"line"`
	Sentence       string `json:"sentence"`
	SentenceDigest string `json:"sentenceDigest"`
}

type acsVector struct {
	ID            string      `json:"id"`
	Kind          string      `json:"kind"`
	File          string      `json:"file"`
	Family        string      `json:"family"`
	Requirements  []string    `json:"requirements"`
	SpecVersion   string      `json:"specVersion"`
	Expected      acsExpected `json:"expected"`
	EvidenceBasis string      `json:"evidenceBasis"`
	WitnessScope  string      `json:"witnessScope"`
	Coverage      string      `json:"coverage"`
}

type acsExpected struct {
	Verdict   string       `json:"verdict"`
	Code      *string      `json:"code"`
	CodeValue *json.Number `json:"codeValue"`
	// ForbidsRegistryCode is present only as true, on a deny whose answer must
	// carry no registry code at all. A null code alone leaves the code
	// unasserted, so a refusal naming any code passes; that is right where the
	// specification fixes no code and forbids none, and wrong where a code
	// would assert a verification result nobody obtained.
	ForbidsRegistryCode *bool   `json:"forbidsRegistryCode,omitempty"`
	UnmeasurableBecause *string `json:"unmeasurableBecause"`
}

func (a acsCore) Judge(dir string, raw []byte) (*Result, error) {
	var m acsManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	known, requirementFindings := a.checkRequirements(dir, &m)
	result.Findings = append(result.Findings, requirementFindings...)

	seen := map[string]bool{}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))
	accepted, rejected, cited := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		switch v.Kind {
		case "accept":
			accepted[v.Family] = true
		case "reject":
			rejected[v.Family] = true
		}
		for _, r := range v.Requirements {
			cited[r] = true
		}
		a.judgeMember(dir, &m, v, known, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, a.checkCorpus(dir, &m, known, accepted, rejected, cited, ids, files)...)
	return result, nil
}

// checkRequirements asserts each identifier still names the sentence it was
// minted against. A reworded requirement is a different requirement and the
// identifier is not reusable for it.
func (acsCore) checkRequirements(dir string, m *acsManifest) (map[string]bool, []string) {
	known := map[string]bool{}
	var findings []string
	for _, row := range m.Requirements {
		if known[row.ID] {
			findings = append(findings, row.ID+": duplicate requirement identifier")
		}
		known[row.ID] = true
		if !existsIn(dir, row.Vendored) {
			findings = append(findings, fmt.Sprintf("%s: names a vendored file %s that is not here", row.ID, row.Vendored))
			continue
		}
		body, err := readIn(dir, row.Vendored)
		if err != nil {
			findings = append(findings, row.ID+": "+err.Error())
			continue
		}
		// The digest is over the NFC bytes of the sentence. Every sentence in
		// this corpus is ASCII, and ASCII is its own NFC form, so no normaliser
		// is needed for them. A non-ASCII sentence is REFUSED rather than
		// hashed unnormalised: a silent wrong digest here would report a corpus
		// as broken while the corpus is intact, and the standard library
		// carries no NFC.
		if !isASCII(row.Sentence) {
			findings = append(findings, fmt.Sprintf(
				"%s: the pinned sentence is not ASCII, and this reader has no NFC "+
					"normaliser to reproduce its digest with. The digest is over NFC bytes; "+
					"add a normaliser before minting a non-ASCII requirement.", row.ID))
			continue
		}
		if sha([]byte(row.Sentence)) != row.SentenceDigest {
			findings = append(findings, row.ID+": the pinned sentence digest does not recompute from the sentence")
		}
		text := string(body)
		index := strings.Index(text, row.Sentence)
		if index < 0 {
			findings = append(findings, row.ID+
				": quotes a sentence the vendored copy no longer carries. A reworded "+
				"requirement is a different requirement and this identifier is not reusable for it.")
			continue
		}
		if strings.Contains(text[index+1:], row.Sentence) {
			findings = append(findings, row.ID+": quotes a sentence that appears more than once, so it identifies nothing")
		}
		if line := strings.Count(text[:index], "\n") + 1; line != row.Line {
			findings = append(findings, fmt.Sprintf("%s: records line %d and the sentence sits on line %d", row.ID, row.Line, line))
		}
	}
	return known, findings
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func (a acsCore) judgeMember(dir string, m *acsManifest, v acsVector, known map[string]bool, out *Member) {
	a.checkVocabulary(m, v, known, out)
	a.checkVerdict(m, v, out)
	if !existsIn(dir, v.File) {
		out.Findings = append(out.Findings, "the manifest names a vector file that does not exist")
		return
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	document, err := decodeJSONNumbers(body)
	if err != nil {
		out.Findings = append(out.Findings, "the vector file does not parse: "+err.Error())
		return
	}
	object, ok := document.(map[string]any)
	if !ok {
		out.Findings = append(out.Findings, "the vector file is not a JSON object")
		return
	}
	// The vector file and the manifest row are two statements of the same
	// facts. They are compared as parsed values so a formatting difference is
	// not a finding and a value difference always is.
	entryValue, err := decodeJSONNumbers(mustMarshal(v))
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	entry, _ := entryValue.(map[string]any)
	for _, field := range []string{"kind", "family", "requirements", "expected", "specVersion"} {
		if !reflect.DeepEqual(object[field], entry[field]) {
			out.Findings = append(out.Findings, "the vector file and the manifest disagree about "+field)
		}
	}
	if id, _ := object["id"].(string); id != v.ID {
		out.Findings = append(out.Findings, "the vector file carries a different identifier")
	}
	// The identifier is a digest over five of the member's own fields, so an
	// edit to the vector file without regenerating leaves a name describing
	// bytes that are no longer there. This is also what makes a corpus-digest
	// failure NAME a member: the aggregate digest says one file moved and this
	// says which.
	if payload, err := idPayloadFromFields(object, acsIDFields); err != nil {
		out.Findings = append(out.Findings, err.Error())
	} else if idFromBytes(payload) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}
	a.checkPayload(v, object, out)
}

func mustMarshal(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		// json.Marshal of a struct of strings, ints and pointers to them cannot
		// fail; returning a body that parses to nothing keeps the caller on its
		// finding path rather than panicking inside a verifier.
		return []byte("null")
	}
	return raw
}

func (acsCore) checkPayload(v acsVector, document map[string]any, out *Member) {
	payload, ok := document["payload"].(map[string]any)
	if !ok {
		out.Findings = append(out.Findings, "carries no payload object")
		return
	}
	if steps, present := payload["steps"]; present {
		list, _ := steps.([]any)
		if len(list) < 2 {
			out.Findings = append(out.Findings,
				"is a sequenced member with fewer than two steps, so nothing about the sequence is under test")
			if v.Kind == "accept" {
				out.Findings = append(out.Findings, "is a sequenced family's control and is not itself sequenced")
			}
		}
		return
	}
	for _, subject := range acsSubjects {
		if _, present := payload[subject]; present {
			return
		}
	}
	out.Findings = append(out.Findings, fmt.Sprintf(
		"carries neither steps nor any of the single-step subjects this suite recognises (%s), "+
			"so there is nothing for an implementation to answer about", strings.Join(acsSubjects, ", ")))
}

func (acsCore) checkVocabulary(m *acsManifest, v acsVector, known map[string]bool, out *Member) {
	for _, field := range []struct {
		value string
		set   map[string]bool
		label string
	}{
		{v.Kind, acsKinds, "kind"},
		{v.EvidenceBasis, acsBases, "evidence basis"},
		{v.WitnessScope, acsScopes, "witness scope"},
		{v.Coverage, acsCoverage, "coverage"},
	} {
		if !field.set[field.value] {
			out.Findings = append(out.Findings, fmt.Sprintf("declares %s %q", field.label, field.value))
		}
	}
	if _, defined := m.Families[v.Family]; !defined {
		out.Findings = append(out.Findings, "cites family "+v.Family+" the manifest does not define")
	}
	for _, r := range v.Requirements {
		if !known[r] {
			out.Findings = append(out.Findings, "cites requirement "+r+" the manifest does not carry")
		}
	}
	if len(v.Requirements) == 0 {
		out.Findings = append(out.Findings, "cites no requirement, so a specification change cannot tell it broke")
	}
	if v.SpecVersion != m.SpecVersion {
		out.Findings = append(out.Findings, "declares a specification version the manifest does not pin")
	}
}

func (a acsCore) checkVerdict(m *acsManifest, v acsVector, out *Member) {
	if !acsVerdicts[v.Expected.Verdict] {
		out.Findings = append(out.Findings, fmt.Sprintf("declares verdict %q", v.Expected.Verdict))
	}
	if v.Expected.Code != nil {
		registered, defined := m.CodeRegistry[*v.Expected.Code]
		switch {
		case !defined:
			out.Findings = append(out.Findings, fmt.Sprintf(
				"asserts code %q, which the specification's own registry does not define. "+
					"A member asserting a code outside the registry is asserting prose with a "+
					"different shape.", *v.Expected.Code))
		case v.Expected.CodeValue == nil || registered.String() != v.Expected.CodeValue.String():
			out.Findings = append(out.Findings, "carries a code value the registry does not pair with that name")
		}
	}
	a.checkThirdBucket(v, out)
	checkForbiddenCode(v.Expected, out)
	if v.Kind == "accept" && v.Expected.Verdict != "allow" {
		out.Findings = append(out.Findings, "is an accept member that does not expect an allow")
	}
	if v.Kind == "reject" && v.Expected.Verdict != "deny" {
		out.Findings = append(out.Findings, "is a reject member that does not expect a deny")
	}
}

// checkForbiddenCode keeps the assertion that a refusal carries no registry
// code to the one place it means something: a deny that names no code. On an
// allow there is no code to forbid, on an unmeasurable member there is no
// answer to constrain, and beside a named code it contradicts itself. A false
// value is a second spelling of an unasserted code, and two spellings of one
// fact give two identifiers to one member.
func checkForbiddenCode(e acsExpected, out *Member) {
	if e.ForbidsRegistryCode == nil {
		return
	}
	if !*e.ForbidsRegistryCode {
		out.Findings = append(out.Findings,
			"carries forbidsRegistryCode false; an unasserted code is spelled by omitting the field")
		return
	}
	if e.Code != nil {
		out.Findings = append(out.Findings, "names a registry code and forbids one")
	}
	if e.Verdict != "deny" {
		out.Findings = append(out.Findings, "forbids a registry code on a verdict other than deny")
	}
}

// checkThirdBucket guards the bucket for a property the specification cannot
// express, both ways. A member that expects no answer and sits outside the
// bucket is scored as though an answer were required; a member inside the
// bucket that expects one is a rejection wearing the bucket's exemption.
func (acsCore) checkThirdBucket(v acsVector, out *Member) {
	reason := v.Expected.UnmeasurableBecause != nil && *v.Expected.UnmeasurableBecause != ""
	if v.Expected.Verdict == "unmeasurable" {
		if v.Kind != "indeterminate" {
			out.Findings = append(out.Findings, "expects an unmeasurable verdict and is not in the indeterminate bucket")
		}
		if !reason {
			out.Findings = append(out.Findings,
				"is unmeasurable and records no reason, which makes it indistinguishable from a member nobody finished")
		}
		if v.Expected.Code != nil {
			out.Findings = append(out.Findings, "is unmeasurable and asserts a code, so it expects an answer after all")
		}
		return
	}
	if v.Kind == "indeterminate" {
		out.Findings = append(out.Findings, "sits in the indeterminate bucket and expects a scorable verdict")
	}
	if reason {
		out.Findings = append(out.Findings, "expects a scorable verdict and carries a reason it cannot be scored")
	}
}

func (acsCore) checkCorpus(dir string, m *acsManifest, known, accepted, rejected, cited map[string]bool,
	ids, files []string) []string {
	var findings []string
	// Every rejecting family accepts something, or a deployment that denies
	// every input scores full marks on it. That deployment governs nothing.
	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		findings = append(findings, fmt.Sprintf("families that reject and never accept: %v", orphan))
	}
	if idle := declaredMinusUsed(known, cited); len(idle) > 0 {
		findings = append(findings, fmt.Sprintf(
			"requirements minted and cited by no member: %v. An identifier with no falsifying "+
				"vector is a row that proves the requirement was named, which is a different "+
				"property from its being forced.", idle))
	}
	carried := map[string]bool{}
	for family := range accepted {
		carried[family] = true
	}
	for family := range rejected {
		carried[family] = true
	}
	if unused := declaredMinusUsed(m.Families, carried); len(unused) > 0 {
		findings = append(findings, fmt.Sprintf("families declared and carried by no member: %v", unused))
	}
	for _, key := range sortedKeys(m.SpecVendored) {
		entry := m.SpecVendored[key]
		if bad := checkVendored(dir, entry.Path, entry.Sha256, "file for "+key); bad != "" {
			findings = append(findings, bad)
		}
	}
	if len(m.ObservedRuns) > 0 {
		findings = append(findings,
			"the manifest records an observed run and this corpus has never been run against "+
				"an implementation. A run row is added by whoever ran it, with what they ran and against what.")
	}
	measured := map[string]int{"accept": 0, "reject": 0, "indeterminate": 0}
	for _, v := range m.Vectors {
		if _, k := measured[v.Kind]; k {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		findings = append(findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		findings = append(findings, err.Error())
	} else if digest != m.CorpusDigest {
		findings = append(findings, "corpusDigest does not match the vector files on disk")
	}
	return findings
}
