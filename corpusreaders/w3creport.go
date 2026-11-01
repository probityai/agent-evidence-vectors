package corpora

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func init() { register(w3cReport{}) }

// w3cReport judges vectors-w3c-report/. It is the Go statement of the
// validator in packaging/agent_evidence_vectors/w3creport.py: every rule here
// has the same shape there, every finding is spelled the same, and a test
// diffs what the two print over the committed corpus and over a mutated one.
// A member is a whole v0.1 per-check report, and the manifest says under which
// requirement identifier, if any, the report is rejected.
type w3cReport struct{}

func (w3cReport) Suite() string { return "w3c-report-v01-conformance" }

const w3cFormat = "public-agent-conformance/report/v0.1"

var (
	w3cStates      = set("pass", "fail", "inconclusive", "not-exercised", "void")
	w3cVerdict     = set("pass", "fail")
	w3cNonVerdict  = set("inconclusive", "not-exercised", "void")
	w3cCauses      = set("not_applicable", "disabled_by_policy", "unsupported_input", "resource_exhausted", "failed", "unavailable", "out_of_scope", "withheld", "evidence-does-not-hold", "integrity-failure", "availability-failure", "precondition-unsatisfiable", w3cConfinementCause)
	w3cNeverExam   = set("not_applicable", "out_of_scope", "withheld")
	w3cOther       = set("unknown", "possible-not-demonstrated", "demonstrated", "foreclosed")
	w3cDisc        = set("unknown", "demonstrated")
	w3cNegative    = set("shown-by-run", "control-failed", "prior-discriminating-run", "nothing")
	w3cChanged     = set("input artifact", "checker rule", "constraint")
	w3cSlots       = set("verdict", "fired-rule list", "error list")
	w3cKinds       = set("accept", "reject")
	w3cSubjects    = set("report", "agent-run-metrics", "llm-context-discovery")
	w3cIDFields    = []string{"kind", "family", "requirements", "subjectType", "subject", "resolves", "expected"}
	w3cAgreeFields = []string{"kind", "family", "requirements", "expected", "specVersion", "subjectType"}
	w3cCoverageStr = []string{"surface", "scan-depth", "point-in-time", "linked-repo"}
	w3cClaims      = set("satisfied", "not-satisfied", "not-claimable")
)

// w3cConfinementCause is row 4's antecedent as a cause value admitted only
// under void, so row 4 reads cause against state the way row 3 does and the
// four-field record carries no extra cell (v0.1 sections 1.2 and 4).
const w3cConfinementCause = "confinement-failed-during-check"

// w3cNoVoid is the fourth completeness claim of v0.1 section 5.2, "no
// declared check is void": population the declared checks, satisfied when
// the void count is zero. Judged when present, as in the Python module.
const w3cNoVoid = "no-void"

func set(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}

func w3cR(n int) string { return fmt.Sprintf("W3C-R-%03d", n) }

type w3cManifest struct {
	SpecVersion  string                     `json:"specVersion"`
	SpecVendored map[string]acsVendoredFile `json:"specVendored"`
	Families     map[string]json.RawMessage `json:"families"`
	Requirements []acsRequirement           `json:"requirements"`
	Counts       map[string]int             `json:"counts"`
	CorpusDigest string                     `json:"corpusDigest"`
	Vectors      []w3cVector                `json:"vectors"`
	EmitterRuns  []w3cEmitterRun            `json:"referenceEmitterRuns"`
}

// w3cEmitterRun is one published run of the reference emitter: the v0.1 report
// it wrote, the harness report it wrote that from, and the record of the run,
// each pinned by digest.
type w3cEmitterRun struct {
	Path              string `json:"path"`
	Sha256            string `json:"sha256"`
	ConformanceReport w3cPin `json:"conformanceReport"`
	Run               w3cPin `json:"run"`
}

type w3cPin struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

type w3cVector struct {
	ID           string      `json:"id"`
	Kind         string      `json:"kind"`
	File         string      `json:"file"`
	Family       string      `json:"family"`
	Requirements []string    `json:"requirements"`
	SpecVersion  string      `json:"specVersion"`
	SubjectType  string      `json:"subjectType"`
	Expected     w3cExpected `json:"expected"`
}

type w3cExpected struct {
	Verdict string    `json:"verdict"`
	Rejects *[]string `json:"rejects"`
	// Cause is the code a reject member's rejection must name, for a member
	// whose row alone does not say why: a float and a root that does not
	// recompute both land under W3C-R-020.
	Cause *string `json:"cause,omitempty"`
}

func (w w3cReport) Judge(dir string, raw []byte) (*Result, error) {
	var m w3cManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	known, findings := w.checkRequirements(dir, &m)
	result.Findings = append(result.Findings, findings...)
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		w.checkVocabulary(&m, v, known, &member)
		w.checkFile(dir, v, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, w.checkCorpus(dir, &m, known)...)
	return result, nil
}

// checkRequirements is acsCore's, with the same findings; the sentence may
// span a line break, which strings.Index reads as any other byte.
func (w3cReport) checkRequirements(dir string, m *w3cManifest) (map[string]bool, []string) {
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
		if !isASCII(row.Sentence) {
			findings = append(findings, row.ID+": the pinned sentence is not ASCII")
			continue
		}
		if sha([]byte(row.Sentence)) != row.SentenceDigest {
			findings = append(findings, row.ID+": the pinned sentence digest does not recompute from the sentence")
		}
		text := string(body)
		index := strings.Index(text, row.Sentence)
		if index < 0 {
			findings = append(findings, row.ID+": quotes a sentence the vendored copy no longer carries")
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

func (w3cReport) checkVocabulary(m *w3cManifest, v w3cVector, known map[string]bool, out *Member) {
	if !w3cKinds[v.Kind] {
		out.Findings = append(out.Findings, "declares kind "+v.Kind)
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
	if !w3cSubjects[v.SubjectType] {
		out.Findings = append(out.Findings, "declares subject type "+v.SubjectType)
	}
	w3cCheckExpectation(v, known, out)
}

// w3cCheckExpectation: the expected block must restate the member's kind and
// name rejection rows the manifest carries and the member itself cites.
func w3cCheckExpectation(v w3cVector, known map[string]bool, out *Member) {
	if !w3cKinds[v.Expected.Verdict] || v.Expected.Verdict != v.Kind {
		out.Findings = append(out.Findings, "expects a verdict that is not its kind")
	}
	if v.Expected.Rejects == nil {
		out.Findings = append(out.Findings, "declares no rejects list")
		return
	}
	rejects := *v.Expected.Rejects
	if v.Expected.Verdict == "accept" && len(rejects) > 0 {
		out.Findings = append(out.Findings, "is an accept member that expects a rejection")
	}
	if cause := v.Expected.Cause; cause != nil && (v.Expected.Verdict != "reject" || !w3cCauseCodes[*cause]) {
		out.Findings = append(out.Findings, "expects the cause "+*cause+", which only a reject member names, from the closed set")
	}
	if v.Expected.Verdict == "reject" && len(rejects) != 1 {
		out.Findings = append(out.Findings, "is a reject member that does not name exactly one row")
	}
	cited := set(v.Requirements...)
	for _, r := range rejects {
		if !known[r] {
			out.Findings = append(out.Findings, "expects rejection under "+r+", which the manifest does not carry")
		}
		if !cited[r] {
			out.Findings = append(out.Findings, "expects rejection under "+r+" and does not cite it")
		}
	}
}

func (w w3cReport) checkFile(dir string, v w3cVector, out *Member) {
	object, finding := readW3CMember(dir, v)
	if finding != "" {
		out.Findings = append(out.Findings, finding)
		return
	}
	out.Findings = append(out.Findings, w3cIdentityFindings(object, v)...)
	out.Findings = append(out.Findings, w3cVerdictFindings(object, v)...)
}

// readW3CMember reads a member's vector file as a JSON object, or names why
// it cannot be read as one.
func readW3CMember(dir string, v w3cVector) (map[string]any, string) {
	if !existsIn(dir, v.File) {
		return nil, "the manifest names a vector file that does not exist"
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		return nil, err.Error()
	}
	document, err := decodeJSONNumbers(body)
	if err != nil {
		return nil, "the vector file does not parse: " + err.Error()
	}
	object, ok := document.(map[string]any)
	if !ok {
		return nil, "the vector file is not a JSON object"
	}
	return object, ""
}

// w3cIdentityFindings holds the vector file to its manifest row and its
// identifier to the member's own bytes.
func w3cIdentityFindings(object map[string]any, v w3cVector) []string {
	var findings []string
	entryValue, err := decodeJSONNumbers(mustMarshal(v))
	if err != nil {
		return append(findings, err.Error())
	}
	entry, _ := entryValue.(map[string]any)
	for _, field := range w3cAgreeFields {
		if !jsonEqual(object[field], entry[field]) {
			findings = append(findings, "the vector file and the manifest disagree about "+field)
		}
	}
	if id, _ := object["id"].(string); id != v.ID {
		findings = append(findings, "the vector file carries a different identifier")
	}
	if payload, err := w3cIDPayload(object); err != nil {
		findings = append(findings, "the member has no RFC 8785 form: "+err.Error())
	} else if idFromBytes(payload) != v.ID {
		findings = append(findings, "identifier does not recompute from the member's own bytes")
	}
	return findings
}

// w3cVerdictFindings judges the member's subject and compares the verdict,
// and for a report the cause, with what the manifest expects.
func w3cVerdictFindings(object map[string]any, v w3cVector) []string {
	if shape := subjectShapeErrors(v.SubjectType, object["subject"]); len(shape) > 0 {
		return []string{"the subject is not the shape its definition gives: " + strings.Join(shape, "; ")}
	}
	var resolves map[string]any
	if raw, present := object["resolves"]; present && raw != nil {
		store, ok := raw.(map[string]any)
		if !ok {
			return []string{"resolves is present and is not an object"}
		}
		resolves = store
	}
	observed := subjectRejections(v.SubjectType, object["subject"].(map[string]any), resolves)
	var expected []string
	if v.Expected.Rejects != nil {
		expected = sortedStrings(*v.Expected.Rejects)
	}
	if strings.Join(observed, ",") != strings.Join(expected, ",") {
		return []string{fmt.Sprintf(
			"the validator rejects under %s and the manifest expects %s", w3cList(observed), w3cList(expected))}
	}
	if stated := v.Expected.Cause; stated != nil && v.SubjectType == "report" {
		named := w3cCheckSetCause(object["subject"].(map[string]any))
		if named != *stated {
			if named == "" {
				named = "none"
			}
			return []string{fmt.Sprintf(
				"the validator names the cause %s and the manifest expects %s", named, *stated)}
		}
	}
	return nil
}

// w3cIDPayload is the RFC 8785 form of the fields a member's identifier
// covers, a missing field read as null: RFC 8785 as written, numbers as IEEE
// 754 doubles, so a member carrying a number the jcs-sha256 profile refuses
// still has a name.
func w3cIDPayload(document map[string]any) ([]byte, error) {
	subset := map[string]any{}
	for _, field := range w3cIDFields {
		subset[field] = document[field]
	}
	return rfc8785Bytes(subset)
}

// subjectShapeErrors and subjectRejections select the validator the manifest
// names for a member: the v0.1 report rows, or one of the two Internet-Drafts
// judged in their own files.
func subjectShapeErrors(subjectType string, subject any) []string {
	switch subjectType {
	case "agent-run-metrics":
		return armShapeErrors(subject)
	case "llm-context-discovery":
		return lcdShapeErrors(subject)
	}
	return w3cShapeErrors(subject)
}

func subjectRejections(subjectType string, subject map[string]any, resolves map[string]any) []string {
	switch subjectType {
	case "agent-run-metrics":
		return armRejections(subject)
	case "llm-context-discovery":
		return lcdRejections(subject)
	}
	return w3cRejections(subject, resolves)
}

// jsonEqual compares two decoded values the way Python's == does on parsed
// JSON: numbers by value, everything else structurally.
func jsonEqual(a, b any) bool {
	left, errA := pythonCompactJSON(a)
	right, errB := pythonCompactJSON(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(left) == string(right)
}

func w3cList(values []string) string { return "[" + strings.Join(values, ", ") + "]" }

func (w w3cReport) checkCorpus(dir string, m *w3cManifest, known map[string]bool) []string {
	var findings []string
	tally := w3cTally(m)
	if orphan := orphanTwins(tally.accepted, tally.rejected); len(orphan) > 0 {
		findings = append(findings, "families that reject and never accept: "+w3cList(orphan))
	}
	if idle := declaredMinusUsed(known, tally.cited); len(idle) > 0 {
		findings = append(findings, "requirements minted and cited by no member: "+w3cList(idle))
	}
	if unused := declaredMinusUsed(m.Families, tally.carried); len(unused) > 0 {
		findings = append(findings, "families declared and carried by no member: "+w3cList(unused))
	}
	findings = append(findings, w3cVendoredFindings(dir, m)...)
	findings = append(findings, w3cEmitterRunFindings(dir, m)...)
	if bad := countsDisagree(m.Counts, tally.measured); bad != "" {
		findings = append(findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, tally.ids, tally.files)
	if err != nil {
		findings = append(findings, err.Error())
	} else if digest != m.CorpusDigest {
		findings = append(findings, "corpusDigest does not match the vector files on disk")
	}
	return findings
}

// w3cCorpusTally is one pass over the manifest's members: which families each
// kind carries, which requirements are cited, and the identity and file lists
// in manifest order for the corpus digest.
type w3cCorpusTally struct {
	accepted, rejected, carried, cited map[string]bool
	measured                           map[string]int
	ids, files                         []string
}

func w3cTally(m *w3cManifest) w3cCorpusTally {
	t := w3cCorpusTally{
		accepted: map[string]bool{}, rejected: map[string]bool{}, carried: map[string]bool{}, cited: map[string]bool{},
		measured: map[string]int{"accept": 0, "reject": 0},
		ids:      make([]string, 0, len(m.Vectors)), files: make([]string, 0, len(m.Vectors)),
	}
	for _, v := range m.Vectors {
		switch v.Kind {
		case "accept":
			t.accepted[v.Family] = true
		case "reject":
			t.rejected[v.Family] = true
		}
		if _, k := t.measured[v.Kind]; k {
			t.measured[v.Kind]++
			t.carried[v.Family] = true
		}
		for _, r := range v.Requirements {
			t.cited[r] = true
		}
		t.ids, t.files = append(t.ids, v.ID), append(t.files, v.File)
	}
	return t
}

// w3cVendoredFindings: every vendored specification file is present and
// matches the digest the manifest pins for it.
func w3cVendoredFindings(dir string, m *w3cManifest) []string {
	var findings []string
	for _, key := range sortedKeys(m.SpecVendored) {
		entry := m.SpecVendored[key]
		if !existsIn(dir, entry.Path) {
			findings = append(findings, fmt.Sprintf("the vendored file for %s %s is missing", key, entry.Path))
			continue
		}
		body, err := readIn(dir, entry.Path)
		if err != nil || sha(body) != entry.Sha256 {
			findings = append(findings, fmt.Sprintf("the vendored file for %s %s does not match its pinned digest", key, entry.Path))
		}
	}
	return findings
}

// w3cEmitterRunFindings: every published run of the reference emitter is on
// disk with the digests the manifest pins, and the report it wrote is one the
// validator accepts as it stands.
func w3cEmitterRunFindings(dir string, m *w3cManifest) []string {
	var findings []string
	for _, run := range m.EmitterRuns {
		reportHolds := true
		for _, pin := range []w3cPin{{run.Path, run.Sha256}, run.ConformanceReport, run.Run} {
			if finding := w3cPinFinding(dir, pin); finding != "" {
				findings = append(findings, finding)
				reportHolds = reportHolds && pin.Path != run.Path
			}
		}
		if reportHolds {
			findings = append(findings, w3cEmittedReportFindings(dir, run.Path)...)
		}
	}
	return findings
}

func w3cPinFinding(dir string, pin w3cPin) string {
	if !existsIn(dir, pin.Path) {
		return fmt.Sprintf("referenceEmitterRuns: %s is missing", pin.Path)
	}
	body, err := readIn(dir, pin.Path)
	if err != nil || sha(body) != pin.Sha256 {
		return fmt.Sprintf("referenceEmitterRuns: %s does not match its pinned digest", pin.Path)
	}
	return ""
}

func w3cEmittedReportFindings(dir, path string) []string {
	body, err := readIn(dir, path)
	if err != nil {
		return []string{fmt.Sprintf("referenceEmitterRuns: %s does not parse", path)}
	}
	document, err := decodeJSONNumbers(body)
	if err != nil {
		return []string{fmt.Sprintf("referenceEmitterRuns: %s does not parse", path)}
	}
	if shape := w3cShapeErrors(document); len(shape) > 0 {
		return []string{fmt.Sprintf("referenceEmitterRuns: %s is not a v0.1 report: %s", path, strings.Join(shape, "; "))}
	}
	if rejected := w3cRejections(document.(map[string]any), nil); len(rejected) > 0 {
		return []string{fmt.Sprintf("referenceEmitterRuns: %s is rejected under %s", path, w3cList(rejected))}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Shape.
// ---------------------------------------------------------------------------

func isStr(v any) bool { _, ok := v.(string); return ok }
func isObj(v any) bool { _, ok := v.(map[string]any); return ok }

func w3cShapeCheck(check any, index int, out *[]string) {
	where := fmt.Sprintf("checks[%d]", index)
	object, ok := check.(map[string]any)
	if !ok {
		*out = append(*out, where+" is not an object")
		return
	}
	if !isStr(object["check"]) {
		*out = append(*out, where+" carries no string check identity")
	}
	if !isStr(object["state"]) {
		*out = append(*out, where+" carries no string state")
	}
	for _, slot := range []string{"cause", "other-verdict", "discrimination"} {
		if value, present := object[slot]; present && !isObj(value) {
			*out = append(*out, where+"."+slot+" is present and is not an object")
		}
	}
	if cause, ok := object["cause"].(map[string]any); ok && !isStr(cause["code"]) {
		*out = append(*out, where+".cause carries no string code")
	}
	for _, slot := range []string{"other-verdict", "discrimination"} {
		if value, ok := object[slot].(map[string]any); ok && !isStr(value["value"]) {
			*out = append(*out, where+"."+slot+" carries no string value")
		}
	}
	if value, present := object["declared-exclusion"]; present {
		if _, isBool := value.(bool); !isBool {
			*out = append(*out, where+".declared-exclusion is present and is not a boolean")
		}
	}
}

// w3cShapeDelta: a delta, when present, is an object, and it lists its changes,
// when present, as an array of objects (0087 section 1.3, "delta the concrete
// change").
func w3cShapeDelta(object map[string]any, where string, out *[]string) {
	raw, present := object["delta"]
	if !present {
		return
	}
	delta, ok := raw.(map[string]any)
	if !ok {
		*out = append(*out, where+".delta is present and is not an object")
		return
	}
	changes, listed := delta["changes"]
	if !listed {
		return
	}
	list, isList := changes.([]any)
	if !isList {
		*out = append(*out, where+".delta.changes is not an array")
		return
	}
	for j, change := range list {
		if !isObj(change) {
			*out = append(*out, fmt.Sprintf("%s.delta.changes[%d] is not an object", where, j))
		}
	}
}

func w3cShapeEvidence(item any, index int, out *[]string) {
	where := fmt.Sprintf("evidence[%d]", index)
	object, ok := item.(map[string]any)
	if !ok {
		*out = append(*out, where+" is not an object")
		return
	}
	if !isStr(object["id"]) {
		*out = append(*out, where+" carries no string id")
	}
	if !isStr(object["changed"]) {
		*out = append(*out, where+" carries no string changed slot")
	}
	if !isObj(object["fixed"]) {
		*out = append(*out, where+" carries no fixed object")
	}
	for _, slot := range []string{"compared", "moved"} {
		if _, ok := stringList(object[slot]); !ok {
			*out = append(*out, where+"."+slot+" is not a list of strings")
		}
	}
	w3cShapeDelta(object, where, out)
	observations, ok := object["observations"].([]any)
	if !ok {
		*out = append(*out, where+".observations is not a list")
		return
	}
	for j, observation := range observations {
		o, ok := observation.(map[string]any)
		ref, hasRef := o["reference"]
		carried, hasCarried := o["carried"]
		if !ok || hasRef == hasCarried {
			*out = append(*out, fmt.Sprintf("%s.observations[%d] is not exactly one of reference or carried", where, j))
		} else if (hasRef && !isObj(ref)) || (hasCarried && !isObj(carried)) {
			*out = append(*out, fmt.Sprintf("%s.observations[%d] carries a form that is not an object", where, j))
		}
	}
}

// w3cShapeDomain: the domain is declared once, at run level, and every slot
// names it by identifier. A slot naming a domain the run does not declare is a
// dangling reference and not a row.
func w3cShapeDomain(report map[string]any, out *[]string) {
	domain, ok := report["domain"].(map[string]any)
	if !ok || !isStr(domain["id"]) {
		*out = append(*out, "the report declares no domain object with a string id")
		return
	}
	declared := domain["id"].(string)
	checks, _ := report["checks"].([]any)
	for i, raw := range checks {
		check, _ := raw.(map[string]any)
		other, _ := check["other-verdict"].(map[string]any)
		if named, ok := other["domain"].(string); ok && named != declared {
			*out = append(*out, fmt.Sprintf("checks[%d].other-verdict names a domain the run does not declare", i))
		}
	}
	evidence, _ := report["evidence"].([]any)
	for i, raw := range evidence {
		item, _ := raw.(map[string]any)
		fixed, _ := item["fixed"].(map[string]any)
		if named, ok := fixed["domain"].(string); ok && named != declared {
			*out = append(*out, fmt.Sprintf("evidence[%d].fixed names a domain the run does not declare", i))
		}
	}
}

func stringList(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func w3cShapeErrors(value any) []string {
	var out []string
	report, ok := value.(map[string]any)
	if !ok {
		return []string{"the report is not a JSON object"}
	}
	if format, _ := report["format"].(string); format != w3cFormat {
		out = append(out, fmt.Sprintf("the report does not declare format '%s'", w3cFormat))
	}
	checks, ok := report["checks"].([]any)
	if !ok {
		out = append(out, "checks is not a list")
	}
	if w3cShapeList(checks, "check", w3cShapeCheck, &out) {
		out = append(out, "two checks carry one identity")
	}
	var evidence []any
	if raw, present := report["evidence"]; present {
		if evidence, ok = raw.([]any); !ok {
			out = append(out, "evidence is present and is not a list")
		}
	}
	if w3cShapeList(evidence, "id", w3cShapeEvidence, &out) {
		out = append(out, "two evidence objects carry one id")
	}
	w3cShapeDomain(report, &out)
	for _, slot := range []string{"roll-up", "check-set", "fixed"} {
		if value, present := report[slot]; present && !isObj(value) {
			out = append(out, slot+" is present and is not an object")
		}
	}
	return out
}

// w3cShapeList runs the per-item shape check over a list and reports whether
// two items carry one value under the identity key.
func w3cShapeList(items []any, key string, shape func(any, int, *[]string), out *[]string) bool {
	ids := map[string]bool{}
	duplicate := false
	for i, item := range items {
		shape(item, i, out)
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := object[key].(string); ok {
			if ids[id] {
				duplicate = true
			}
			ids[id] = true
		}
	}
	return duplicate
}

// ---------------------------------------------------------------------------
// The rows.
// ---------------------------------------------------------------------------

type w3cRejects map[string]bool

func (r w3cRejects) add(n int) { r[w3cR(n)] = true }

func w3cRowCause(check map[string]any, state string, out w3cRejects) {
	cause, present := check["cause"]
	if w3cNonVerdict[state] && !present {
		out.add(1)
	}
	if w3cVerdict[state] && present {
		out.add(7)
	}
	if !present {
		return
	}
	code, _ := cause.(map[string]any)["code"].(string)
	if !w3cCauses[code] {
		out.add(19)
	}
	if state == "void" && w3cNeverExam[code] {
		out.add(2)
	}
	if state == "not-exercised" && code == "integrity-failure" {
		out.add(3)
	}
	if code == w3cConfinementCause && state != "void" {
		out.add(4)
	}
}

func w3cRowPairs(check map[string]any, state string, out w3cRejects) {
	if flag, _ := check["declared-exclusion"].(bool); flag && state != "not-exercised" {
		out.add(5)
	}
}

func w3cRowQualifiers(check map[string]any, state string, evidence map[string]map[string]any, resolves map[string]any, out w3cRejects) {
	other, hasOther := check["other-verdict"].(map[string]any)
	disc, hasDisc := check["discrimination"].(map[string]any)
	if w3cNonVerdict[state] && (hasOther || hasDisc) {
		out.add(6)
	}
	ov, dv := "unknown", "unknown"
	if hasOther {
		ov, _ = other["value"].(string)
	}
	if hasDisc {
		dv, _ = disc["value"].(string)
	}
	if !w3cOther[ov] || !w3cDisc[dv] {
		out.add(19)
		return
	}
	if ov == "foreclosed" && dv == "demonstrated" {
		out.add(8)
	}
	if dv == "demonstrated" && (ov == "unknown" || ov == "possible-not-demonstrated") {
		out.add(9)
	}
	w3cRowOtherVerdict(other, ov, evidence, resolves, out)
	w3cRowDiscrimination(disc, dv, evidence, out)
}

// w3cRowOtherVerdict: the rows the other-verdict qualifier carries on its own:
// a restated domain, an unbounded foreclosure, an asserted value with no
// reference, and (row 13) a demonstration whose recomputed moved
// does not contain the verdict.
func w3cRowOtherVerdict(other map[string]any, ov string, evidence map[string]map[string]any, resolves map[string]any, out w3cRejects) {
	domain, hasDomain := other["domain"]
	if hasDomain && !isStr(domain) {
		out.add(28)
	}
	if ov == "foreclosed" && (!isStr(other["constraint-set"]) || !hasDomain) {
		out.add(10)
	}
	if ov != "demonstrated" && ov != "foreclosed" {
		return
	}
	ref, isString := other["ref"].(string)
	if !isString || evidence[ref] == nil {
		out.add(11)
		return
	}
	if ov == "demonstrated" {
		moved, state := w3cRecomputedMoved(evidence[ref], resolves)
		if state == w3cRead && !moved["verdict"] {
			out.add(25)
		}
	}
}

// w3cRowDiscrimination: a demonstrated discrimination must point at evidence
// that is a delta observation and not a checker-rule change.
func w3cRowDiscrimination(disc map[string]any, dv string, evidence map[string]map[string]any, out w3cRejects) {
	if dv != "demonstrated" {
		return
	}
	ref, isString := disc["ref"].(string)
	if !isString || evidence[ref] == nil {
		out.add(11)
		return
	}
	if changed, _ := evidence[ref]["changed"].(string); changed == "checker rule" {
		out.add(12)
	}
	if !w3cDeltaRelated(evidence[ref]) {
		out.add(24)
	}
}

// w3cDeltaChanges is the list of concrete changes a stated delta lists, or
// nil when the object states none; arity is its length and is never declared.
func w3cDeltaChanges(item map[string]any) []map[string]any {
	delta, _ := item["delta"].(map[string]any)
	raw, _ := delta["changes"].([]any)
	if len(raw) == 0 {
		return nil
	}
	changes := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		change, ok := entry.(map[string]any)
		if field, _ := change["field"].(string); !ok || field == "" {
			return nil
		}
		changes = append(changes, change)
	}
	return changes
}

// w3cDeltaRelated: two observations, a stated delta, and the checker, the
// constraint set and the domain pinned by name.
func w3cDeltaRelated(item map[string]any) bool {
	observations, _ := item["observations"].([]any)
	fixed, _ := item["fixed"].(map[string]any)
	if len(observations) != 2 || w3cDeltaChanges(item) == nil {
		return false
	}
	for _, key := range []string{"checker", "constraint-set", "domain"} {
		if value, _ := fixed[key].(string); value == "" {
			return false
		}
	}
	return true
}

// The reading table for carry-or-reference, as the Python module reads it: a
// carried observation is read as carried; a referenced one resolves with a
// matching digest (read), resolves with a mismatch (an integrity failure), or
// does not resolve (unchecked, and the rows reading moved degrade).
const (
	w3cRead      = "read"
	w3cMismatch  = "mismatch"
	w3cUnchecked = "unchecked"
)

func w3cOutcomeOf(body any) (string, string, bool) {
	object, ok := body.(map[string]any)
	if !ok {
		return "", "", false
	}
	verdict, isString := object["verdict"].(string)
	rules, isList := stringList(object["rules"])
	if !isString || !isList {
		return "", "", false
	}
	return verdict, strings.Join(sortedStrings(rules), "\x00"), true
}

// w3cReadObservation is the outcome an observation resolves to and the reading
// table line it fell on.
func w3cReadObservation(observation map[string]any, resolves map[string]any) (string, string, string) {
	if carried, present := observation["carried"]; present {
		verdict, rules, ok := w3cOutcomeOf(carried)
		if !ok {
			return "", "", w3cUnchecked
		}
		return verdict, rules, w3cRead
	}
	reference, ok := observation["reference"].(map[string]any)
	if !ok || !isStr(reference["sha256"]) {
		return "", "", w3cUnchecked
	}
	locator, ok := reference["vector"].(string)
	resolved, found := resolves[locator]
	if !ok || !found {
		return "", "", w3cUnchecked
	}
	body, ok := resolved.(map[string]any)
	if !ok || body["sha256"] != reference["sha256"] {
		return "", "", w3cMismatch
	}
	verdict, rules, ok := w3cOutcomeOf(body)
	if !ok {
		return "", "", w3cUnchecked
	}
	return verdict, rules, w3cRead
}

// w3cRecomputedMoved is the set of slots that moved between the two
// observations, with the reading-table line the pair fell on.
func w3cRecomputedMoved(item map[string]any, resolves map[string]any) (map[string]bool, string) {
	observations, _ := item["observations"].([]any)
	if len(observations) != 2 {
		return nil, w3cUnchecked
	}
	first, _ := observations[0].(map[string]any)
	second, _ := observations[1].(map[string]any)
	v1, r1, s1 := w3cReadObservation(first, resolves)
	v2, r2, s2 := w3cReadObservation(second, resolves)
	if s1 == w3cMismatch || s2 == w3cMismatch {
		return nil, w3cMismatch
	}
	if s1 != w3cRead || s2 != w3cRead {
		return nil, w3cUnchecked
	}
	moved := map[string]bool{}
	if v1 != v2 {
		moved["verdict"] = true
	}
	if r1 != r2 {
		moved["fired-rule list"] = true
	}
	return moved, w3cRead
}

// w3cRowRecomputedMoved is rules 16 and 21: moved is read as recomputed from
// the two observations, never as the emitter declared it. Rule 16 holds the
// recomputed moved against the declared compared set (v0.1 section 2), rule 21
// the declared moved against the recomputed one, both over the slots a reader
// recomputes: no rejection row reads the recompute-opaque error list (section
// 2.1). A mismatch is rule 20; observations that cannot be read fire neither.
func w3cRowRecomputedMoved(item map[string]any, resolves map[string]any, out w3cRejects) {
	recomputed, state := w3cRecomputedMoved(item, resolves)
	if state == w3cMismatch {
		out.add(20)
		return
	}
	if state != w3cRead {
		return
	}
	compared, _ := stringList(item["compared"])
	within := set(compared...)
	for v := range recomputed {
		if !within[v] {
			out.add(16)
			break
		}
	}
	moved, _ := stringList(item["moved"])
	declared := map[string]bool{}
	for _, v := range moved {
		if v == "verdict" || v == "fired-rule list" {
			declared[v] = true
		}
	}
	if len(declared) != len(recomputed) {
		out.add(21)
		return
	}
	for v := range declared {
		if !recomputed[v] {
			out.add(21)
			return
		}
	}
}

// w3cDigestReferenced: form, an observation is carried or referenced with a digest.
func w3cDigestReferenced(observation map[string]any) bool {
	if _, present := observation["carried"]; present {
		return true
	}
	reference, ok := observation["reference"].(map[string]any)
	return ok && isStr(reference["sha256"])
}

// w3cRowsEvidenceForm: the form rows, decidable from the object alone: row 14,
// a declared arity, a restated domain.
func w3cRowsEvidenceForm(item map[string]any, out w3cRejects) {
	moved, _ := stringList(item["moved"])
	observations, _ := item["observations"].([]any)
	if len(moved) > 0 {
		for _, raw := range observations {
			if observation, _ := raw.(map[string]any); !w3cDigestReferenced(observation) {
				out.add(26)
				break
			}
		}
	}
	delta, _ := item["delta"].(map[string]any)
	_, itemArity := item["arity"]
	_, deltaArity := delta["arity"]
	if itemArity || deltaArity {
		out.add(27)
	}
	fixed, _ := item["fixed"].(map[string]any)
	if !isStr(fixed["domain"]) {
		out.add(28)
	}
}

func w3cRowsEvidence(item map[string]any, resolves map[string]any, out w3cRejects) {
	if changed, _ := item["changed"].(string); !w3cChanged[changed] {
		out.add(19)
	}
	compared, _ := stringList(item["compared"])
	moved, _ := stringList(item["moved"])
	for _, v := range append(append([]string{}, compared...), moved...) {
		if !w3cSlots[v] {
			out.add(19)
			break
		}
	}
	w3cRowsEvidenceForm(item, out)
	w3cRowRecomputedMoved(item, resolves, out)
}

func w3cCounts(checks []map[string]any) map[string]int {
	counts := map[string]int{"declared": len(checks), "exercised": 0}
	for state := range w3cStates {
		counts[state] = 0
	}
	for _, check := range checks {
		state, _ := check["state"].(string)
		if _, known := counts[state]; known && w3cStates[state] {
			counts[state]++
		}
		if state != "not-exercised" {
			counts["exercised"]++
		}
	}
	return counts
}

// intValue reads a JSON integer the way Python's isinstance(v, int) does: a
// float spelling, a bool and a string are all refused.
func intValue(v any) (int64, bool) {
	number, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// w3cBindingRefusal is why a set binding does not bind (rule (b)), "" when it
// binds: a digest over a set carries its leaf count and its tree shape, and an
// encoding it declares comes from the closed set. Only the last refusal is a
// coded cause; the others are this reader's own words.
func w3cBindingRefusal(ref any) string {
	object, ok := ref.(map[string]any)
	if !ok || !isStr(object["sha256"]) {
		return "no digest"
	}
	if count, ok := intValue(object["leaf-count"]); !ok || count < 0 {
		return "no leaf count"
	}
	if shape, _ := object["tree-shape"].(string); !w3cShapes[shape] {
		return "no tree shape from the closed set"
	}
	if w3cUnsupportedDeclaration(object) {
		return w3cUnsupportedEncoding
	}
	return ""
}

func w3cSetBinding(ref any, out w3cRejects) (map[string]any, bool) {
	if w3cBindingRefusal(ref) != "" {
		out.add(15)
		return nil, false
	}
	return ref.(map[string]any), true
}

// w3cUnsupportedDeclaration: an encoding a binding declares comes from the
// closed set (proposed: 2026Oct/0038). A binding that declares none is
// digested under jcs-sha256.
func w3cUnsupportedDeclaration(binding map[string]any) bool {
	declared, present := binding["digest-encoding"]
	if !present {
		return false
	}
	name, ok := declared.(string)
	return !ok || !w3cDigestEncodings[name]
}

func w3cIdentity(v any, ids map[string]bool) bool {
	checks, ok := stringList(v)
	if !ok || len(checks) == 0 {
		return false
	}
	for _, c := range checks {
		if !ids[c] {
			return false
		}
	}
	return true
}

func w3cRowsNegative(rollup map[string]any, counts map[string]int, ids map[string]bool, runFixed any, out w3cRejects) {
	field, ok := rollup["negative-capable"].(map[string]any)
	if !ok || !isStr(field["kind"]) {
		out.add(13)
		return
	}
	kind := field["kind"].(string)
	switch {
	case !w3cNegative[kind]:
		out.add(19)
	case kind == "shown-by-run" && counts["fail"] < 1:
		out.add(13)
	case kind == "control-failed":
		control, ok := field["control"].(map[string]any)
		if !ok || !w3cIdentity(control["checks"], ids) {
			out.add(13)
		} else if state, _ := control["state"].(string); state != "fail" {
			out.add(13)
		} else {
			w3cRowBinding(control["fixed"], runFixed, 29, out)
		}
	case kind == "prior-discriminating-run":
		if !w3cIdentity(field["check-identity"], ids) {
			out.add(14)
		}
		w3cSetBinding(field["reference"], out)
		w3cRowBinding(field["fixed"], runFixed, 33, out)
	}
}

// numberEquals compares a decoded JSON value to an integer the way Python's
// == does: 2 and 2.0 are equal, and anything that is not a number is not.
func numberEquals(v any, want int) bool {
	number, ok := v.(json.Number)
	if !ok {
		return false
	}
	f, err := number.Float64()
	return err == nil && f == float64(want)
}

func countField(v any) (int64, bool) {
	n, ok := intValue(v)
	return n, ok && n >= 0
}

// w3cCoverageWellFormed is rule 22: a coverage block states its scope in
// controlled fields, and a sampled scan records what it did not read.
func w3cCoverageWellFormed(coverage map[string]any) bool {
	for _, key := range w3cCoverageStr {
		if !isStr(coverage[key]) {
			return false
		}
	}
	snapshots, ok := coverage["snapshots"].([]any)
	if !ok {
		return false
	}
	for _, raw := range snapshots {
		snap, ok := raw.(map[string]any)
		if !ok || !isStr(snap["name"]) || !isStr(snap["date"]) {
			return false
		}
	}
	live, liveOK := coverage["live-observed"].(bool)
	sampled, sampledOK := coverage["sampled"].(bool)
	_ = live
	if !liveOK || !sampledOK {
		return false
	}
	scannable, ok := countField(coverage["scannable-files"])
	if !ok {
		return false
	}
	if sampled {
		scanned, ok := countField(coverage["scanned-files"])
		if !ok || scanned > scannable {
			return false
		}
	}
	return true
}

func w3cRowsCoverage(report map[string]any, out w3cRejects) {
	raw, present := report["coverage"]
	if !present || raw == nil {
		return
	}
	coverage, ok := raw.(map[string]any)
	if !ok || !w3cCoverageWellFormed(coverage) {
		out.add(22)
	}
}

func w3cDemonstrated(check map[string]any) bool {
	disc, ok := check["discrimination"].(map[string]any)
	if !ok {
		return false
	}
	value, _ := disc["value"].(string)
	return value == "demonstrated"
}

// w3cClaimHolds is one completeness claim against the population it counts
// over: the size must recompute, an empty population is not claimable, and a
// satisfied claim must be true of the records.
func w3cClaimHolds(name string, claim map[string]any, checks []map[string]any, counts map[string]int) bool {
	populations := map[string]int{
		"accounting": counts["declared"],
		"execution":  counts["declared"],
		"evidence":   counts["pass"] + counts["fail"],
		w3cNoVoid:    counts["declared"],
	}
	value, _ := claim["claim"].(string)
	if !numberEquals(claim["population"], populations[name]) || !w3cClaims[value] {
		return false
	}
	if populations[name] == 0 {
		return value == "not-claimable"
	}
	if value != "satisfied" {
		return true
	}
	switch name {
	case w3cNoVoid:
		return counts["void"] == 0
	case "execution":
		return counts["exercised"] == counts["declared"]
	case "evidence":
		for _, check := range checks {
			if state, _ := check["state"].(string); state == "pass" && !w3cDemonstrated(check) {
				return false
			}
		}
	}
	return true
}

// w3cRowsCompleteness is rule 23: a completeness claim carries the size of
// the population it counts over, and a claim over an empty one is not claimable.
func w3cRowsCompleteness(rollup map[string]any, checks []map[string]any, counts map[string]int, out w3cRejects) {
	raw, present := rollup["completeness"]
	if !present || raw == nil {
		return
	}
	claims, ok := raw.(map[string]any)
	if !ok {
		out.add(23)
		return
	}
	for _, name := range []string{"accounting", "execution", "evidence"} {
		claim, ok := claims[name].(map[string]any)
		if !ok || !w3cClaimHolds(name, claim, checks, counts) {
			out.add(23)
			return
		}
	}
	if raw, present := claims[w3cNoVoid]; present {
		claim, ok := raw.(map[string]any)
		if !ok || !w3cClaimHolds(w3cNoVoid, claim, checks, counts) {
			out.add(23)
		}
	}
}

func w3cRowsRollup(report map[string]any, checks []map[string]any, out w3cRejects) {
	counts := w3cCounts(checks)
	rollup, ok := report["roll-up"].(map[string]any)
	if !ok {
		out.add(17)
		return
	}
	for key, value := range counts {
		if !numberEquals(rollup[key], value) {
			out.add(17)
			break
		}
	}
	carried, referenced := 0, 0
	if evidence, ok := report["evidence"].([]any); ok {
		for _, item := range evidence {
			observations, _ := item.(map[string]any)["observations"].([]any)
			for _, observation := range observations {
				if _, isCarried := observation.(map[string]any)["carried"]; isCarried {
					carried++
				} else {
					referenced++
				}
			}
		}
	}
	if !numberEquals(rollup["carried"], carried) || !numberEquals(rollup["referenced"], referenced) {
		out.add(18)
	}
	ids := map[string]bool{}
	for _, check := range checks {
		id, _ := check["check"].(string)
		ids[id] = true
	}
	w3cRowsNegative(rollup, counts, ids, report["fixed"], out)
	w3cRowsCompleteness(rollup, checks, counts, out)
}

// w3cRoots is the closed set of tree shapes and the construction each name
// denotes. w3cShapes is derived from its keys, so a name cannot enter the set
// without a root function and a name outside it has none to fall through to.
var w3cRoots = map[string]func([][]byte) []byte{
	"flat":    flatRoot,
	"rfc6962": mth,
	// RFC 9942 section 5.1 registers RFC9162_SHA256 as the Merkle tree of RFC
	// 9162 section 2.1.1 over SHA-256, whose Merkle Tree Hash is the RFC 6962
	// one: the same leaf and node prefixes and the same split.
	"RFC9162_SHA256": mth,
}

var w3cShapes = func() map[string]bool {
	out := map[string]bool{}
	for name := range w3cRoots {
		out[name] = true
	}
	return out
}()

// w3cRowBinding reads a filling of v0.1 section 5.4 against the checker and
// constraint set of the checks it speaks for: rule 29 a control's binding, rule
// 33 a prior run's. It is read only where both the filling and the run declare
// the binding, so a binding that differs from the run's is refused and a
// missing one is not.
func w3cRowBinding(bound, runFixed any, row int, out w3cRejects) {
	filling, okFilling := bound.(map[string]any)
	run, okRun := runFixed.(map[string]any)
	if !okFilling || !okRun {
		return
	}
	for _, slot := range []string{"checker", "constraint-set"} {
		if !jsonEqual(filling[slot], run[slot]) {
			out.add(row)
			return
		}
	}
}

// w3cCheckSetRoot is the root over the check set: each check's jcs-sha256
// bytes, under the named tree shape.
func w3cCheckSetRoot(checks []map[string]any, shape string) (string, error) {
	root, registered := w3cRoots[shape]
	if !registered {
		return "", fmt.Errorf("tree shape %q is not in the closed set", shape)
	}
	leaves := make([][]byte, 0, len(checks))
	for _, check := range checks {
		leaf, err := jcsSHA256Bytes(check)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, leaf)
	}
	return hex.EncodeToString(root(leaves)), nil
}

// flatRoot is SHA-256 over the concatenated SHA-256 of each leaf, in order.
func flatRoot(leaves [][]byte) []byte {
	h := sha256.New()
	for _, leaf := range leaves {
		sum := sha256.Sum256(leaf)
		h.Write(sum[:])
	}
	return h.Sum(nil)
}

// mth is the Merkle tree hash of RFC 6962 section 2.1: leaf prefix 0x00, node
// prefix 0x01, and the left subtree holding the largest power of two strictly
// smaller than the count.
func mth(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		sum := sha256.Sum256(append([]byte{0}, leaves[0]...))
		return sum[:]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(mth(leaves[:k]))
	h.Write(mth(leaves[k:]))
	return h.Sum(nil)
}

// w3cCheckSetFinding is the row the check-set binding is rejected under (0
// when it holds) and the cause code it names ("" for a binding refused in
// words no member names).
func w3cCheckSetFinding(report map[string]any, checks []map[string]any) (int, string) {
	if refusal := w3cBindingRefusal(report["check-set"]); refusal == w3cUnsupportedEncoding {
		return 15, w3cUnsupportedEncoding
	} else if refusal != "" {
		return 15, ""
	}
	binding := report["check-set"].(map[string]any)
	if count, _ := intValue(binding["leaf-count"]); count != int64(len(checks)) {
		return 15, ""
	}
	shape, _ := binding["tree-shape"].(string)
	root, err := w3cCheckSetRoot(checks, shape)
	if err != nil {
		var refused *w3cDigestRefusal
		if errors.As(err, &refused) {
			return 20, refused.cause
		}
		return 20, ""
	}
	if binding["sha256"].(string) != root {
		return 20, w3cDigestsDiffer
	}
	return 0, ""
}

func w3cRowsCheckSet(report map[string]any, checks []map[string]any, out w3cRejects) {
	if row, _ := w3cCheckSetFinding(report, checks); row != 0 {
		out.add(row)
	}
}

// w3cCheckSetCause is the cause a rejection from the report's check-set
// binding names, "" when it names none (check_set_cause in the Python module).
func w3cCheckSetCause(report map[string]any) string {
	rawChecks, _ := report["checks"].([]any)
	checks := make([]map[string]any, 0, len(rawChecks))
	for _, raw := range rawChecks {
		checks = append(checks, raw.(map[string]any))
	}
	_, cause := w3cCheckSetFinding(report, checks)
	return cause
}

// w3cRejections is rejections() in the Python module: the sorted requirement
// identifiers a well-shaped report is rejected under. resolves is what this
// reader can resolve a referenced observation to, keyed by vector locator.
func w3cRejections(report map[string]any, resolves map[string]any) []string {
	out := w3cRejects{}
	if resolves == nil {
		resolves = map[string]any{}
	}
	rawChecks, _ := report["checks"].([]any)
	checks := make([]map[string]any, 0, len(rawChecks))
	for _, raw := range rawChecks {
		checks = append(checks, raw.(map[string]any))
	}
	evidence := map[string]map[string]any{}
	if items, ok := report["evidence"].([]any); ok {
		for _, raw := range items {
			item := raw.(map[string]any)
			evidence[item["id"].(string)] = item
		}
	}
	for _, check := range checks {
		state, _ := check["state"].(string)
		if !w3cStates[state] {
			out.add(19)
			continue
		}
		w3cRowCause(check, state, out)
		w3cRowPairs(check, state, out)
		w3cRowQualifiers(check, state, evidence, resolves, out)
	}
	for _, item := range evidence {
		w3cRowsEvidence(item, resolves, out)
	}
	w3cRowsRollup(report, checks, out)
	w3cRowsCheckSet(report, checks, out)
	w3cRowsCoverage(report, out)
	ids := make([]string, 0, len(out))
	for id := range out {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
