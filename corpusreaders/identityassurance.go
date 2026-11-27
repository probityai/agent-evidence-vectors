package corpusreaders

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func init() { register(identityAssurance{}) }

// identityAssurance judges corpora/vectors-identity-assurance/. A record set names one
// subject and lists findings other suites reached about it; the grade is a pure function
// of the set, level 0 to 6. The rules and their order are those of the Python reference
// reader (packaging/agent_evidence_vectors/assurancelevels.py), and the answer is derived
// from the record alone, never from the manifest.
type identityAssurance struct{}

func (identityAssurance) Suite() string { return "identity-assurance-levels/v1" }

const iaContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels"

var iaRungs = []string{"E0", "E1", "E2", "E3", "E4"}

const iaFloorRung = "E2"

// iaTest is one rung of the ladder: the finding reasons, by suite, that prove it.
type iaTest struct {
	name    string
	reasons map[string][]string
}

// T0 (the set names a subject) needs no finding, so the ladder starts at T1.
var iaTests = []iaTest{
	{"T1", map[string][]string{
		"agent-principal-binding/v1":    {"agent_bound"},
		"agent-did-identity-binding/v1": {"subject_bound"},
	}},
	{"T2", map[string][]string{"actor-marker-survival/v1": {"marker_survives"}}},
	{"T3", map[string][]string{"holder-bound-credential/v1": {"holder_bound"}}},
	{"T4", map[string][]string{"delegator-right/v1": {"entitled"}}},
	{"T5", map[string][]string{"credential-reachability/v1": {"contained_verified"}}},
	{"T6", map[string][]string{"evidence-grade-floor/v1": {"grade_derived"}}},
}

type iaFinding struct {
	suite, decision, reason, subject, digest, rung string
	hasRung                                        bool
}

type iaBad string

// iaText is a non-empty string with no leading or trailing whitespace.
func iaText(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" || strings.TrimFunc(s, pyIsSpace) != s {
		return "", false
	}
	return s, true
}

func iaIsHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func iaKeysWithin(m map[string]any, required, optional []string) bool {
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return false
		}
	}
	return true
}

func iaFindingOf(v any) (iaFinding, bool) {
	item, ok := v.(map[string]any)
	if !ok || !iaKeysWithin(item, []string{"suite", "decision", "reason", "subject", "evidence"}, []string{"rung"}) {
		return iaFinding{}, false
	}
	var f iaFinding
	var okSuite, okReason, okSubject bool
	f.suite, okSuite = iaText(item["suite"])
	f.reason, okReason = iaText(item["reason"])
	f.subject, okSubject = iaText(item["subject"])
	if !okSuite || !okReason || !okSubject {
		return iaFinding{}, false
	}
	f.decision, _ = item["decision"].(string)
	if f.decision != "accept" && f.decision != "reject" {
		return iaFinding{}, false
	}
	if raw, present := item["rung"]; present {
		rung, _ := raw.(string)
		if !slices.Contains(iaRungs, rung) {
			return iaFinding{}, false
		}
		f.rung, f.hasRung = rung, true
	}
	evidence, ok := item["evidence"].(map[string]any)
	if !ok {
		return iaFinding{}, false
	}
	if _, present := evidence["sha256"]; !present {
		return iaFinding{}, false
	}
	pointer := []string{"corpus", "member", "file"}
	if len(evidence) != 1 && !iaKeysWithin(evidence, pointer, []string{"sha256"}) {
		return iaFinding{}, false
	}
	for _, m := range pointer {
		if raw, present := evidence[m]; present {
			if _, ok := iaText(raw); !ok {
				return iaFinding{}, false
			}
		}
	}
	f.digest, _ = evidence["sha256"].(string)
	if !iaIsHex64(f.digest) {
		return iaFinding{}, false
	}
	return f, true
}

// iaShape returns the findings of a well-formed set, or the check code that refuses it.
func iaShape(record map[string]any) ([]iaFinding, string) {
	id, present := record["contractId"]
	if !present {
		return nil, "contract_id_missing"
	}
	if id != iaContractID {
		return nil, "contract_id_unknown"
	}
	if !iaKeysWithin(record, []string{"contractId", "subject", "findings"}, nil) {
		return nil, "record_malformed"
	}
	_, okSubject := iaText(record["subject"])
	list, okList := record["findings"].([]any)
	if !okSubject || !okList {
		return nil, "record_malformed"
	}
	findings := make([]iaFinding, 0, len(list))
	for _, raw := range list {
		f, ok := iaFindingOf(raw)
		if !ok {
			return nil, "finding_malformed"
		}
		findings = append(findings, f)
	}
	type key struct{ suite, subject, digest string }
	type answer struct {
		decision, rung, reason string
		hasRung                bool
	}
	type owner struct{ suite, subject string }
	seen := map[key]answer{}
	owned := map[string]owner{}
	for _, f := range findings {
		k, a := key{f.suite, f.subject, f.digest}, answer{f.decision, f.rung, f.reason, f.hasRung}
		if prior, ok := seen[k]; ok && prior != a {
			return nil, "finding_conflict"
		}
		seen[k] = a
		// One piece of evidence is one record of one suite about one subject.
		if prior, ok := owned[f.digest]; ok && prior != (owner{f.suite, f.subject}) {
			return nil, "finding_conflict"
		}
		owned[f.digest] = owner{f.suite, f.subject}
	}
	return findings, ""
}

// iaCause is "" when the test passes, else why it fails.
func iaCause(name string, reasons map[string][]string, mine []iaFinding, anyNamed bool) string {
	if !anyNamed {
		return "no_finding"
	}
	if len(mine) == 0 {
		return "subject_mismatch"
	}
	for _, f := range mine {
		if f.decision == "reject" {
			return "finding_refused:" + f.reason
		}
	}
	for _, f := range mine {
		if !slices.Contains(reasons[f.suite], f.reason) {
			return "reason_not_proving:" + f.reason
		}
	}
	if name == "T6" {
		for _, f := range mine {
			if !f.hasRung {
				return "rung_missing"
			}
			if slices.Index(iaRungs, f.rung) < slices.Index(iaRungs, iaFloorRung) {
				return "rung_below_floor:" + f.rung
			}
		}
	}
	return ""
}

func iaDecide(record map[string]any) scDecision {
	findings, code := iaShape(record)
	if code != "" {
		return scDecision{Decision: "reject", Reason: code}
	}
	level := 0
	for _, t := range iaTests {
		var named, mine []iaFinding
		for _, f := range findings {
			if _, ok := t.reasons[f.suite]; ok {
				named = append(named, f)
				if f.subject == record["subject"] {
					mine = append(mine, f)
				}
			}
		}
		if why := iaCause(t.name, t.reasons, mine, len(named) > 0); why != "" {
			return scDecision{Decision: "accept", Reason: fmt.Sprintf("level=%d next=%s:%s", level, t.name, why)}
		}
		level++
	}
	return scDecision{Decision: "accept", Reason: fmt.Sprintf("level=%d next=none", level)}
}

type iaRetained struct {
	Subject  *string  `json:"subject"`
	Evidence []string `json:"evidence"`
}

type iaVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained iaRetained        `json:"retained"`
}

func iaRetain(record map[string]any) iaRetained {
	findings, code := iaShape(record)
	if record == nil || code != "" {
		return iaRetained{Evidence: []string{}}
	}
	set := map[string]bool{}
	for _, f := range findings {
		set[f.digest] = true
	}
	evidence := make([]string, 0, len(set))
	for d := range set {
		evidence = append(evidence, d)
	}
	sort.Strings(evidence)
	subject := record["subject"].(string)
	return iaRetained{Subject: &subject, Evidence: evidence}
}

func (identityAssurance) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v iaVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = iaJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func iaJudgeMember(caseDir string, v iaVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read")
	}
	var record map[string]any
	if value, err := decodeJSONNumbers(body); err == nil {
		record, _ = value.(map[string]any)
	}
	if !reflect.DeepEqual(iaRetain(record), v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	got := scDecision{Decision: "reject", Reason: "record_malformed"}
	if record != nil {
		got = iaDecide(record)
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}
