package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"time"
)

func init() { register(evidenceCell{}) }

// evidenceCell judges corpora/vectors-incident-evidence-cell/. Each member is
// one coded cell of an incident decision table, carried as an in-toto
// Statement v1 whose subjects are the source documents the cell was coded
// from. The reader applies the Python reader's checks in the same order and
// names the first that fails:
//
//  1. statement_malformed: exactly _type, subject, predicateType and predicate,
//     the in-toto v1 type, a non-empty list of named SHA-256 subjects, this
//     predicate type and an object predicate;
//  2. predicate_malformed: exactly the predicate's members, each of its type,
//     with exactly one of value and notAddressed;
//  3. closed_vocabulary_violation: state, response and supportLabel inside
//     their closed sets;
//  4. empty_cell_labelled: an empty cell is labelled unknown;
//  5. truth_disclaimer_missing: doesNotAssert carries the exact disclaimer.
//
// A signature over the Statement shows who coded the cell, never that the
// cell is true; this reader checks the record, not the envelope around it.
type evidenceCell struct{}

const (
	ecStatementType = "https://in-toto.io/Statement/v1"
	ecPredicateType = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/incident-evidence-cell"
	ecStateTerm     = "https://w3id.org/agent-evidence/vocab/v1/evidence_state"
	ecDisclaimer    = "The signature shows who coded this cell, not that the cell is true."
)

var (
	ecResponses = []string{"monitoring_increase", "notification", "restriction", "isolation",
		"pause", "remediation", "restoration"}
	ecLabels    = []string{"supported", "unsupported", "unknown"}
	ecStatement = []string{"_type", "predicate", "predicateType", "subject"}
	ecRequired  = []string{"cell", "doesNotAssert", "issuedAt", "producer", "registryDigest",
		"response", "state", "supportLabel"}
	ecHex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ecHTTPS = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[\x21-\x7e]*)?$`)
	ecUTC   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
)

func (evidenceCell) Suite() string { return "incident-evidence-cell/v1" }

type ecRetained struct {
	Column       string `json:"column"`
	Empty        bool   `json:"empty"`
	Subjects     int    `json:"subjects"`
	SupportLabel string `json:"supportLabel"`
}

type ecVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained ecRetained        `json:"retained"`
}

func (evidenceCell) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ecVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ecJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ecJudgeMember(caseDir string, v ecVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	record, err := esReadObject(caseDir, "record.json")
	if err != nil {
		return append(findings, err.Error())
	}
	if kept := ecRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := ecDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func ecPredicate(record map[string]any) map[string]any {
	predicate, _ := record["predicate"].(map[string]any)
	return predicate
}

func ecRetain(record map[string]any) ecRetained {
	predicate := ecPredicate(record)
	cell, _ := predicate["cell"].(map[string]any)
	column, _ := cell["column"].(string)
	label, _ := predicate["supportLabel"].(string)
	subjects, _ := record["subject"].([]any)
	_, empty := predicate["notAddressed"]
	return ecRetained{Column: column, Empty: empty, Subjects: len(subjects), SupportLabel: label}
}

func ecText(value any) bool {
	text, ok := value.(string)
	return ok && text != ""
}

func ecMatch(pattern *regexp.Regexp, value any) bool {
	text, ok := value.(string)
	return ok && pattern.MatchString(text)
}

// ecObject reports whether value is an object with exactly the named members.
func ecObject(value any, keys ...string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, present := object[key]; !present {
			return nil, false
		}
	}
	return object, true
}

func ecDigest(value any) bool {
	digest, ok := ecObject(value, "sha256")
	return ok && ecMatch(ecHex, digest["sha256"])
}

func ecSubject(value any) bool {
	subject, ok := ecObject(value, "digest", "name")
	return ok && ecText(subject["name"]) && ecDigest(subject["digest"])
}

func ecStatementMalformed(record map[string]any) bool {
	if _, ok := ecObject(record, ecStatement...); !ok {
		return true
	}
	subjects, ok := record["subject"].([]any)
	if !ok || len(subjects) == 0 {
		return true
	}
	for _, subject := range subjects {
		if !ecSubject(subject) {
			return true
		}
	}
	_, isObject := record["predicate"].(map[string]any)
	return record["_type"] != ecStatementType || record["predicateType"] != ecPredicateType || !isObject
}

func ecContentMalformed(predicate map[string]any) bool {
	value, hasValue := predicate["value"]
	empty, hasEmpty := predicate["notAddressed"]
	switch {
	case hasValue && !hasEmpty:
		return !ecText(value)
	case hasEmpty && !hasValue:
		reason, ok := ecObject(empty, "reason")
		return !ok || !ecText(reason["reason"])
	}
	return true
}

func ecUTCTime(value any) bool {
	if !ecMatch(ecUTC, value) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value.(string))
	return err == nil
}

func ecSentences(value any) bool {
	sentences, ok := value.([]any)
	if !ok || len(sentences) == 0 {
		return false
	}
	for _, sentence := range sentences {
		if !ecText(sentence) {
			return false
		}
	}
	return true
}

func ecPredicateMalformed(record map[string]any) bool {
	predicate := ecPredicate(record)
	members := make(map[string]any, len(predicate))
	for key, value := range predicate {
		if key != "value" && key != "notAddressed" {
			members[key] = value
		}
	}
	if _, ok := ecObject(members, ecRequired...); !ok || ecContentMalformed(predicate) {
		return true
	}
	cell, ok := ecObject(predicate["cell"], "column", "row", "table")
	if !ok || !ecText(cell["column"]) || !ecText(cell["row"]) || !ecText(cell["table"]) {
		return true
	}
	producer, ok := ecObject(predicate["producer"], "id")
	return !ok || !ecMatch(ecHTTPS, producer["id"]) ||
		!ecText(predicate["response"]) || !ecText(predicate["state"]) || !ecText(predicate["supportLabel"]) ||
		!ecUTCTime(predicate["issuedAt"]) || !ecDigest(predicate["registryDigest"]) ||
		!ecSentences(predicate["doesNotAssert"])
}

func ecInSet(value any, set []string) bool {
	text, ok := value.(string)
	return ok && slices.Contains(set, text)
}

func ecStates() []string {
	states := make([]string, 0, 9)
	for n := range 9 {
		states = append(states, fmt.Sprintf("%s#ES%d", ecStateTerm, n))
	}
	return states
}

func ecOutsideVocabulary(record map[string]any) bool {
	predicate := ecPredicate(record)
	return !ecInSet(predicate["state"], ecStates()) || !ecInSet(predicate["response"], ecResponses) ||
		!ecInSet(predicate["supportLabel"], ecLabels)
}

func ecEmptyCellLabelled(record map[string]any) bool {
	predicate := ecPredicate(record)
	_, empty := predicate["notAddressed"]
	return empty && predicate["supportLabel"] != "unknown"
}

func ecDisclaimerMissing(record map[string]any) bool {
	sentences, ok := ecPredicate(record)["doesNotAssert"].([]any)
	return !ok || !slices.Contains(sentences, any(ecDisclaimer))
}

// ecDecide names the first check the record fails, in the Python reader's order.
func ecDecide(record map[string]any) scDecision {
	checks := []struct {
		reason string
		fails  func(map[string]any) bool
	}{
		{"statement_malformed", ecStatementMalformed},
		{"predicate_malformed", ecPredicateMalformed},
		{"closed_vocabulary_violation", ecOutsideVocabulary},
		{"empty_cell_labelled", ecEmptyCellLabelled},
		{"truth_disclaimer_missing", ecDisclaimerMissing},
	}
	for _, check := range checks {
		if check.fails(record) {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "cell_recorded"}
}
