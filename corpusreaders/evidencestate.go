package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

func init() { register(evidenceState{}) }

// evidenceState judges corpora/vectors-evidence-state/. Each member is one
// record: a system, the evidence_state code its producer declares and the
// observations that ground it. The reader derives the code from the
// observations (the highest code whose entry condition they meet) and applies
// the Python reader's checks in the same order, naming the first that fails:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. record_malformed: exactly the record's members, each of its type, with
//     non-negative counts and a threshold of at least one where one is declared;
//  4. evidence_state_unregistered: the declared code is one of ES0 to ES8;
//  5. observations_inconsistent: a pathway only for an observed propagation, a
//     propagation only beside a recorded anomaly, a verified containment only
//     where one is recorded;
//  6. clean_without_coverage: a declared ES1 rests on measured coverage;
//  7. evidence_state_unsupported: the declared code is no higher than derived;
//  8. evidence_state_understated: the declared code is no lower than derived.
type evidenceState struct{}

const esContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evidence-state"

var (
	esStates = []string{"ES0", "ES1", "ES2", "ES3", "ES4", "ES5", "ES6", "ES7", "ES8"}
	esTop    = []string{"assessedAt", "contractId", "evidenceState", "observations", "recordId", "system"}
	esFlags  = []string{"containmentRecorded", "containmentVerified", "coverageMeasured",
		"externalEffectsConfirmed", "pathwayIdentified", "propagationObserved",
		"restartRequested", "scopeBounded"}
)

func (evidenceState) Suite() string { return "evidence-state/v1" }

type esRetained struct {
	Declared string `json:"declared"`
	Derived  string `json:"derived"`
	System   string `json:"system"`
}

type esVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained esRetained        `json:"retained"`
}

func (evidenceState) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v esVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = esJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// esReadObject reads one case file as a JSON object whose numbers stay exact.
func esReadObject(caseDir, name string) (map[string]any, error) {
	body, err := readIn(caseDir, name)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", name, err)
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", name, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", name)
	}
	return object, nil
}

func esJudgeMember(caseDir string, v esVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	record, err := esReadObject(caseDir, "record.json")
	if err != nil {
		return append(findings, err.Error())
	}
	if kept := esRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := esDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func esRetain(record map[string]any) esRetained {
	declared, _ := record["evidenceState"].(string)
	system, _ := record["system"].(string)
	return esRetained{Declared: declared, Derived: esDerive(esObservations(record)), System: system}
}

func esObservations(record map[string]any) map[string]any {
	seen, _ := record["observations"].(map[string]any)
	return seen
}

// esCount reads a JSON integer the way Python's json module does: a number with
// no fraction and no exponent. A float, a bool or a string is not a count.
func esCount(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE") {
		return 0, false
	}
	n, err := number.Int64()
	return n, err == nil
}

func esIsCount(value any) bool {
	n, ok := esCount(value)
	return ok && n >= 0
}

func esFlag(seen map[string]any, name string) bool {
	set, _ := seen[name].(bool)
	return set
}

// esDerive is the highest code whose entry condition the observations meet.
func esDerive(seen map[string]any) string {
	anomalies, _ := esCount(seen["anomaliesRecorded"])
	threshold, declared := esCount(seen["changeThreshold"])
	conditions := []struct {
		code  string
		holds bool
	}{
		{"ES8", esFlag(seen, "containmentRecorded") && esFlag(seen, "restartRequested")},
		{"ES7", esFlag(seen, "externalEffectsConfirmed")},
		{"ES6", esFlag(seen, "scopeBounded") && esFlag(seen, "containmentVerified")},
		{"ES5", esFlag(seen, "pathwayIdentified")},
		{"ES4", esFlag(seen, "propagationObserved")},
		{"ES3", declared && anomalies >= threshold},
		{"ES2", anomalies >= 1},
		{"ES1", esFlag(seen, "coverageMeasured")},
	}
	for _, condition := range conditions {
		if condition.holds {
			return condition.code
		}
	}
	return "ES0"
}

func esSameKeys(object map[string]any, want []string) bool {
	return len(object) == len(want) && reflect.DeepEqual(sortedKeys(object), want)
}

func esMalformed(record map[string]any) bool {
	if !esSameKeys(record, esTop) {
		return true
	}
	for _, key := range []string{"assessedAt", "evidenceState", "recordId", "system"} {
		if text, ok := record[key].(string); !ok || text == "" {
			return true
		}
	}
	seen, ok := record["observations"].(map[string]any)
	if !ok || !esSameKeys(seen, append([]string{"anomaliesRecorded", "changeThreshold"}, esFlags...)) {
		return true
	}
	threshold, counted := esCount(seen["changeThreshold"])
	if !esIsCount(seen["anomaliesRecorded"]) || (seen["changeThreshold"] != nil && (!counted || threshold < 1)) {
		return true
	}
	for _, flag := range esFlags {
		if _, ok := seen[flag].(bool); !ok {
			return true
		}
	}
	return false
}

func esInconsistent(seen map[string]any) bool {
	anomalies, _ := esCount(seen["anomaliesRecorded"])
	return (esFlag(seen, "pathwayIdentified") && !esFlag(seen, "propagationObserved")) ||
		(esFlag(seen, "propagationObserved") && anomalies == 0) ||
		(esFlag(seen, "containmentVerified") && !esFlag(seen, "containmentRecorded"))
}

// esDecide names the first check the record fails, in the Python reader's
// order, with each later check evaluated only once every earlier one passed.
func esDecide(record map[string]any) scDecision {
	contract, present := record["contractId"]
	if _, isText := contract.(string); present && !isText {
		return scDecision{"deny", "record_malformed"}
	}
	declared, _ := record["evidenceState"].(string)
	derived := esDerive(esObservations(record))
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"contract_id_missing", func() bool { return !present }},
		{"contract_id_unknown", func() bool { return contract != esContractID }},
		{"record_malformed", func() bool { return esMalformed(record) }},
		{"evidence_state_unregistered", func() bool { return !slices.Contains(esStates, declared) }},
		{"observations_inconsistent", func() bool { return esInconsistent(esObservations(record)) }},
		{"clean_without_coverage", func() bool { return declared == "ES1" && derived == "ES0" }},
		{"evidence_state_unsupported", func() bool {
			return slices.Index(esStates, declared) > slices.Index(esStates, derived)
		}},
		{"evidence_state_understated", func() bool {
			return slices.Index(esStates, declared) < slices.Index(esStates, derived)
		}},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "state_supported"}
}
