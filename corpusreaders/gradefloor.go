package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
)

func init() { register(gradeFloor{}) }

// gradeFloor judges vectors-grade-floor/. Each member is one record for the
// E0-E4 evidence ladder in AAIF Observability WG issue #37
// (https://github.com/aaif/wg-observability-and-traceability/issues/37). The
// reader derives the grade from the record's observations, enforcement,
// reconciliation and integrity marker objects, never from the grade or the
// integrity booleans the producer declares, then applies the claim floor. The
// rules, their order and the refusal codes are the ones the Python reader
// (packaging/agent_evidence_vectors/gradefloor.py) applies:
//
//  1. E1 needs a framework or gateway observation not scoped SELF:
//     e1_no_external_observer;
//  2. E2 needs policy enforced at the boundary and a denial recorded by a
//     substrate, intercepted observer: e2_no_recorded_denial;
//  3. E3 needs two distinct independent engines, neither a self report nor
//     SELF scoped: e3_insufficient_independent_engines;
//  4. E4 needs an external timestamp, a chain link and an independent
//     verification marker: e4_missing_external_timestamp,
//     e4_missing_chain_link, e4_missing_independent_verification.
//
// An operationally-conformant claim is refused under contradiction
// (claim_floor_contradiction) and below E3 (claim_floor_below_e3).
type gradeFloor struct{}

func (gradeFloor) Suite() string { return "evidence-grade-floor/v1" }

type gfExpected struct {
	Decision     string `json:"decision"`
	DerivedGrade string `json:"derivedGrade"`
	Reason       string `json:"reason"`
}

type gfVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected gfExpected        `json:"expected"`
	Twin     string            `json:"twin"`
}

type gfObservation struct {
	Engine       string `json:"engine"`
	Source       string `json:"source"`
	Relationship string `json:"relationship"`
	Vantage      string `json:"observation_vantage"`
	Directness   string `json:"observation_directness"`
	WitnessScope string `json:"witness_scope"`
}

type gfRecord struct {
	DeclaredGrade string          `json:"declared_grade"`
	Claim         string          `json:"claim"`
	Observations  []gfObservation `json:"observations"`
	Enforcement   struct {
		AtBoundary *bool             `json:"policy_enforced_at_boundary"`
		Denials    []json.RawMessage `json:"denials"`
	} `json:"enforcement"`
	Reconciliation string                     `json:"reconciliation"`
	Markers        map[string]json.RawMessage `json:"integrity_markers"`
}

var gfGrades = []string{"E0", "E1", "E2", "E3", "E4"}

var gfHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (gradeFloor) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepted := map[string]bool{}
	var vectors []gfVector
	for _, entry := range manifest.Vectors {
		var v gfVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		accepted[v.ID] = v.Expected.Decision == "accepted"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = gfJudgeMember(filepath.Join(dir, v.Path), v)
		if v.Expected.Decision == "rejected" && !accepted[v.Twin] {
			member.Findings = append(member.Findings, "a rejected member must name an accepted twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func gfJudgeMember(caseDir string, v gfVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var rec gfRecord
	if err := scReadJSON(caseDir, "case.json", &rec); err != nil {
		return append(findings, err.Error())
	}
	if got := gfDecide(rec); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s/%s, the manifest declares %s/%s/%s",
			got.Decision, got.DerivedGrade, got.Reason,
			v.Expected.Decision, v.Expected.DerivedGrade, v.Expected.Reason))
	}
	return findings
}

func gfDecide(r gfRecord) gfExpected {
	grade, blocked := gfDerive(r)
	declared := 0
	for i, g := range gfGrades {
		if g == r.DeclaredGrade {
			declared = i
		}
	}
	out := gfExpected{DerivedGrade: gfGrades[grade], Decision: "rejected"}
	conformant := r.Claim == "operationally-conformant"
	switch {
	case conformant && r.Reconciliation == "contradiction":
		out.Reason = "claim_floor_contradiction"
	case grade < declared:
		out.Reason = blocked
	case conformant && grade < 3:
		out.Reason = "claim_floor_below_e3"
	default:
		out.Decision, out.Reason = "accepted", "grade_derived"
	}
	return out
}

func gfDerive(r gfRecord) (int, string) {
	steps := []struct {
		rung int
		code string
		ok   bool
	}{
		{1, "e1_no_external_observer", gfExternalObserver(r)},
		{2, "e2_no_recorded_denial", gfRecordedDenial(r)},
		{3, "e3_insufficient_independent_engines", gfIndependentEngines(r) >= 2},
		{4, "e4_missing_external_timestamp", gfMarker(r, "external_timestamp")},
		{4, "e4_missing_chain_link", gfMarker(r, "chain_link")},
		{4, "e4_missing_independent_verification", gfMarker(r, "independent_verification")},
	}
	for _, s := range steps {
		if !s.ok {
			return s.rung - 1, s.code
		}
	}
	return len(gfGrades) - 1, ""
}

func gfExternalObserver(r gfRecord) bool {
	for _, o := range r.Observations {
		if (o.Source == "framework" || o.Source == "gateway") && o.WitnessScope != "SELF" {
			return true
		}
	}
	return false
}

func gfRecordedDenial(r gfRecord) bool {
	if r.Enforcement.AtBoundary == nil || !*r.Enforcement.AtBoundary {
		return false
	}
	engines := map[string]bool{}
	for _, o := range r.Observations {
		if o.Vantage == "substrate" && o.Directness == "intercepted" && o.WitnessScope != "SELF" {
			engines[o.Engine] = true
		}
	}
	for _, raw := range r.Enforcement.Denials {
		var d struct {
			RecordedBy string `json:"recorded_by"`
		}
		if json.Unmarshal(raw, &d) == nil && engines[d.RecordedBy] {
			return true
		}
	}
	return false
}

func gfIndependentEngines(r gfRecord) int {
	engines := map[string]bool{}
	for _, o := range r.Observations {
		if o.Relationship == "independent" && o.Source != "self_report" && o.WitnessScope != "SELF" {
			engines[o.Engine] = true
		}
	}
	return len(engines)
}

func gfMarker(r gfRecord, name string) bool {
	raw, present := r.Markers[name]
	if !present {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return false
	}
	str := func(key string) string { s, _ := m[key].(string); return s }
	switch name {
	case "external_timestamp":
		return str("witness_scope") == "EXTERNAL" && gfHex64.MatchString(str("token_sha256"))
	case "chain_link":
		return gfHex64.MatchString(str("prev_sha256"))
	default:
		return str("witness_scope") == "EXTERNAL" && str("result") == "verified"
	}
}
