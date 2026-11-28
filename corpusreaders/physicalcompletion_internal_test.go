package corpusreaders

// The Go physical-completion reader is held to the table the Python corpus
// tests also read: criterionMet true, false, absent and null, each against the
// result a verifier reported. Missing and null are unknown, never false (issue 554).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type pcCriterionCase struct {
	CriterionMet string  `json:"criterionMet"`
	Controller   *string `json:"controller"`
	Reported     string  `json:"reported"`
	Decision     string  `json:"decision"`
	Reason       string  `json:"reason"`
	Owed         string  `json:"owed"`
}

func pcCriterionVariant(t *testing.T, base []byte, c pcCriterionCase) pcRecord {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(base, &doc); err != nil {
		t.Fatal(err)
	}
	presented, _ := doc["presented"].(map[string]any)
	observation, _ := presented["observation"].(map[string]any)
	result, _ := doc["result"].(map[string]any)
	if observation == nil || result == nil {
		t.Fatal("the base record has no observation or no result")
	}
	switch c.CriterionMet {
	case "absent":
		delete(observation, "criterionMet")
	case "null":
		observation["criterionMet"] = nil
	default:
		observation["criterionMet"] = c.CriterionMet == "true"
	}
	if c.Controller != nil {
		presented["controllerOutcome"] = map[string]any{"authenticated": true, "status": *c.Controller}
	}
	result["physicalCompletion"] = c.Reported
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var record pcRecord
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPhysicalCompletionCriterionStatesMatchThePythonTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "physical-completion-criterion.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Base  string            `json:"base"`
		Cases []pcCriterionCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("the table has no cases")
	}
	base, err := os.ReadFile(filepath.Join("..", "corpora", "vectors-physical-completion", "cases", table.Base, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range table.Cases {
		record := pcCriterionVariant(t, base, c)
		if got, want := pcDecide(record), (scDecision{c.Decision, c.Reason}); got != want {
			t.Errorf("criterionMet %s, controller %v, reported %s: got %v, want %v",
				c.CriterionMet, c.Controller, c.Reported, got, want)
		}
		if got := pcRetain(record).Owed; got != c.Owed {
			t.Errorf("criterionMet %s, controller %v, reported %s: owed %q, want %q",
				c.CriterionMet, c.Controller, c.Reported, got, c.Owed)
		}
	}
}
