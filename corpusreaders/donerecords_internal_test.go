package corpora

// The Go done reader's record rules are held to the Python reader's answers.
// testdata/done-records.json holds base records from the done corpora and thousands of
// variants of them, each with the code the Python reader refuses it under, or "ok"
// (written by vectors-done-receipt/tests/test_done_record_cases.py, which also checks it).
// This test applies each edit, parses the record with the Go reader and requires the
// same answer.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

type doneRecordCase struct {
	Kind  string `json:"kind"`
	Base  int    `json:"base"`
	Path  []any  `json:"path"`
	Op    string `json:"op"`
	Value any    `json:"value"`
	Want  string `json:"want"`
}

var doneRecordParsers = map[string]func([]byte) (doneObject, error){
	"contract": doneContract, "tree": doneTree, "observation": doneObservation,
	"capability": doneCapability, "grade": doneGrade, "claims": doneClaims,
}

func loadDoneRecordCases(t *testing.T) (map[string][]any, []doneRecordCase) {
	t.Helper()
	raw, err := os.ReadFile("testdata/done-records.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fixture struct {
		Bases map[string][]any `json:"bases"`
		Cases []doneRecordCase `json:"cases"`
	}
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 || len(fixture.Bases) != len(doneRecordParsers) {
		t.Fatalf("done-records.json: %d cases over %d kinds", len(fixture.Cases), len(fixture.Bases))
	}
	return fixture.Bases, fixture.Cases
}

// doneEdited is a deep copy of base with the case's edit applied.
func doneEdited(base any, item doneRecordCase) (any, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out any
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	if len(item.Path) == 0 {
		return item.Value, nil
	}
	parent := out
	for _, step := range item.Path[:len(item.Path)-1] {
		switch node := parent.(type) {
		case map[string]any:
			parent = node[step.(string)]
		case []any:
			index, _ := step.(json.Number).Int64()
			parent = node[index]
		}
	}
	last := item.Path[len(item.Path)-1]
	switch node := parent.(type) {
	case map[string]any:
		if item.Op == "delete" {
			delete(node, last.(string))
		} else {
			node[last.(string)] = item.Value
		}
	case []any:
		index, _ := last.(json.Number).Int64()
		node[index] = item.Value
	default:
		return nil, fmt.Errorf("path %v does not reach a container", item.Path)
	}
	return out, nil
}

func doneEncoded(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

func TestDoneRecordsAgreeWithPython(t *testing.T) {
	bases, cases := loadDoneRecordCases(t)
	answers := map[string]int{}
	for index, item := range cases {
		parse, known := doneRecordParsers[item.Kind]
		if !known || item.Base >= len(bases[item.Kind]) {
			t.Fatalf("case %d names %s base %d", index, item.Kind, item.Base)
		}
		edited, err := doneEdited(bases[item.Kind][item.Base], item)
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		data, err := doneEncoded(edited)
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		got := "ok"
		if _, err := parse(data); err != nil {
			var refused *doneError
			if !errors.As(err, &refused) {
				t.Fatalf("case %d: %s refused with no code: %v", index, item.Kind, err)
			}
			got = refused.code
		}
		answers[got]++
		if got != item.Want {
			t.Errorf("case %d: %s with %v %s %v: Go says %s, Python says %s",
				index, item.Kind, item.Path, item.Op, item.Value, got, item.Want)
		}
	}
	if answers["ok"] == 0 || len(answers) < 3 {
		t.Fatalf("the cases reach too few answers: %v", answers)
	}
}
