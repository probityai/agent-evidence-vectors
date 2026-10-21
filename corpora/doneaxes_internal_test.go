package corpora

// The Go done reader's axis rules are held to the Python reader's answers.
// testdata/done-axes.json.gz holds every combination of a few verdicts per check and what
// the Python reader derives from each: the two axes without their check lists, accepted
// and the receipt's decision (written by vectors-done-receipt/tests/test_done_axis_cases.py,
// which also checks it). This test combines the same verdicts and requires the same answers.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func doneWithoutChecks(axis map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range axis {
		if key != "checks" {
			out[key] = value
		}
	}
	return out
}

func doneAxisVerdict(claimType string, option map[string]any, excused map[string]string) doneVerdict {
	out := doneVerdict{"claim_type": claimType}
	for key, value := range option {
		out[key] = value
	}
	if out["reason"] == "excused" {
		if reason, ok := excused[claimType]; ok {
			out["reason"] = reason
		}
	}
	return out
}

func TestDoneAxesAgreeWithPython(t *testing.T) {
	packed, err := os.ReadFile("testdata/done-axes.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Head struct {
			Outcome   []map[string]any  `json:"outcome_options"`
			Integrity []map[string]any  `json:"integrity_options"`
			Types     []string          `json:"integrity_types"`
			Excused   map[string]string `json:"excused"`
		} `json:"head"`
		Cases []struct {
			Pick []int          `json:"pick"`
			Want map[string]any `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 1000 || !doneEqual(normalize(fixture.Head.Types), normalize(doneIntegrityTypes)) {
		t.Fatalf("done-axes.json.gz holds %d cases over %v", len(fixture.Cases), fixture.Head.Types)
	}
	disagreed := 0
	for index, item := range fixture.Cases {
		verdicts := map[string]doneVerdict{
			doneAcceptanceType: doneAxisVerdict(doneAcceptanceType, fixture.Head.Outcome[item.Pick[0]], fixture.Head.Excused),
		}
		for position, claimType := range doneIntegrityTypes {
			verdicts[claimType] = doneAxisVerdict(claimType, fixture.Head.Integrity[item.Pick[position+1]], fixture.Head.Excused)
		}
		axes := doneAxes(verdicts)
		outcome, integrity := doneObj(axes["outcome"]), doneObj(axes["integrity"])
		decision, reason, extra := doneReceiptDecision(outcome, integrity)
		got := map[string]any{"outcome": doneWithoutChecks(outcome), "integrity": doneWithoutChecks(integrity),
			"accepted": axes["accepted"], "receipt": []any{decision, reason, doneWithoutChecks(extra)}}
		if !doneEqual(normalize(got), normalize(item.Want)) {
			gotText, _ := json.Marshal(got)
			wantText, _ := json.Marshal(item.Want)
			t.Errorf("case %d %v:\n Go     %s\n Python %s", index, item.Pick, gotText, wantText)
			if disagreed++; disagreed == doneMemberDisagreements {
				t.Fatalf("stopping after %d disagreements", disagreed)
			}
		}
	}
}
