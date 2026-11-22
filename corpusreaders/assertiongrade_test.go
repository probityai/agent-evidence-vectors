package corpusreaders_test

// The assertion-grade reader derives every grade from the bundle against the
// trust it pins. The committed corpus reaches each rule once; the cases below
// put one member's case into another member's slot, so the derived answer
// moves, and require the reader to report the move. A reader that echoed the
// declared answer passes the committed corpus and fails every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const asgDir = "vectors-assertion-grade"

type asgRow struct {
	ID        string `json:"id"`
	PairsWith string `json:"pairsWith"`
	Expected  struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"expected"`
}

func asgRows(t *testing.T) []asgRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(asgDir), "MANIFEST.json")) // #nosec G304 -- the repository's own corpus
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []asgRow `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Vectors) == 0 {
		t.Fatal("no members, so this test asserted nothing")
	}
	return manifest.Vectors
}

func asgStageWithCase(t *testing.T, member, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), asgDir)
	copyTree(t, corpusPath(asgDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, "case.json")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "case.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestAssertionGradeCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(asgDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) != len(asgRows(t)) {
		t.Fatalf("judged %d members, the manifest lists %d", len(result.Members), len(asgRows(t)))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

// Every refusal moves: an attack's case in its accepted twin's slot is derived
// rejected for the attack's own reason, and the twin's case in the attack's
// slot is derived accepted.
func TestAssertionGradeEveryRefusalMovesTheVerdict(t *testing.T) {
	for _, row := range asgRows(t) {
		if row.Expected.Decision != "rejected" {
			continue
		}
		t.Run(row.ID+" in the slot of "+row.PairsWith, func(t *testing.T) {
			got := scDerived(t, asgStageWithCase(t, row.PairsWith, row.ID), row.PairsWith)
			want := "derived rejected/" + row.Expected.Reason
			if !strings.Contains(got, want) {
				t.Fatalf("want a finding containing %q, got %q", want, got)
			}
		})
		t.Run(row.PairsWith+" in the slot of "+row.ID, func(t *testing.T) {
			got := scDerived(t, asgStageWithCase(t, row.ID, row.PairsWith), row.ID)
			if !strings.Contains(got, "derived accepted/grades_derived") {
				t.Fatalf("want the twin derived accepted, got %q", got)
			}
		})
	}
}
