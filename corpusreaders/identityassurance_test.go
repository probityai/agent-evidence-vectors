package corpusreaders_test

// The identity-assurance-levels reader grades every set from the record alone and agrees
// with the Python reader on every member (the manifest's declared answer is the Python
// reader's). Dropping a level's finding from the top-grade set must lower the grade.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const iaDir = "vectors-identity-assurance"

func TestIdentityAssuranceAgreesWithThePythonReaderOnEveryMember(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(iaDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	counts := result.CountsByVerdict()
	if !result.OK() || len(result.Members) != 44 || counts["accept"] != 27 {
		t.Fatalf("findings: %v %v %v", result.Findings, result.Members, counts)
	}
}

func TestIdentityAssuranceEverySetMovesTheTopGrade(t *testing.T) {
	control := "level-6-out-of-reach-record"
	entries, err := os.ReadDir(filepath.Join(corpusPath(iaDir), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		from := entry.Name()
		if from == control || from == "one-evidence-for-every-level" || from == "order-does-not-matter" ||
			strings.HasPrefix(from, "level-6") {
			continue
		}
		t.Run(from, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(corpusPath(iaDir), "cases", from, "record.json")) // #nosec G304 -- a test reading its own corpus
			if err != nil {
				t.Fatal(err)
			}
			copied := filepath.Join(t.TempDir(), iaDir)
			copyTree(t, corpusPath(iaDir), copied)
			if err := os.WriteFile(filepath.Join(copied, "cases", control, "record.json"), body, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := scDerived(t, copied, control); !strings.Contains(got, "derived ") {
				t.Fatalf("want a derived finding, got %q", got)
			}
		})
	}
}
