package corpusreaders_test

// The holder-bound-credential reader derives every decision from the record alone and
// agrees with the Python reader on every member: the manifest's declared decision and
// retained fields are the Python reader's, so a clean Judge is the differential check.
// Swapping a refused member's record onto the control must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const hbDir = "vectors-holder-bound-credential"

func TestHolderBoundAgreesWithThePythonReaderOnEveryMember(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(hbDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	counts := result.CountsByVerdict()
	if !result.OK() || len(result.Members) != 35 || counts["accept"] != 5 {
		t.Fatalf("findings: %v %v %v", result.Findings, result.Members, counts)
	}
}

func TestHolderBoundEachRefusalMovesTheControl(t *testing.T) {
	control := "accept-single-presentation"
	entries, err := os.ReadDir(filepath.Join(corpusPath(hbDir), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		from := entry.Name()
		if strings.HasPrefix(from, "accept-") {
			continue
		}
		t.Run(from, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(corpusPath(hbDir), "cases", from, "record.json")) // #nosec G304 -- a test reading its own corpus
			if err != nil {
				t.Fatal(err)
			}
			copied := filepath.Join(t.TempDir(), hbDir)
			copyTree(t, corpusPath(hbDir), copied)
			if err := os.WriteFile(filepath.Join(copied, "cases", control, "record.json"), body, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := scDerived(t, copied, control); !strings.Contains(got, "derived reject/") {
				t.Fatalf("want a derived reject, got %q", got)
			}
		})
	}
}
