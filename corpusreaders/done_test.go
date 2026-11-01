package corpora_test

// The done readers derive every member's verdict from its records. Swapping a
// record for another run's, or breaking one rule in it, must move the derived
// verdict, and the reader must say so.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

var doneCorpora = []string{
	"vectors-done-contract", "vectors-done-receipt", "vectors-spoofed-tool-output",
	"vectors-test-tampering", "vectors-grader-isolation", "vectors-done-probes",
}

func doneStage(t *testing.T, dir, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dir)
	copyTree(t, corpusPath(dir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func doneRead(t *testing.T, dir, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(dir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDoneCorporaAreClean(t *testing.T) {
	for _, dir := range doneCorpora {
		t.Run(dir, func(t *testing.T) {
			result, err := corpora.Judge(corpusPath(dir))
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			if !result.OK() || len(result.Members) == 0 {
				t.Fatalf("findings: %v %v", result.Findings, result.Members)
			}
			if len(result.CountsByVerdict()) < 2 {
				t.Fatalf("a corpus of one verdict forces nothing: %v", result.CountsByVerdict())
			}
		})
	}
}

func TestDoneRecordsMoveTheDerivedVerdict(t *testing.T) {
	const dir = "vectors-done-receipt"
	t.Run("an honest run given the adversary's observation", func(t *testing.T) {
		staged := doneStage(t, dir, "honest", "observation.json", doneRead(t, dir, "planted-adversary", "observation.json"))
		if got := scDerived(t, staged, "honest"); !strings.Contains(got, "derived") {
			t.Fatalf("want a derived finding, got %q", got)
		}
	})
	t.Run("an adversary run given the honest grade", func(t *testing.T) {
		staged := doneStage(t, dir, "planted-adversary", "grade.json", doneRead(t, dir, "honest", "grade.json"))
		if got := scDerived(t, staged, "planted-adversary"); !strings.Contains(got, "derived") {
			t.Fatalf("want a derived finding, got %q", got)
		}
	})
	t.Run("a record changed after the consumer pinned it is named", func(t *testing.T) {
		staged := doneStage(t, dir, "honest", "tree.json", []byte("{"))
		if got := scDerived(t, staged, "honest"); !strings.Contains(got, "case_artifact_binding_mismatch") {
			t.Fatalf("want a binding finding, got %q", got)
		}
	})
	t.Run("a forged receipt is caught by rederiving its verdicts", func(t *testing.T) {
		verdict, err := corpora.DoneCheck("done_receipt/v2", filepath.Join(corpusPath(dir), "cases", "forged-receipt"))
		if err != nil {
			t.Fatal(err)
		}
		if verdict["reason"] != "receipt_outcome_mismatch" || verdict["receipt_valid"] != false {
			t.Fatalf("want receipt_outcome_mismatch with receipt_valid false, got %v", verdict)
		}
	})
}

func TestDoneContractRulesAreForced(t *testing.T) {
	const dir = "vectors-done-contract"
	staged := doneStage(t, dir, "acceptance-empty", "contract.json", doneRead(t, dir, "valid-directory-protected", "contract.json"))
	if got := scDerived(t, staged, "acceptance-empty"); !strings.Contains(got, "statement_subject_unbound") &&
		!strings.Contains(got, "statement_predicate_differs") {
		t.Fatalf("a valid contract under an invalid member's statement must be judged on the statement: %q", got)
	}
}

func TestDoneDamagedManifestIsAFinding(t *testing.T) {
	for _, dir := range doneCorpora {
		t.Run(dir, func(t *testing.T) {
			copied := filepath.Join(t.TempDir(), dir)
			copyTree(t, corpusPath(dir), copied)
			path := filepath.Join(copied, corpora.ManifestName)
			raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
			if err != nil {
				t.Fatal(err)
			}
			damaged := strings.Replace(string(raw), `"kind"`, `"kinds"`, 1)
			if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := corpora.Judge(copied)
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			if len(result.Findings) == 0 {
				t.Fatal("want a corpusDigest finding")
			}
		})
	}
}
