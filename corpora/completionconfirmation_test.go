package corpora_test

// The completion-confirmation reader derives every decision from the record. Swapping
// one member's record into another must move the derived decision, and the
// reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const ccDir = "vectors-completion-confirmation"

func ccStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ccDir)
	copyTree(t, corpusPath(ccDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ccRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ccDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCompletionConfirmationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(ccDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestCompletionConfirmationEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "malformed-confirmation-field-missing",
		"completion-claimed-without-confirmation", "confirmation-for-another-task",
		"confirmation-written-by-the-acting-agent", "confirmation-already-consumed",
		"confirmation-after-decision", "outcome-unresolved-claimed-complete", "outcome-absent-claimed-complete"}
	for _, from := range denied {
		t.Run("allow-confirmed with the record of "+from, func(t *testing.T) {
			dir := ccStage(t, "allow-confirmed", ccRead(t, from))
			if got := scDerived(t, dir, "allow-confirmed"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := ccStage(t, "completion-claimed-without-confirmation", ccRead(t, "allow-confirmed"))
		if got := scDerived(t, dir, "completion-claimed-without-confirmation"); !strings.Contains(got, "derived allow/confirmed") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestCompletionConfirmationUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/completion-confirmation/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := ccStage(t, "allow-confirmed", []byte(tc.body))
			if got := scDerived(t, dir, "allow-confirmed"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
