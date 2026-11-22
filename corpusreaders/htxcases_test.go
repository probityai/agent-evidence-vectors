package corpusreaders_test

// The HTX case reader derives every decision from the record alone. Swapping a
// control's record for a reject's must move the decision, and back.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const htxDir = "vectors-htx-cases"

func htxStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), htxDir)
	copyTree(t, corpusPath(htxDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func htxRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(htxDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestHTXCasesCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(htxDir))
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

func TestHTXCasesEachRejectMovesTheVerdict(t *testing.T) {
	pairs := map[string][]string{
		"allow-request-matches-confirmation": {"reject-beneficiary-changed", "reject-amount-changed",
			"reject-currency-changed", "reject-scope-changed", "reject-confirmation-declined"},
		"allow-disclosure-within-consent": {"reject-field-beyond-consent", "reject-refused-field-disclosed",
			"reject-purpose-changed", "reject-recipient-changed", "reject-consent-declined-with-disclosure"},
	}
	for control, rejects := range pairs {
		for _, from := range rejects {
			t.Run("the control with the record of "+from, func(t *testing.T) {
				dir := htxStage(t, control, htxRead(t, from))
				if got := scDerived(t, dir, control); !strings.Contains(got, "derived deny/") {
					t.Fatalf("want a derived deny, got %q", got)
				}
			})
		}
		dir := htxStage(t, rejects[0], htxRead(t, control))
		if got := scDerived(t, dir, rejects[0]); !strings.Contains(got, "derived allow/") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	}
}

func TestHTXCasesUnreadableInputsAreFindings(t *testing.T) {
	dir := htxStage(t, "allow-request-matches-confirmation", "{")
	if got := scDerived(t, dir, "allow-request-matches-confirmation"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	dir = htxStage(t, "allow-request-matches-confirmation", "{}")
	if got := scDerived(t, dir, "allow-request-matches-confirmation"); !strings.Contains(got, "derived deny/record-shape-unknown") {
		t.Fatalf("want a shape refusal, got %q", got)
	}
}
