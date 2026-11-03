package corpusreaders_test

// The propagation-step reader derives every decision from the record alone.
// Swapping the control's record for a denied member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const psDir = "vectors-propagation-step"

func psStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), psDir)
	copyTree(t, corpusPath(psDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func psRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(psDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestPropagationStepCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(psDir))
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

func TestPropagationStepEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"reject-contract-id-missing", "reject-contract-id-unknown",
		"reject-hop-to-itself", "reject-chain-digest-mismatch", "reject-chain-gap",
		"reject-edge-after-effect", "reject-common-cause-attributed-as-propagation"}
	for _, from := range denied {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := psStage(t, "allow-propagation-by-digest-chain", psRead(t, from))
			if got := scDerived(t, dir, "allow-propagation-by-digest-chain"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	dir := psStage(t, "reject-chain-gap", psRead(t, "allow-propagation-by-digest-chain"))
	if got := scDerived(t, dir, "reject-chain-gap"); !strings.Contains(got, "derived allow/attribution_supported") {
		t.Fatalf("want a derived allow, got %q", got)
	}
}

func TestPropagationStepUnreadableInputsAreFindings(t *testing.T) {
	dir := psStage(t, "allow-propagation-by-digest-chain", "{")
	if got := scDerived(t, dir, "allow-propagation-by-digest-chain"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	later := strings.Replace(psRead(t, "allow-propagation-by-digest-chain"), "2026-11-02T09:01:00Z", "today", 1)
	dir = psStage(t, "allow-propagation-by-digest-chain", later)
	if got := scDerived(t, dir, "allow-propagation-by-digest-chain"); !strings.Contains(got, "not RFC 3339") {
		t.Fatalf("want a timestamp finding, got %q", got)
	}
}
