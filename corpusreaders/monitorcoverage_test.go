package corpusreaders_test

// The monitor-coverage reader derives every decision from the record alone.
// Swapping the control's record for a denied member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const mcDir = "vectors-monitor-coverage"

func mcStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), mcDir)
	copyTree(t, corpusPath(mcDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func mcRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(mcDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestMonitorCoverageCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(mcDir))
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

func TestMonitorCoverageEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"reject-contract-id-missing", "reject-contract-id-unknown",
		"reject-window-ends-before-start", "reject-collected-exceeds-expected",
		"reject-actions-exceed-decisions", "reject-clean-on-producer-count",
		"reject-clean-with-dropped-events", "reject-clean-with-uncollected-events",
		"reject-clean-outside-vantage", "reject-clean-contradicts-observed-effect",
		"reject-defence-effect-with-zero-effective-actions"}
	for _, from := range denied {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := mcStage(t, "allow-clean-complete-coverage", mcRead(t, from))
			if got := scDerived(t, dir, "allow-clean-complete-coverage"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	dir := mcStage(t, "reject-clean-with-dropped-events", mcRead(t, "allow-clean-complete-coverage"))
	if got := scDerived(t, dir, "reject-clean-with-dropped-events"); !strings.Contains(got, "derived allow/verdict_supported") {
		t.Fatalf("want a derived allow, got %q", got)
	}
}

func TestMonitorCoverageUnreadableInputsAreFindings(t *testing.T) {
	dir := mcStage(t, "allow-clean-complete-coverage", "{")
	if got := scDerived(t, dir, "allow-clean-complete-coverage"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	later := strings.Replace(mcRead(t, "allow-clean-complete-coverage"), "2026-11-02T09:00:00Z", "today", 1)
	dir = mcStage(t, "allow-clean-complete-coverage", later)
	if got := scDerived(t, dir, "allow-clean-complete-coverage"); !strings.Contains(got, "not RFC 3339") {
		t.Fatalf("want a timestamp finding, got %q", got)
	}
}
