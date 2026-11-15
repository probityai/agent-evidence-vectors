package corpusreaders_test

// The physical-completion reader derives every decision from the record alone.
// Swapping a control's record for another member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const pcDir = "vectors-physical-completion"

func pcStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), pcDir)
	copyTree(t, corpusPath(pcDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func pcRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(pcDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestPhysicalCompletionCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(pcDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"conformant", "nonconformant", "ambiguous"} {
		if counts[verdict] == 0 {
			t.Fatalf("every verdict must be present: %v", counts)
		}
	}
}

func TestPhysicalCompletionEachCheckMovesTheVerdict(t *testing.T) {
	control := "conformant-witness-proven-to-policy"
	refused := []string{"nonconformant-contract-id-missing", "nonconformant-contract-id-unknown",
		"nonconformant-result-member-absent", "nonconformant-unqualified-proven",
		"nonconformant-result-outside-vocabulary", "nonconformant-conflict-as-profile-token",
		"nonconformant-receipt-executed-read-as-completion",
		"nonconformant-controller-success-read-as-completion",
		"nonconformant-lost-ack-over-met-witness", "nonconformant-absence-read-as-indeterminate"}
	for _, from := range refused {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := pcStage(t, control, pcRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived nonconformant/") {
				t.Fatalf("want a derived nonconformant, got %q", got)
			}
		})
	}
	for _, from := range []string{"open-stale-witness-proven", "open-conflict-drops-a-claim",
		"open-bare-receipt-not-claimed", "open-untrusted-witness-proven"} {
		dir := pcStage(t, control, pcRead(t, from))
		if got := scDerived(t, dir, control); !strings.Contains(got, "derived ambiguous/") {
			t.Fatalf("%s: want a derived ambiguous, got %q", from, got)
		}
	}
	dir := pcStage(t, "nonconformant-unqualified-proven", pcRead(t, control))
	if got := scDerived(t, dir, "nonconformant-unqualified-proven"); !strings.Contains(got, "derived conformant/result_follows_presentation") {
		t.Fatalf("want a derived conformant, got %q", got)
	}
}

func TestPhysicalCompletionUnreadableInputsAreFindings(t *testing.T) {
	dir := pcStage(t, "conformant-witness-proven-to-policy", "{")
	if got := scDerived(t, dir, "conformant-witness-proven-to-policy"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}
