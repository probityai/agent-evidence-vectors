package corpusreaders_test

// The refusal-reason-priority reader derives every decision from the record
// alone. Swapping a control's record for another member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const rrDir = "vectors-refusal-reason-priority"

func rrStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), rrDir)
	copyTree(t, corpusPath(rrDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func rrRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(rrDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRefusalReasonCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(rrDir))
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

func TestRefusalReasonEachCheckMovesTheVerdict(t *testing.T) {
	control := "conformant-null-is-the-only-permit"
	refused := []string{"nonconformant-contract-id-missing", "nonconformant-contract-id-unknown",
		"nonconformant-reason-member-absent", "nonconformant-granted-value",
		"nonconformant-undeclared-answer-outside-both-readings",
		"nonconformant-refusal-without-condition", "nonconformant-permit-over-diagnostic-read",
		"nonconformant-revocation-over-expiry", "nonconformant-diagnostic-backfills-observation",
		"nonconformant-diagnostic-renews-expiry"}
	for _, from := range refused {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := rrStage(t, control, rrRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived nonconformant/") {
				t.Fatalf("want a derived nonconformant, got %q", got)
			}
		})
	}
	for _, from := range []string{"open-boundary-undeclared", "open-inclusive-declared-expired-at-instant"} {
		dir := rrStage(t, control, rrRead(t, from))
		if got := scDerived(t, dir, control); !strings.Contains(got, "derived ambiguous/") {
			t.Fatalf("%s: want a derived ambiguous, got %q", from, got)
		}
	}
	dir := rrStage(t, "nonconformant-granted-value", rrRead(t, control))
	if got := scDerived(t, dir, "nonconformant-granted-value"); !strings.Contains(got, "derived conformant/response_follows_source") {
		t.Fatalf("want a derived conformant, got %q", got)
	}
}

func TestRefusalReasonUnreadableInputsAreFindings(t *testing.T) {
	dir := rrStage(t, "conformant-null-is-the-only-permit", "{")
	if got := scDerived(t, dir, "conformant-null-is-the-only-permit"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}
