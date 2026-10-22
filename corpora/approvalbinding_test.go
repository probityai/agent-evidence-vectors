package corpora_test

// The approval-binding reader derives every decision from the record and the
// used bytes. Swapping one member's record or bytes into the conformant member
// must move the derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const abDir = "vectors-approval-binding"

func abStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), abDir)
	copyTree(t, corpusPath(abDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func abRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(abDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestApprovalBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(abDir))
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

func TestApprovalBindingEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "approval-id-reused-different-content",
		"approval-already-consumed", "approval-key-not-approvers", "same-client-other-user", "event-differs",
		"phase-differs", "target-differs", "tool-differs", "used-at-expiry", "used-before-issued",
		"release-lookup-unavailable", "release-first-served-after-decision", "release-retired-beyond-grace"}
	for _, from := range denied {
		t.Run("allow-bound with the record of "+from, func(t *testing.T) {
			dir := abStage(t, "allow-bound", "record.json", abRead(t, from, "record.json"))
			if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("allow-bound with mutated bytes", func(t *testing.T) {
		dir := abStage(t, "allow-bound", "payload.bin", abRead(t, "payload-mutated-after-approval", "payload.bin"))
		got := scDerived(t, dir, "allow-bound")
		for _, want := range []string{"derived deny/payload_mismatch", "use matches approval: false"} {
			if !strings.Contains(got, want) {
				t.Fatalf("want %q in %q", want, got)
			}
		}
	})
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := abStage(t, "same-client-other-user", "record.json", abRead(t, "allow-bound", "record.json"))
		if got := scDerived(t, dir, "same-client-other-user"); !strings.Contains(got, "derived allow/bound") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestApprovalBindingUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"use":{"payloadFile":"absent.bin"}}`, "absent.bin cannot be read"},
		{`{"decisionTime":"soon","use":{"payloadFile":"payload.bin"}}`, "does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := abStage(t, "allow-bound", "record.json", []byte(tc.body))
			if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
