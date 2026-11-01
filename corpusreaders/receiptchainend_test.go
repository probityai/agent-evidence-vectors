package corpora_test

// The receipt-chain-end reader derives every decision from the receipt bytes.
// The committed corpus reaches each check; the cases below copy one file of
// another member into a member, so the derived decision moves, and require the
// reader to report the move. Each expected decision is the one the Python
// reference reader derives for the same swap. A reader that echoed the
// declared decision passes the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const rceDir = "vectors-receipt-chain-end"

func rceStageWithFile(t *testing.T, member, name, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), rceDir)
	copyTree(t, corpusPath(rceDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, name)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestReceiptChainEndCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(rceDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) != 24 {
		t.Fatalf("judged %d members, the corpus has 24", len(result.Members))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestReceiptChainEndEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, name, from, want string
	}{
		{"control-closed-run", "chain.jsonl", "tail-truncation", "derived prefix/end_unproven"},
		{"control-closed-run", "chain.jsonl", "signature-tamper", "derived rejected/signature_invalid"},
		{"control-closed-run", "chain.jsonl", "signature-tamper", "every receipt signature verifies: false"},
		{"control-closed-run", "chain.jsonl", "untrusted-genesis-key", "derived rejected/signer_untrusted"},
		{"control-closed-run", "chain.jsonl", "close-count-forged", "derived rejected/close_binding_invalid"},
		{"control-closed-run", "chain.jsonl", "reorder-timestamp-tie", "derived rejected/chain_link_broken"},
		{"control-rotation-endorsed", "chain.jsonl", "rotation-resigned-tail-endorsement", "derived rejected/rotation_unendorsed"},
		{"control-closed-run-retained-head", "chain.jsonl", "tail-truncation", "derived rejected/head_missing"},
		{"control-closed-run-retained-head", "chain.jsonl", "fork-both-branches", "derived rejected/chain_link_broken"},
		{"control-closed-run-retained-head", "head.json", "fork-branch-against-retained-seq", "derived rejected/head_position_mismatch"},
		{"control-closed-run-retained-head", "head.json", "seq-reset-control-endorsed", "derived rejected/head_position_mismatch"},
		{"control-open-run-final-head", "head.json", "final-head-not-at-end", "derived rejected/head_not_final"},
		{"control-open-run-final-head", "head.json", "stale-head-honest-extension", "derived prefix/end_unproven"},
		{"tail-truncation", "chain.jsonl", "control-closed-run", "derived verified/end_proven_close"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.name+" of "+tc.from, func(t *testing.T) {
			dir := rceStageWithFile(t, tc.member, tc.name, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

// A swap that leaves the decision where the manifest puts it must still be
// reported, as a changed file: a reader that judged only decisions would pass
// a member whose bytes were replaced by an equivalent chain.
func TestReceiptChainEndReplacedBytesAreReported(t *testing.T) {
	dir := rceStageWithFile(t, "control-open-prefix", "chain.jsonl", "prefix-replay-shared-session-close")
	got := scDerived(t, dir, "control-open-prefix")
	if !strings.Contains(got, "chain.jsonl does not match its manifest digest") || strings.Contains(got, "derived") {
		t.Fatalf("want only the digest finding, got %q", got)
	}
}
