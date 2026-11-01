package corpora_test

// The anchored-chain reader derives every decision from the stored bytes. The
// committed corpus reaches each check once; the cases below swap one member's
// store for another member's, so the derived decision moves, and require the
// reader to report the move. A reader that echoed the declared decision passes
// the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const acDir = "vectors-anchored-chain"

func acStageWithStore(t *testing.T, member, storeFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), acDir)
	copyTree(t, corpusPath(acDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", storeFrom, "store.jsonl")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "store.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestAnchoredChainCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(acDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) == 0 {
		t.Fatal("no members judged")
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestAnchoredChainEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, storeFrom, want string
	}{
		{"t2-tail-removal", "intact", "derived verified/chain_anchored"},
		{"intact", "t2-tail-removal", "derived rejected/anchored_head_missing"},
		{"intact", "t3-middle-deletion", "derived rejected/chain_link_broken"},
		{"intact", "t6-cross-context-replay", "derived rejected/record_from_other_chain"},
		{"intact", "rollback-to-abandoned-branch", "derived rejected/anchored_head_mismatch"},
		{"intact", "t1-content-tamper", "every stored signature verifies: false"},
		{"intact", "t9-snapshot-rollback", "derived rejected/anchored_head_missing"},
		{"t1-content-tamper", "intact", "every stored signature verifies: true"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the store of "+tc.storeFrom, func(t *testing.T) {
			dir := acStageWithStore(t, tc.member, tc.storeFrom)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
