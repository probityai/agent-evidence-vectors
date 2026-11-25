package corpusreaders_test

// The authority-epoch reader derives every answer from the stored log, head and request.
// The committed corpus reaches each rule; the cases below swap one file of a member for the
// same file of another member built on the same log, so the derived answer moves, and
// require the reader to report the move. A reader that echoed the declared answer passes
// the committed corpus and fails each case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const aeDir = "vectors-authority-epoch-fence"

func aeStageWithFile(t *testing.T, member, file, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), aeDir)
	copyTree(t, corpusPath(aeDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestAuthorityEpochCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(aeDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 || len(result.Members) == 0 {
		t.Fatalf("findings %v, members %d", result.Findings, len(result.Members))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestAuthorityEpochEachRuleMovesTheAnswer(t *testing.T) {
	const clean = "epoch-current-epoch-admitted"
	cases := []struct{ member, file, from, want string }{
		{clean, "request.json", "epoch-ahead-of-the-log", "derived refuse/epoch_ahead/live"},
		{clean, "request.json", "delegation-grant-held-by-another-subject", "derived refuse/no_grant/live"},
		{clean, "request.json", "root-request-signed-by-unpinned-holder", "derived refuse/unknown_holder/live"},
		{clean, "request.json", "root-request-altered-after-signing", "derived refuse/request_signature_invalid/live"},
		{clean, "request.json", "status-malformed-request-epoch-float", "derived no_verdict/malformed/unknown"},
		{clean, "case.json", "status-no-head-reads-unknown", "derived refuse/epoch_unavailable/unknown"},
		{"status-open-dispute-reads-unknown", "head.json", "status-confirmed-dispute-reads-closed",
			"derived refuse/history_incomplete/unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := aeStageWithFile(t, tc.member, tc.file, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
