package corpusreaders_test

// The key-revocation reader derives every decision from the stored list. The committed
// corpus reaches each rule once; the cases below swap one file of a member for the same file
// of another, so the derived decision moves, and require the reader to report the move. A
// reader that echoed the declared decision passes the committed corpus and fails each case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const krDir = "vectors-key-revocation-list"

func krStageWithFile(t *testing.T, member, file, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), krDir)
	copyTree(t, corpusPath(krDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestKeyRevocationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(krDir))
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

func TestKeyRevocationEachRuleMovesTheDecision(t *testing.T) {
	const clean = "covered-no-entry"
	cases := []struct{ member, file, from, want string }{
		{clean, "list.json", "revoked-in-list", "derived revoked/revoked_in_list"},
		{clean, "list.json", "signer-not-trusted", "derived rejected/signer_not_trusted"},
		{clean, "list.json", "signer-claims-a-trusted-thumbprint", "derived rejected/signer_not_trusted"},
		{clean, "list.json", "list-signature-invalid", "derived rejected/list_signature_invalid"},
		{clean, "case.json", "list-older-than-accepted", "derived rejected/list_older_than_accepted"},
		{clean, "case.json", "list-past-next-update", "derived stale/list_stale"},
		{clean, "case.json", "key-not-covered", "derived no_statement/key_not_covered"},
		{clean, "case.json", "revocation-kept-after-later-list-omits-it", "derived revoked/revoked_kept_from_earlier_list"},
		{"list-signature-invalid", "list.json", clean, "signature verifies true"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := krStageWithFile(t, tc.member, tc.file, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
