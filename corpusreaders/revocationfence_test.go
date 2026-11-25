package corpusreaders_test

// The revocation-fence reader derives every member's expected object from the stored records.
// The committed corpus reaches each rule; the cases below swap one file of a member for the same
// file of another, so the derived object moves, and require the reader to report the move. A
// reader that echoed the declared object passes the committed corpus and fails each case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const rfDir = "vectors-revocation-fence"

func rfStageWithFile(t *testing.T, member, file, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), rfDir)
	copyTree(t, corpusPath(rfDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestRevocationFenceCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(rfDir))
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

func TestRevocationFenceEachRuleMovesTheDecision(t *testing.T) {
	cases := []struct{ member, file, from, want string }{
		{"permit-valid", "permit.json", "permit-unknown-authority", `"reason":"unknown_authority"`},
		{"permit-valid", "permit.json", "permit-bad-signature-non-canonical-base64", `"reason":"bad_signature"`},
		{"permit-valid", "permit.json", "permit-malformed-epoch-float", `"reason":"malformed"`},
		{"permit-valid", "permit.json", "permit-malformed-repeated-member", `"reason":"malformed"`},
		{"permit-valid", "case.json", "permit-expired-at-not-after", `"reason":"expired"`},
		{"update-installs-next-epoch", "case.json", "update-rollback-refused", `"reason":"epoch_unchanged"`},
		{"outcome-valid-committed", "outcome.json", "outcome-malformed-stage-before-key", `"reason":"malformed"`},
		{"outcome-valid-committed", "outcome.json", "outcome-key-before-types", `"reason":"unknown_target_key"`},
		{"commit-a-committed", "case.json", "commit-a-revoked-effect-not-done", `"decision":"outcome_mismatch"`},
		{"commit-a-committed", "outcome.json", "commit-a-outcome-unpinned-key", `"decision":"outcome_mismatch"`},
		{"commit-b-committed", "case.json", "commit-b-revocation-pending", `"revocation_status":"partial"`},
		{"commit-c-committed", "case.json", "commit-c-revoked-before-commit-void-pending", `"reason":"revoked_before_commit"`},
		{"propagation-all-acknowledged", "case.json", "propagation-pending-on-both", `"decision":"pending"`},
		{"ledger-resolved-after-revoke", "case.json", "ledger-retry-after-revoke-refused", `"revocation_status":"unknown"`},
		{"feed-account-disabled-revoked", "set.jws", "feed-session-revoked-bound", `"decision":"session_ended"`},
		{"feed-account-disabled-revoked", "set.jws", "feed-bad-signature", `"reason":"bad_signature"`},
		{"feed-account-disabled-revoked", "set.jws", "feed-set-malformed-padded", `"reason":"set_malformed"`},
		{"feed-account-disabled-revoked", "set.jws", "feed-subject-issuer-mismatch", `"reason":"subject_issuer_mismatch"`},
		{"feed-session-revoked-bound", "case.json", "feed-session-revoked-unbound", `"decision":"rotated"`},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := rfStageWithFile(t, tc.member, tc.file, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, "derived ") || !strings.Contains(got, tc.want) {
				t.Fatalf("want a derived finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
