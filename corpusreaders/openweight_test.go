package corpora_test

// The open-weight reader derives every decision from the release record. The
// committed corpus reaches each condition; the cases below put one member's
// release in another member's place, so the derived decision moves, and
// require the reader to say so.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const owDir = "vectors-open-weight-art53"

func owStageWithRelease(t *testing.T, member, releaseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), owDir)
	copyTree(t, corpusPath(owDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", releaseFrom, "release.json")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "release.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestOpenWeightCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(owDir))
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

func TestOpenWeightEachConditionMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, releaseFrom, want string
	}{
		{"exempt-open-release", "noncommercial-licence", "derived not-exempt/licence_restricts_use"},
		{"exempt-open-release", "licence-not-recognised", "derived not-established/licence_not_recognised"},
		{"exempt-open-release", "weights-private", "derived not-exempt/weights_not_public"},
		{"exempt-open-release", "weights-gated", "derived not-established/weights_access_gated"},
		{"exempt-open-release", "weights-without-digest", "derived not-established/weights_not_digest_bound"},
		{"exempt-open-release", "architecture-missing", "derived not-established/architecture_not_evidenced"},
		{"exempt-open-release", "usage-information-missing", "derived not-established/usage_information_not_evidenced"},
		{"exempt-open-release", "monetised-by-personal-data", "derived not-exempt/monetised_release"},
		{"exempt-open-release", "monetisation-not-stated", "derived not-established/monetisation_not_stated"},
		{"exempt-open-release", "systemic-risk-presumed", "derived not-exempt/systemic_risk_presumed"},
		{"exempt-open-release", "systemic-risk-designated", "derived not-exempt/systemic_risk_designated"},
		{"exempt-open-release", "training-compute-not-stated", "derived not-established/training_compute_not_stated"},
		{"systemic-risk-presumed", "exempt-systemic-presumption-rebutted", "derived exempt/all_conditions_evidenced"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the release of "+tc.releaseFrom, func(t *testing.T) {
			dir := owStageWithRelease(t, tc.member, tc.releaseFrom)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
