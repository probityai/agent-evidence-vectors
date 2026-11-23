package corpusreaders_test

// The tool-descriptor-digest reader derives every decision from the record
// alone. Swapping a control's record for another member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const ddDir = "vectors-tool-descriptor-digest"

func ddStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ddDir)
	copyTree(t, corpusPath(ddDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ddRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ddDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestDescriptorDigestCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(ddDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"match", "contradicted", "gap", "refused"} {
		if counts[verdict] == 0 {
			t.Fatalf("every verdict must be present: %v", counts)
		}
	}
}

func TestDescriptorDigestEachCheckMovesTheVerdict(t *testing.T) {
	control := "match-descriptor-unchanged"
	moved := map[string]string{
		"refused-contract-id-missing":            "refused/contract_id_missing",
		"refused-contract-id-unknown":            "refused/contract_id_unknown",
		"refused-profile-unknown":                "refused/profile_unknown",
		"refused-descriptor-not-canonicalizable": "refused/descriptor_not_canonicalizable",
		"refused-digest-not-recomputed":          "refused/digest_not_recomputed",
		"gap-same-descriptor-two-profiles":       "gap/profiles_differ",
		"gap-profiles-differ-digests-coincide":   "gap/profiles_differ",
		"gap-pin-without-profile":                "gap/profile_absent",
		"contradicted-description-rewritten":     "contradicted/descriptor_changed",
	}
	for from, want := range moved {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := ddStage(t, control, ddRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived "+want) {
				t.Fatalf("want derived %s, got %q", want, got)
			}
		})
	}
	dir := ddStage(t, "refused-profile-unknown", ddRead(t, control))
	if got := scDerived(t, dir, "refused-profile-unknown"); !strings.Contains(got, "derived match/descriptor_unchanged") {
		t.Fatalf("want a derived match, got %q", got)
	}
}

func TestDescriptorDigestUnreadableInputsAreFindings(t *testing.T) {
	dir := ddStage(t, "match-descriptor-unchanged", "{")
	if got := scDerived(t, dir, "match-descriptor-unchanged"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}
