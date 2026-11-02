package corpora_test

// The OASF record reader derives every decision from the case and the record
// bytes. Swapping one member's files into another must move the derived
// decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const orDir = "vectors-oasf-record"

func orStage(t *testing.T, member, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), orDir)
	copyTree(t, corpusPath(orDir), copied)
	for _, name := range []string{"case.json", "record.json"} {
		body, err := os.ReadFile(filepath.Join(corpusPath(orDir), "cases", from, name)) // #nosec G304 -- a test reading its own corpus
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copied
}

func TestOasfRecordCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(orDir))
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

func TestOasfRecordEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":            "contract_id_missing",
		"contract-id-unknown":            "contract_id_unknown",
		"case-digest-unprefixed":         "malformed_case",
		"record-duplicate-member":        "record_not_json",
		"record-not-utf8":                "record_not_json",
		"integer-beyond-exact-range":     "number_not_exact",
		"required-skills-missing":        "oasf_required_field",
		"digest-over-escaped-html":       "digest_mismatch",
		"digest-over-utf8-key-order":     "digest_mismatch",
		"digest-over-negative-zero-text": "digest_mismatch",
		"signer-subject-contains-policy": "signer_not_policy",
		"policy-written-as-pattern":      "signer_not_policy",
	}
	for from, reason := range denied {
		t.Run("allow-plain with the files of "+from, func(t *testing.T) {
			dir := orStage(t, "allow-plain", from)
			if got := scDerived(t, dir, "allow-plain"); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied member with the conformant files", func(t *testing.T) {
		dir := orStage(t, "digest-over-escaped-html", "allow-html-characters")
		if got := scDerived(t, dir, "digest-over-escaped-html"); !strings.Contains(got, "derived allow/conformant") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}
