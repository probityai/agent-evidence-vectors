package corpusreaders_test

// The rsa-digestinfo reader derives every decision from the recovered block
// alone. Swapping the valid control's record for another member's must move the
// decision to that member's, and a reader that compares only the trailing digest
// would derive valid for the four blocks that merely end in it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const rdiDir = "vectors-rsa-digestinfo"

func rdiStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), rdiDir)
	copyTree(t, corpusPath(rdiDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func rdiRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(rdiDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestRSADigestInfoCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(rdiDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 8 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"valid", "invalid", "profile-dependent"} {
		if counts[verdict] == 0 {
			t.Fatalf("every verdict must be present: %v", counts)
		}
	}
}

func TestRSADigestInfoEachBlockMovesTheVerdict(t *testing.T) {
	control := "rfc8017-null-parameters"
	moved := map[string]string{
		"absent-null-parameters-exact": "derived profile-dependent/absent_null_parameters",
		"garbage-prefix":               "derived invalid/block_not_exact_encoding",
		"garbage-after-legacy-prefix":  "derived invalid/block_not_exact_encoding",
		"sha512-oid":                   "derived invalid/block_not_exact_encoding",
		"short-padding":                "derived invalid/block_not_exact_encoding",
		"wrong-message":                "derived invalid/block_not_exact_encoding",
		"signature-one-byte-short":     "derived invalid/signature_length",
	}
	for from, want := range moved {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := rdiStage(t, control, rdiRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, want) {
				t.Fatalf("want %q, got %q", want, got)
			}
		})
	}
	dir := rdiStage(t, "garbage-prefix", rdiRead(t, control))
	if got := scDerived(t, dir, "garbage-prefix"); !strings.Contains(got, "derived valid/rfc8017") {
		t.Fatalf("want a derived valid, got %q", got)
	}
}

func TestRSADigestInfoUnreadableInputsAreFindings(t *testing.T) {
	dir := rdiStage(t, "rfc8017-null-parameters", "{")
	if got := scDerived(t, dir, "rfc8017-null-parameters"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}
