package corpusreaders_test

// The PriorSeal seam reader derives each answer from the case's own signed
// source and observed envelope. Changing one field of an observed envelope must
// move the derived answer, and a manifest that declares another answer than the
// text gives must be a finding.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const pssDir = "vectors-priorseal-exact-call-seams"

func pssStage(t *testing.T, member, old, replacement string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), pssDir)
	copyTree(t, corpusPath(pssDir), copied)
	path := filepath.Join(copied, "cases", member, "case.json")
	body, err := os.ReadFile(path) // #nosec G304 -- a test reading its own staged copy
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), old) {
		t.Fatalf("%s does not contain %q", member, old)
	}
	changed := strings.Replace(string(body), old, replacement, 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestPriorSealSeamsCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(pssDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["bound"] == 0 || counts["not_bound"] == 0 || counts["open"] == 0 {
		t.Fatalf("all three answers must be present: %v", counts)
	}
}

func TestPriorSealSeamsAnEditedCaseMovesTheAnswer(t *testing.T) {
	// The control is decided; changing its observed action makes it not_bound,
	// which the manifest does not declare, so the member carries a finding.
	dir := pssStage(t, "control-case-00", `"action"`, `"actionX"`)
	if got := scDerived(t, dir, "control-case-00"); !strings.Contains(got, "answer the text gives") {
		t.Fatalf("want an answer finding, got %q", got)
	}
}

func TestPriorSealSeamsUnreadableCaseIsAFinding(t *testing.T) {
	dir := pssStage(t, "control-case-00", "{", "[")
	if got := scDerived(t, dir, "control-case-00"); got == "" {
		t.Fatal("want a finding for a case that does not parse or match its digest")
	}
}
