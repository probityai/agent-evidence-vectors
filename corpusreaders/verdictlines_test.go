package corpusreaders_test

// VerdictLines answers every member of a corpus with one line. These tests
// hold the three per-member readers, the not-applicable answer for a suite
// with no reader here, and each way a corpus can be unreadable, in this
// package so the per-file coverage floor counts them.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

var vlVerifier = corpusreaders.Verifier{Name: "test", Version: "0"}

func vlLines(t *testing.T, dir string) []corpusreaders.VerdictLine {
	t.Helper()
	lines, err := corpusreaders.VerdictLines(dir, vlVerifier)
	if err != nil {
		t.Fatal(err)
	}
	return lines
}

func vlStage(t *testing.T, dir string) string {
	t.Helper()
	staged := filepath.Join(t.TempDir(), "corpus")
	copyTree(t, corpusPath(dir), staged)
	return staged
}

func TestVerdictLinesCoverEveryMemberOfEachReaderCorpus(t *testing.T) {
	for _, dir := range []string{"vectors", "vectors-approval-binding", "vectors-uncertain-effect"} {
		lines := vlLines(t, corpusPath(dir))
		if len(lines) == 0 {
			t.Fatalf("%s: no lines", dir)
		}
		accept, reject := 0, 0
		for _, l := range lines {
			if l.Schema != corpusreaders.VerdictLineSchema || l.Verifier != vlVerifier || l.CorpusDigest == "" {
				t.Fatalf("%s %s: header %+v", dir, l.Vector, l)
			}
			switch l.Verdict {
			case "accept":
				accept++
			case "reject":
				reject++
				if l.Reason == nil {
					t.Fatalf("%s %s: a reject without a reason", dir, l.Vector)
				}
			default:
				t.Fatalf("%s %s: verdict %q", dir, l.Vector, l.Verdict)
			}
		}
		if accept == 0 || reject == 0 {
			t.Fatalf("%s: %d accept, %d reject", dir, accept, reject)
		}
	}
}

func TestVerdictLinesSuiteWithoutReaderIsNotApplicable(t *testing.T) {
	for _, l := range vlLines(t, corpusPath("vectors-dispatch-fence")) {
		if l.Verdict != "not-applicable" || l.Reason == nil || *l.Reason != "suite-not-implemented" {
			t.Fatalf("%s: %+v", l.Vector, l)
		}
	}
}

func TestVerdictLinesRefuseAnUnreadableManifest(t *testing.T) {
	if _, err := corpusreaders.VerdictLines(t.TempDir(), vlVerifier); err == nil {
		t.Fatal("a directory with no manifest was answered")
	}
	for name, body := range map[string]string{
		"not json":   "{",
		"no suite":   `{"corpusDigest":"d","vectors":[{"id":"a"}]}`,
		"no digest":  `{"suite":"s","vectors":[{"id":"a"}]}`,
		"no vectors": `{"suite":"s","corpusDigest":"d","vectors":[]}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "MANIFEST.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := corpusreaders.VerdictLines(dir, vlVerifier); err == nil {
			t.Fatalf("%s: answered", name)
		}
	}
}

func TestVerdictLinesReportAMissingMemberAsAnError(t *testing.T) {
	staged := vlStage(t, "vectors")
	if err := os.RemoveAll(filepath.Join(staged, "statements")); err != nil {
		t.Fatal(err)
	}
	unreadable := 0
	for _, l := range vlLines(t, staged) {
		if l.Verdict == "error" && l.Reason != nil && strings.HasPrefix(*l.Reason, "vector-unreadable") {
			unreadable++
		}
	}
	if unreadable == 0 {
		t.Fatal("no member reported as unreadable after its files were removed")
	}
}

func TestVerdictLinesReportABrokenRecordAsAnError(t *testing.T) {
	for _, dir := range []string{"vectors-approval-binding", "vectors-uncertain-effect"} {
		staged := vlStage(t, dir)
		cases, err := filepath.Glob(filepath.Join(staged, "cases", "*", "record.json"))
		if err != nil || len(cases) == 0 {
			t.Fatalf("%s: no records (%v)", dir, err)
		}
		if err := os.WriteFile(cases[0], []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		hit := false
		for _, l := range vlLines(t, staged) {
			if l.Verdict == "error" {
				hit = true
			}
		}
		if !hit {
			t.Fatalf("%s: a record that does not parse produced no error line", dir)
		}
	}
}
