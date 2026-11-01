package corpora_test

// The a2a canonicalization reader answers every vector itself, so a member
// whose expected bytes are edited, or a manifest whose digest no longer covers
// it, must turn the committed clean corpus into findings.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const a2aDir = "vectors-a2a-jcs-v01"

func TestA2AJCSCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(a2aDir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() || len(result.Members) != 57 {
		t.Fatalf("members=%d findings=%v", len(result.Members), result.Findings)
	}
	for _, m := range result.Members {
		if !m.OK() {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func a2aStage(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), a2aDir)
	copyTree(t, corpusPath(a2aDir), copied)
	return copied
}

func a2aRewrite(t *testing.T, path, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), from) {
		t.Fatalf("%s does not contain %q", path, from)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), from, to, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestA2AJCSRecomputesTheExpectedBytes(t *testing.T) {
	dir := a2aStage(t)
	// 0.000001, the cross-SDK break, with its expected bytes changed to the
	// 1e-06 a2a-python wrote: the reader's own answer must disagree.
	a2aRewrite(t, filepath.Join(dir, "a5-number-serialization", "A5-001.json"),
		"302e3030303030317d", "31652d30367d")
	result, err := corpora.Judge(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range result.Members {
		if m.ID == "A5-001" {
			found = strings.Contains(strings.Join(m.Findings, " "), "diverged")
		}
	}
	if !found {
		t.Fatalf("an edited expected value was not caught: %+v", result)
	}
}

func TestA2AJCSRefusesADigestThatDoesNotCoverTheManifest(t *testing.T) {
	dir := a2aStage(t)
	a2aRewrite(t, filepath.Join(dir, "MANIFEST.json"), `"layer": "canonicalization"`, `"layer": "canonicalisation"`)
	result, err := corpora.Judge(dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() || !strings.Contains(strings.Join(result.Findings, " "), "corpusDigest") {
		t.Fatalf("a manifest edit was not caught: %v", result.Findings)
	}
}
