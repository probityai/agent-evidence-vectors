package corpusreaders

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevocationListCorpusHolds(t *testing.T) {
	result, err := Judge(filepath.Join("..", "corpora", "vectors-revocation-list"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("the corpus does not hold: %+v", result)
	}
}

// A manifest that names another refusal detail, or another list in force, is a finding: the
// reader holds every member to the full refusal text and the state, not only the code.
func TestRevocationListReaderHoldsDetailAndState(t *testing.T) {
	src := filepath.Join("..", "corpora", "vectors-revocation-list")
	for _, edit := range [][2]string{
		{`"reason": "revocation_list_shape:entry_kind_unknown"`, `"reason": "revocation_list_shape:entry_members"`},
		{`"seq": 3`, `"seq": 4`},
	} {
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
			t.Fatal(err)
		}
		manifest := filepath.Join(dir, "MANIFEST.json")
		raw, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), edit[0]) {
			t.Fatalf("the manifest no longer holds %s", edit[0])
		}
		if err := os.WriteFile(manifest, []byte(strings.Replace(string(raw), edit[0], edit[1], 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := Judge(dir)
		if err != nil {
			t.Fatal(err)
		}
		failed := 0
		for _, m := range result.Members {
			if !m.OK() {
				failed++
			}
		}
		if failed != 1 {
			t.Fatalf("%s -> %s: %d members failed, want 1", edit[0], edit[1], failed)
		}
	}
}
