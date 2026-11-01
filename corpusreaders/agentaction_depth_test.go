package corpora_test

// The depth pair under aia-c-12 must agree with the parser that enforces the
// bound, not only with the reader's own depth measure. The accepting member
// once nested its extensions 128 deep inside a Statement 130 deep: the reader
// measured the extensions object and passed it, while the I-JSON parser, which
// counts from the Statement's outermost brace, refused the very bytes the
// manifest labels valid.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func TestAgentActionDepthPairMatchesTheParser(t *testing.T) {
	dir := corpusPath("vectors-ai-agent-action")
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID         string   `json:"id"`
			Kind       string   `json:"kind"`
			File       string   `json:"file"`
			Conditions []string `json:"conditions"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, v := range manifest.Vectors {
		if !slices.Contains(v.Conditions, "aia-c-12") {
			continue
		}
		seen[v.Kind]++
		body, err := os.ReadFile(filepath.Join(dir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		err = aee.CheckIJSON(body)
		switch v.Kind {
		case "accept":
			if err != nil {
				t.Errorf("%s is declared valid and the parser refuses it: %v", v.ID, err)
			}
		case "reject":
			if !errors.Is(err, aee.ErrInputTooDeep) {
				t.Errorf("%s is declared depth-exceeded and the parser returns %v", v.ID, err)
			}
		}
	}
	if seen["accept"] != 1 || seen["reject"] != 1 {
		t.Fatalf("want one accept and one reject member under aia-c-12, found %v", seen)
	}
}
