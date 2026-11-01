package corpora_test

// A corpus names its vendored contract or criterion relative to the directory
// it sits in. The directory is whatever the caller typed, so these readers must
// agree on that directory however it is spelled: with a trailing slash, as an
// absolute path, or as "." from inside the corpus. They once took
// filepath.Dir of the raw argument, which is the corpus itself in the first and
// third spellings, and reported a present contract missing.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

func TestContractResolvesAgainstTheParentWhateverTheSpelling(t *testing.T) {
	for _, corpus := range []string{
		"vectors-self-reported-record",
		"vectors-mcp-record-contract",
		"vectors-mcp-response-phase",
		"vectors-ai-generation",
	} {
		abs, err := filepath.Abs(filepath.Join("..", corpus))
		if err != nil {
			t.Fatal(err)
		}
		spellings := map[string]string{
			"relative":       filepath.Join("..", corpus),
			"trailing slash": filepath.Join("..", corpus) + string(filepath.Separator),
			"absolute":       abs,
			"dot segments":   filepath.Join("..", "corpora", "..", corpus),
		}
		for name, dir := range spellings {
			result, err := corpora.Judge(dir)
			if err != nil {
				t.Fatalf("%s, %s: %v", corpus, name, err)
			}
			if !result.OK() {
				t.Errorf("%s, %s: judged dirty: %v", corpus, name, result.Findings)
			}
		}
	}
}

func TestContractResolvesFromInsideTheCorpus(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "vectors-self-reported-record"))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(abs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	result, err := corpora.Judge(".")
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Errorf("judged dirty from inside the corpus: %v", result.Findings)
	}
}
