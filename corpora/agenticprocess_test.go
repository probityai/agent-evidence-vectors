package corpora_test

// The agentic-process reader decides every member from its signed envelope
// and its policy. The cases below give each refused member
// the whole case of its supported twin, and each supported member the case of a
// refused member that names it, and require the reader to report the moved
// decision. A reader that echoed the manifest passes the committed corpus and
// fails every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const apDir = "vectors-agentic-process-evidence"

func apTwins(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(apDir), "MANIFEST.json")) // #nosec G304 -- the committed manifest
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID   string `json:"id"`
			Twin string `json:"twin"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	twins := map[string]string{}
	for _, v := range manifest.Vectors {
		if v.Twin != "" {
			twins[v.ID] = v.Twin
		}
	}
	return twins
}

func apStageWithCase(t *testing.T, member, caseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), apDir)
	copyTree(t, corpusPath(apDir), copied)
	target := filepath.Join(copied, "cases", member)
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(copied, "cases", caseFrom), target)
	return copied
}

func TestAgenticProcessCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(apDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["supported"] != 8 || counts["contradicted"] != 4 ||
		counts["not_established"] != 38 || counts["no_verdict"] != 2 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestAgenticProcessReaderDecidesRatherThanEchoes(t *testing.T) {
	seen := map[string]bool{}
	for refused, supported := range apTwins(t) {
		pairs := [][2]string{{refused, supported}}
		if !seen[supported] {
			seen[supported] = true
			pairs = append(pairs, [2]string{supported, refused})
		}
		for _, pair := range pairs {
			member, from := pair[0], pair[1]
			t.Run(member+"<-"+from, func(t *testing.T) {
				result, err := corpora.Judge(apStageWithCase(t, member, from))
				if err != nil {
					t.Fatalf("judge: %v", err)
				}
				for _, m := range result.Members {
					if m.ID != member {
						continue
					}
					for _, f := range m.Findings {
						if strings.HasPrefix(f, "derived ") {
							return
						}
					}
					t.Fatalf("%s carries %s's case and the reader reported no moved decision: %v",
						member, from, m.Findings)
				}
				t.Fatalf("%s missing from the result", member)
			})
		}
	}
}
