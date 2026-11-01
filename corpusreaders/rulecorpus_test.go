package corpora_test

// A rule corpus reader derives every answer from the record. The committed
// corpus reaches each refusal code at least once; the cases below give each
// rejected member its accepted twin's record and each accepted member its
// rejected twin's, so the derived answer moves, and require the reader to report
// the move. A reader that echoed the manifest passes the committed corpus and
// fails every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

func rlTwins(t *testing.T, dir string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(dir), "MANIFEST.json")) // #nosec G304 -- the committed manifest
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

func rlStageWithCase(t *testing.T, dir, member, caseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dir)
	copyTree(t, corpusPath(dir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", caseFrom, "case.json")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "case.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func rlCommittedCorpusIsClean(t *testing.T, dir string, accepted, rejected int) {
	t.Helper()
	result, err := corpora.Judge(corpusPath(dir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accepted"] != accepted || counts["rejected"] != rejected {
		t.Fatalf("counts: %v", counts)
	}
}

func rlReaderDerivesRatherThanEchoes(t *testing.T, dir string) {
	t.Helper()
	for rejected, accepted := range rlTwins(t, dir) {
		for _, pair := range [][2]string{{rejected, accepted}, {accepted, rejected}} {
			member, from := pair[0], pair[1]
			t.Run(member+"<-"+from, func(t *testing.T) {
				result, err := corpora.Judge(rlStageWithCase(t, dir, member, from))
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
					t.Fatalf("%s carries %s's record and the reader reported no moved decision: %v",
						member, from, m.Findings)
				}
				t.Fatalf("%s missing from the result", member)
			})
		}
	}
}
