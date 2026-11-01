package corpora_test

// The grade-floor reader derives every grade from the record. The committed
// corpus reaches each refusal code once; the cases below give each rejected
// member its accepted twin's record and each accepted member its rejected
// twin's, so the derived answer moves, and require the reader to report the
// move. A reader that echoed the manifest passes the committed corpus and fails
// every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const gfDir = "vectors-grade-floor"

func gfTwins(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(gfDir), "MANIFEST.json")) // #nosec G304 -- the committed manifest
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

func gfStageWithCase(t *testing.T, member, caseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), gfDir)
	copyTree(t, corpusPath(gfDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", caseFrom, "case.json")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "case.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestGradeFloorCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(gfDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accepted"] != 5 || counts["rejected"] != 8 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestGradeFloorReaderDerivesRatherThanEchoes(t *testing.T) {
	for rejected, accepted := range gfTwins(t) {
		for _, pair := range [][2]string{{rejected, accepted}, {accepted, rejected}} {
			member, from := pair[0], pair[1]
			t.Run(member+"<-"+from, func(t *testing.T) {
				result, err := corpora.Judge(gfStageWithCase(t, member, from))
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
