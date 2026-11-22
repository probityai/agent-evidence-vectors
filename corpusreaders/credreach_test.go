package corpusreaders_test

// The credential-reachability reader decides every member from its signed envelope and its
// verifier policy. Each refused member is given its supported twin's case, and each supported
// member a refused member's case, and the reader must report the moved decision: a reader that
// echoed the manifest passes the committed corpus and fails every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const credDir = "vectors-credential-reachability"

func credTwins(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(credDir), "MANIFEST.json")) // #nosec G304 -- the committed manifest
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

func credStageWithCase(t *testing.T, member, caseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), credDir)
	copyTree(t, corpusPath(credDir), copied)
	target := filepath.Join(copied, "cases", member)
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(copied, "cases", caseFrom), target)
	return copied
}

func TestCredentialReachabilityCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(credDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["supported"] != 6 || counts["contradicted"] != 26 ||
		counts["not_established"] != 24 || counts["no_verdict"] != 2 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestCredentialReachabilityReaderDecidesRatherThanEchoes(t *testing.T) {
	seen := map[string]bool{}
	for refused, supported := range credTwins(t) {
		pairs := [][2]string{{refused, supported}}
		if !seen[supported] {
			seen[supported] = true
			pairs = append(pairs, [2]string{supported, refused})
		}
		for _, pair := range pairs {
			member, from := pair[0], pair[1]
			t.Run(member+"<-"+from, func(t *testing.T) {
				result, err := corpusreaders.Judge(credStageWithCase(t, member, from))
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
