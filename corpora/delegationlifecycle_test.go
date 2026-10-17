package corpora_test

// The delegation lifecycle reader decides every member from its signed records
// and its policy. The cases below give each refused member the whole case of its
// accepted twin, and each accepted twin the case of a refused member that names
// it, and require the reader to report the moved decision. A reader that echoed
// the manifest passes the committed corpus and fails every case here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const dlDir = "vectors-delegation-lifecycle"

type dlRow struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Set  string `json:"set"`
	Twin string `json:"twin"`
}

func dlRows(t *testing.T) []dlRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(dlDir), "MANIFEST.json")) // #nosec G304 -- the committed manifest
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []dlRow `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Vectors
}

func dlStageWithCase(t *testing.T, member, caseFrom string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dlDir)
	copyTree(t, corpusPath(dlDir), copied)
	target := filepath.Join(copied, "cases", member)
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	copyTree(t, filepath.Join(copied, "cases", caseFrom), target)
	return copied
}

func dlFindings(t *testing.T, dir, id string) []string {
	t.Helper()
	result, err := corpora.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	for _, m := range result.Members {
		if m.ID == id {
			return m.Findings
		}
	}
	t.Fatalf("%s missing from the result", id)
	return nil
}

func TestDelegationLifecycleCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(dlDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accept"] != 14 || counts["reject"] != 27 || counts["no_verdict"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
	sets := map[string]int{}
	for _, row := range dlRows(t) {
		sets[row.Set]++
	}
	if sets["delegation-tree"] != 23 || sets["re-registration"] != 12 || sets["recovery"] != 7 {
		t.Fatalf("sets: %v", sets)
	}
}

func TestDelegationLifecycleReaderDecidesRatherThanEchoes(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range dlRows(t) {
		if row.Twin == "" {
			continue
		}
		pairs := [][2]string{{row.ID, row.Twin}}
		if !seen[row.Twin] {
			seen[row.Twin] = true
			pairs = append(pairs, [2]string{row.Twin, row.ID})
		}
		for _, pair := range pairs {
			member, from := pair[0], pair[1]
			t.Run(member+"<-"+from, func(t *testing.T) {
				for _, f := range dlFindings(t, dlStageWithCase(t, member, from), member) {
					if strings.HasPrefix(f, "derived ") {
						return
					}
				}
				t.Fatalf("%s carries %s's case and the reader reported no moved decision", member, from)
			})
		}
	}
}

func TestDelegationLifecycleFlippedRecordNamesItsMember(t *testing.T) {
	copied := filepath.Join(t.TempDir(), dlDir)
	copyTree(t, corpusPath(dlDir), copied)
	record := filepath.Join(copied, "cases", "tree-chain-valid", "07-grant-g-worker.json")
	flipOneByte(t, record)
	findings := dlFindings(t, copied, "tree-chain-valid")
	if len(findings) == 0 {
		t.Fatal("a record was changed and the member it belongs to carries no finding")
	}
}

func TestDelegationLifecycleRefusedMemberNeedsAnAcceptedTwin(t *testing.T) {
	copied := filepath.Join(t.TempDir(), dlDir)
	copyTree(t, corpusPath(dlDir), copied)
	path := filepath.Join(copied, "MANIFEST.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"twin": "tree-chain-valid"`, `"twin": "tree-dispute-open"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	named := false
	for _, m := range result.Members {
		for _, f := range m.Findings {
			named = named || strings.Contains(f, "accepted twin")
		}
	}
	if !named {
		t.Fatal("a refused member whose twin is itself refused carries no finding")
	}
}
