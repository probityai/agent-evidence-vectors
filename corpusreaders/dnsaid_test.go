package corpusreaders_test

// The DNS-AID integrity reader must report the committed corpora clean and turn
// each tampering it exists to catch into a finding: a manifest key repeated in
// another letter case (Go's decoder folds case, the Python reader does not), a
// case file the manifest does not list, and a declared code listed twice.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

var dnsAidDirs = map[string]int{"vectors-dns-aid-sig-v01": 53, "vectors-dns-aid-rrset-v01": 17}

func TestDNSAIDCorporaAreClean(t *testing.T) {
	for dir, members := range dnsAidDirs {
		result, err := corpusreaders.Judge(corpusPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if !result.OK() || len(result.Members) != members {
			t.Errorf("%s: members=%d findings=%v", dir, len(result.Members), result.Findings)
		}
		for _, m := range result.Members {
			if !m.OK() {
				t.Errorf("%s %s: %v", dir, m.ID, m.Findings)
			}
		}
	}
}

func dnsAidStage(t *testing.T, dir string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dir)
	copyTree(t, corpusPath(dir), copied)
	return copied
}

func dnsAidFindings(t *testing.T, dir string) string {
	t.Helper()
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]string{}, result.Findings...)
	for _, m := range result.Members {
		all = append(all, m.Findings...)
	}
	return strings.Join(all, "\n")
}

func dnsAidEdit(t *testing.T, path, from, to string) {
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

func TestDNSAIDRefusesACaseFoldedManifestKey(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-sig-v01")
	// The Python reader reads "expected" (agrees); Go's decoder keeps the last
	// case-insensitive match, so without the check it would judge "Expected".
	dnsAidEdit(t, filepath.Join(dir, "MANIFEST.json"), `"expected": {`,
		`"Expected": {"codes": ["expired"], "decision": "contradicted", "verdict": "invalid"}, "expected": {`)
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "twice in one object") {
		t.Fatalf("no finding for a case-folded duplicate key: %q", got)
	}
}

func TestDNSAIDReportsAnUnlistedCaseFile(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	if err := os.WriteFile(filepath.Join(dir, "cases", "stray.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "stray.json") {
		t.Fatalf("no finding for an unlisted case file: %q", got)
	}
}

func TestDNSAIDReportsARepeatedCode(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	dnsAidEdit(t, filepath.Join(dir, "MANIFEST.json"), `"rrset-malformed"`, `"rrset-malformed",
     "rrset-malformed"`)
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "twice: codes are a set") {
		t.Fatalf("no finding for a repeated code: %q", got)
	}
}
