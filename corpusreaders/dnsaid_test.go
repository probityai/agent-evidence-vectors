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

var dnsAidDirs = map[string]int{"vectors-dns-aid-sig-v01": 59, "vectors-dns-aid-rrset-v01": 17}

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

// Each tampering of the sig corpus and the finding it must produce.
var dnsAidTamperings = []struct {
	name, file, from, to, want string
}{
	{"accept declared invalid", "MANIFEST.json", `"verdict": "valid"`, `"verdict": "invalid"`, "does not fit the kind"},
	{"decision unknown", "MANIFEST.json", `"decision": "agrees"`, `"decision": "maybe"`, "decision \"maybe\" does not fit"},
	{"codes unsorted", "MANIFEST.json", `"codes": [
     "alg-not-es256"
    ]`, `"codes": [
     "zz",
     "alg-not-es256"
    ]`, "not sorted"},
	{"file outside cases", "MANIFEST.json", `"file": "cases/alg-none.json"`, `"file": "alg-none.json"`, "not under cases/"},
	{"file missing", "MANIFEST.json", `"file": "cases/alg-none.json"`, `"file": "cases/absent.json"`, "missing"},
	{"member edited", "cases/alg-none.json", `"now": 1790000000`, `"now": 1790000001`, "does not recompute"},
	{"member names another case", "cases/alg-none.json", `"case": "alg-none"`, `"case": "expired"`, "names another case"},
	{"counts wrong", "MANIFEST.json", `"accept": `, `"accept": 1`, "counts disagree"},
	{"duplicate id", "MANIFEST.json", `"id": "expired"`, `"id": "alg-none"`, "duplicate id"},
}

func TestDNSAIDReportsEachTampering(t *testing.T) {
	for _, tc := range dnsAidTamperings {
		t.Run(tc.name, func(t *testing.T) {
			dir := dnsAidStage(t, "vectors-dns-aid-sig-v01")
			dnsAidEdit(t, filepath.Join(dir, tc.file), tc.from, tc.to)
			if got := dnsAidFindings(t, dir); !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestDNSAIDRefusesAnUnparsableManifest(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	dnsAidEdit(t, filepath.Join(dir, "MANIFEST.json"), `"counts": {`, `"counts": [`)
	if _, err := corpusreaders.Judge(dir); err == nil {
		t.Fatal("a manifest that does not parse must be an error")
	}
}

func TestDNSAIDReportsAMemberThatDoesNotParse(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	path := filepath.Join(dir, "cases", "proto-empty.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "does not parse") {
		t.Fatalf("no finding for a member that does not parse: %q", got)
	}
}

func TestDNSAIDReportsAMissingCasesDirectory(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	if err := os.RemoveAll(filepath.Join(dir, "cases")); err != nil {
		t.Fatal(err)
	}
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "cases/ cannot be read") {
		t.Fatalf("no finding for a missing cases/: %q", got)
	}
}

func TestDNSAIDFindsARepeatedKeyInsideAnArray(t *testing.T) {
	dir := dnsAidStage(t, "vectors-dns-aid-rrset-v01")
	dnsAidEdit(t, filepath.Join(dir, "MANIFEST.json"), `"id": "alpn-as-list"`, `"id": "alpn-as-list", "ID": "x"`)
	if got := dnsAidFindings(t, dir); !strings.Contains(got, "twice in one object") {
		t.Fatalf("no finding for a repeated key inside the vectors array: %q", got)
	}
}
