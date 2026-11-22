package corpusreaders_test

// The dns-aid readers judge the corpus tree, not the members' verdicts. Each case
// copies one of the two corpora, makes one change, and requires the reader to
// report it, so a check deleted from dnsaid.go fails here instead of passing a
// damaged corpus as clean.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const (
	dnsSigDir   = "vectors-dns-aid-sig-v01"
	dnsRRsetDir = "vectors-dns-aid-rrset-v01"
)

// dnsAidRewriteMember replaces a member file and re-pins its sha256 in the
// manifest, so the only defect left is the one the case plants in the bytes.
func dnsAidRewriteMember(t *testing.T, dir, id, body string) {
	t.Helper()
	rel := filepath.Join("cases", id+".json")
	writeFile(t, dir, rel, body)
	sum := sha256.Sum256([]byte(body))
	editManifest(t, dir, func(m map[string]any) {
		row := firstRowWhere(t, m, func(r map[string]any) bool { return r["id"] == id })
		row["sha256"] = hex.EncodeToString(sum[:])
	})
}

func dnsAidFirstReject(m map[string]any) string {
	for _, item := range vectorsOf(m) {
		if row, ok := item.(map[string]any); ok && row["kind"] == "reject" {
			id, _ := row["id"].(string)
			return id
		}
	}
	return ""
}

func dnsAidFindings() []findingCase {
	return []findingCase{
		{"dns-aid repeated id", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				rows := vectorsOf(m)
				first, _ := rows[0].(map[string]any)
				second, _ := rows[1].(map[string]any)
				second["id"] = first["id"]
			})
		}, "duplicate id"},
		{"dns-aid accept that declares codes", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), []any{"svcb-claim-absent"}, "expected", "codes")
			})
		}, "does not fit the kind"},
		{"dns-aid reject declared valid", dnsRRsetDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "valid", "expected", "verdict")
			})
		}, "does not fit the kind"},
		{"dns-aid unsorted codes", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), []any{"z-code", "a-code"}, "expected", "codes")
			})
		}, "codes are not sorted"},
		{"dns-aid reject that agrees", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "agrees", "expected", "decision")
			})
		}, "does not fit the kind: agrees is an accept"},
		{"dns-aid unknown decision", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), "maybe", "expected", "decision")
			})
		}, `decision "maybe"`},
		{"dns-aid member outside cases/", dnsRRsetDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["file"] = "cases/../MANIFEST.json"
			})
		}, "not under cases/"},
		{"dns-aid member file gone", dnsSigDir, func(t *testing.T, dir string) {
			var id string
			editManifest(t, dir, func(m map[string]any) { id = dnsAidFirstReject(m) })
			removeFile(t, dir, filepath.Join("cases", id+".json"))
		}, "member file is missing"},
		{"dns-aid member bytes changed", dnsRRsetDir, func(t *testing.T, dir string) {
			var id string
			editManifest(t, dir, func(m map[string]any) { id = dnsAidFirstReject(m) })
			path := filepath.Join(dir, "cases", id+".json")
			body, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, dir, filepath.Join("cases", id+".json"), string(body)+"\n")
		}, "sha256 does not recompute"},
		{"dns-aid member names another case", dnsSigDir, func(t *testing.T, dir string) {
			var id string
			editManifest(t, dir, func(m map[string]any) { id = dnsAidFirstReject(m) })
			dnsAidRewriteMember(t, dir, id, `{"case":"some-other-case"}`)
		}, "names another case"},
		{"dns-aid member repeats a member", dnsSigDir, func(t *testing.T, dir string) {
			var id string
			editManifest(t, dir, func(m map[string]any) { id = dnsAidFirstReject(m) })
			dnsAidRewriteMember(t, dir, id, `{"case":"`+id+`","case":"`+id+`"}`)
		}, "the member does not parse"},
		{"dns-aid member carries NaN", dnsRRsetDir, func(t *testing.T, dir string) {
			var id string
			editManifest(t, dir, func(m map[string]any) { id = dnsAidFirstReject(m) })
			dnsAidRewriteMember(t, dir, id, `{"case":"`+id+`","port":NaN}`)
		}, "the member does not parse"},
		{"dns-aid counts disagree", dnsSigDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				counts, _ := m["counts"].(map[string]any)
				counts["accept"] = 99.0
			})
		}, "counts disagree"},
		{"dns-aid corpus digest stale", dnsRRsetDir, func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				m["corpusDigest"] = strings.Repeat("0", 64)
			})
		}, "corpusDigest does not match"},
	}
}

func TestDNSAidEveryFindingIsReachable(t *testing.T) {
	for _, c := range dnsAidFindings() {
		t.Run(c.name, func(t *testing.T) {
			dir := stage(t, c.dir)
			c.mutate(t, dir)
			got := allFindings(t, dir)
			for _, f := range got {
				if strings.Contains(f, c.want) {
					return
				}
			}
			t.Fatalf("want a finding containing %q, got %v", c.want, got)
		})
	}
}

func TestDNSAidCommittedCorporaAreClean(t *testing.T) {
	for _, dir := range []string{dnsSigDir, dnsRRsetDir} {
		result, err := corpusreaders.Judge(corpusPath(dir))
		if err != nil {
			t.Fatalf("%s: judge: %v", dir, err)
		}
		if !result.OK() || len(result.Members) == 0 {
			t.Fatalf("%s: findings %v, members %d", dir, result.Findings, len(result.Members))
		}
	}
}

func TestDNSAidManifestThatDoesNotParseIsAnError(t *testing.T) {
	dir := stage(t, dnsSigDir)
	editManifest(t, dir, func(m map[string]any) { m["vectors"] = "not a list" })
	if _, err := corpusreaders.Judge(dir); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("want a parse error, got %v", err)
	}
}
