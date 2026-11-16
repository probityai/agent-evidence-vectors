package corpusreaders_test

// The capability-requirement reader derives every decision from the record
// alone. Putting a refused member's record into an accepted member's directory
// must move the derived decision to the reason that member declares.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const crDir = "vectors-capability-requirement"

func crManifest(t *testing.T) []struct {
	ID       string `json:"id"`
	Expected struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"expected"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(corpusPath(crDir), "MANIFEST.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID       string `json:"id"`
			Expected struct {
				Decision string `json:"decision"`
				Reason   string `json:"reason"`
			} `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Vectors
}

func crRecord(t *testing.T, dir, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCapabilityRequirementCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(crDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestCapabilityRequirementEachRefusedRecordMovesTheVerdict(t *testing.T) {
	controls := map[string]string{
		"requirement": "allow-requirement-pinned",
		"report":      "allow-report-identity-unproven-behaviour-supported",
		"drift":       "allow-drift-stable",
	}
	for _, member := range crManifest(t) {
		if member.Expected.Decision != "deny" {
			continue
		}
		family := "requirement"
		switch {
		case strings.Contains(member.ID, "-report-"):
			family = "report"
		case strings.Contains(member.ID, "-drift-"):
			family = "drift"
		}
		control := controls[family]
		t.Run(member.ID, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), crDir)
			copyTree(t, corpusPath(crDir), dir)
			record := crRecord(t, corpusPath(crDir), member.ID)
			if err := os.WriteFile(filepath.Join(dir, "cases", control, "record.json"), record, 0o600); err != nil {
				t.Fatal(err)
			}
			want := "derived deny/" + member.Expected.Reason
			if got := scDerived(t, dir, control); !strings.Contains(got, want) {
				t.Fatalf("want %q, got %q", want, got)
			}
		})
	}
}
