package corpusreaders_test

// The destination-narrowed-exchange reader derives every decision from the record
// alone, and agrees with the Python reader on all 46 members: the manifest's declared
// decision and retained fields are the Python reader's, so a clean Judge is the
// differential check. Swapping a control's record for a refused member's must move
// the decision, and a changed trust bundle or pinned signing input is a finding.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const deDir = "vectors-destination-narrowed-exchange"

func deStage(t *testing.T, member, name, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), deDir)
	copyTree(t, corpusPath(deDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func deRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(deDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestDestExchangeAgreesWithThePythonReaderOnEveryMember(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(deDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 46 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	if counts := result.CountsByVerdict(); counts["accept"] != 7 || counts["reject"] != 39 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestDestExchangeEachRefusalMovesTheControl(t *testing.T) {
	control := "accept-single-destination"
	entries, err := os.ReadDir(filepath.Join(corpusPath(deDir), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		from := entry.Name()
		if strings.HasPrefix(from, "accept-") {
			continue
		}
		t.Run(from, func(t *testing.T) {
			dir := deStage(t, control, "record.json", deRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived reject/") {
				t.Fatalf("want a derived reject, got %q", got)
			}
		})
	}
}

func TestDestExchangeChangedSigningInputIsAFinding(t *testing.T) {
	dir := deStage(t, "accept-single-destination", "signing-input-1.jcs", "{}")
	if got := scDerived(t, dir, "accept-single-destination"); !strings.Contains(got, "signing-input-1.jcs") {
		t.Fatalf("want a signing-input finding, got %q", got)
	}
}

func TestDestExchangeMovedTrustBundleIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), deDir)
	copyTree(t, corpusPath(deDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "TRUST.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	moved := strings.Replace(string(body), `"maxDelegatedLifetimeSeconds": 300`, `"maxDelegatedLifetimeSeconds": 301`, 1)
	if moved == string(body) {
		t.Fatal("the trust bundle does not carry the lifetime limit this test moves")
	}
	if err := os.WriteFile(filepath.Join(copied, "TRUST.json"), []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() {
		t.Fatal("a trust bundle that moved must not judge clean")
	}
}
