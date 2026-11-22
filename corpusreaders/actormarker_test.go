package corpusreaders_test

// The actor-marker-survival reader derives every decision from the record alone, and
// agrees with the Python reader on every member: the manifest's declared decision is
// the Python reader's. Swapping a control's record for a refused member's must move
// the decision, and a changed trust bundle or pinned signing input is a finding.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const amDir = "vectors-actor-marker-survival"

func amStage(t *testing.T, member, name, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), amDir)
	copyTree(t, corpusPath(amDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func amRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(amDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestActorMarkerCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(amDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 30 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	if counts := result.CountsByVerdict(); counts["accept"] != 8 || counts["reject"] != 22 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestActorMarkerEachRefusalMovesTheControl(t *testing.T) {
	control := "accept-two-hop"
	entries, err := os.ReadDir(filepath.Join(corpusPath(amDir), "cases"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		from := entry.Name()
		if strings.HasPrefix(from, "accept-") || strings.HasPrefix(from, "contract-id") {
			continue
		}
		t.Run(from, func(t *testing.T) {
			dir := amStage(t, control, "record.json", amRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived reject/") {
				t.Fatalf("want a derived reject, got %q", got)
			}
		})
	}
}

func TestActorMarkerChangedSigningInputIsAFinding(t *testing.T) {
	dir := amStage(t, "accept-two-hop", "signing-input-1.jcs", "{}")
	if got := scDerived(t, dir, "accept-two-hop"); !strings.Contains(got, "signing-input-1.jcs") {
		t.Fatalf("want a signing-input finding, got %q", got)
	}
}

func TestActorMarkerMovedTrustBundleIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), amDir)
	copyTree(t, corpusPath(amDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "TRUST.json"), []byte(`{"writers":{}}`), 0o600); err != nil {
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
