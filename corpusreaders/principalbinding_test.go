package corpusreaders_test

// The principal-binding reader derives every decision from the binding bytes
// and the request. The committed corpus reaches each check once; the cases below
// swap one member's file for another member's, so the derived decision moves,
// and require the reader to report the move. A reader that echoed the declared
// decision passes the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const pbDir = "vectors-principal-binding"

func pbStageWithFile(t *testing.T, member, from, name string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), pbDir)
	copyTree(t, corpusPath(pbDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, name)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestPrincipalBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(pbDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) == 0 {
		t.Fatal("no members judged")
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestPrincipalBindingEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, from, file, want string
	}{
		{"uma-other-agent", "uma-bound", "case.json", "derived verified/agent_bound"},
		{"uma-bound", "uma-other-agent", "case.json", "derived rejected/agent_mismatch"},
		{"uma-bound", "uma-other-principal", "case.json", "derived rejected/principal_mismatch"},
		{"uma-bound", "uma-scope-widened", "case.json", "derived rejected/scope_exceeded"},
		{"uma-bound", "uma-purpose-not-echoed", "binding.jws", "derived rejected/echo_mismatch"},
		{"uma-bound", "uma-expiry-extended", "binding.jws", "derived rejected/terms_weakened"},
		{"uma-bound", "uma-edited-after-signing", "binding.jws", "the binding signature verifies: false"},
		{"uma-signed-by-other-key", "uma-bound", "binding.jws", "the binding signature verifies: true"},
		{"hcp-bound", "hcp-grant-revoked", "binding.json", "derived rejected/grant_inactive"},
		{"hcp-bound", "hcp-scopes-beyond-access", "binding.json", "derived rejected/scope_not_backed"},
		{"hcp-bound", "hcp-principal-not-subject", "binding.json", "derived rejected/principal_mismatch"},
		{"hcp-scopes-beyond-access", "hcp-bound", "binding.json", "derived rejected/scope_exceeded"},
		{"hcp-bound", "hcp-edited-after-signing", "binding.json", "the binding signature verifies: false"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := pbStageWithFile(t, tc.member, tc.from, tc.file)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

// scope_not_backed reads the grant against its own access, not the request: the
// widened grant is refused there even under a request it covers.
func TestPrincipalBindingScopeStringsMustComeFromAccess(t *testing.T) {
	dir := pbStageWithFile(t, "hcp-scope-widened", "hcp-scopes-beyond-access", "binding.json")
	if got := scDerived(t, dir, "hcp-scope-widened"); !strings.Contains(got, "derived rejected/scope_not_backed") {
		t.Fatalf("want scope_not_backed, got %q", got)
	}
}
