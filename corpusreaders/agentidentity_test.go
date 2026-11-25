package corpusreaders_test

// The agent-identity-statement reader derives every decision from the member's own
// files. The committed corpus must be clean, and a member whose history is damaged
// must move to the reason the Python reader gives for that damage.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const aisDir = "vectors-agent-identity-statement"

func TestAgentIdentityCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(aisDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accept"] == 0 || counts["reject"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

// Unreadable pins, history or decision move the verdict to the first check they break.
func TestAgentIdentityUnreadableInputsMoveTheVerdict(t *testing.T) {
	const control = "accept-single-version"
	for _, tc := range []struct{ name, file, body, reason string }{
		{"no context", "context.json", "{", "history_malformed"},
		{"no history", "history.json", "[]", "history_malformed"},
		{"no decision", "decision.json", "{", "decision_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			staged := filepath.Join(t.TempDir(), aisDir)
			copyTree(t, corpusPath(aisDir), staged)
			path := filepath.Join(staged, "cases", control, tc.file)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := scDerived(t, staged, control)
			if !strings.Contains(got, "derived reject/"+tc.reason) {
				t.Fatalf("want reject/%s in %q", tc.reason, got)
			}
		})
	}
}
