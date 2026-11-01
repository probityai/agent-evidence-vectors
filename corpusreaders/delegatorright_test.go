package corpora_test

// The delegator-right reader derives every decision from the record. Swapping
// one member's record into another must move the derived decision, and the
// reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const drDir = "vectors-delegator-right"

func drStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), drDir)
	copyTree(t, corpusPath(drDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func drRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(drDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDelegatorRightCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(drDir))
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

func TestDelegatorRightEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "malformed-rights-field-missing",
		"request-outside-granted-scope", "delegator-never-entitled", "entitlement-removed-at-deadline",
		"ancestor-scope-removed-at-deadline"}
	for _, from := range denied {
		t.Run("allow-entitled-delegator with the record of "+from, func(t *testing.T) {
			dir := drStage(t, "allow-entitled-delegator", drRead(t, from))
			if got := scDerived(t, dir, "allow-entitled-delegator"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := drStage(t, "delegator-never-entitled", drRead(t, "allow-entitled-delegator"))
		if got := scDerived(t, dir, "delegator-never-entitled"); !strings.Contains(got, "derived allow/entitled") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestDelegatorRightUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/delegator-right/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := drStage(t, "allow-entitled-delegator", []byte(tc.body))
			if got := scDerived(t, dir, "allow-entitled-delegator"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
