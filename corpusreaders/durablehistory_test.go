package corpusreaders_test

// The durable-history reader derives every decision from the record. Swapping
// one member's record into another must move the derived decision, and the
// reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const dhDir = "vectors-durable-history"

func dhStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dhDir)
	copyTree(t, corpusPath(dhDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func dhRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(dhDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDurableHistoryCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(dhDir))
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

// One denied member per check, in check order.
var dhDenied = []string{
	"contract-id-missing", "contract-id-unknown", "malformed-effect-permit-unknown",
	"reset-before-witnessed-event", "run-deleted", "event-moved",
	"codec-key-holder-reencrypted-edit", "store-edit-amount", "model-args-edited",
	"result-edited", "tool-code-changed", "hidden-retry", "applied-effect-recorded-as-timeout",
	"update-accepted-twice", "lost-reply-recorded-as-completed",
}

func TestDurableHistoryEachCheckMovesTheVerdict(t *testing.T) {
	for _, from := range dhDenied {
		t.Run("allow-clean-run with the record of "+from, func(t *testing.T) {
			dir := dhStage(t, "allow-clean-run", dhRead(t, from))
			if got := scDerived(t, dir, "allow-clean-run"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := dhStage(t, "tool-code-changed", dhRead(t, "allow-clean-run"))
		if got := scDerived(t, dir, "tool-code-changed"); !strings.Contains(got, "derived allow/consistent") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

// The reader takes both export shapes and the codec shape: each such control's
// record judged in a denied member's place is derived as an allow.
func TestDurableHistoryReadsEveryExportShape(t *testing.T) {
	for _, from := range []string{"allow-cloud-export-run", "allow-cloud-export-duplicate-delivery",
		"allow-codec-encrypted-run"} {
		t.Run(from, func(t *testing.T) {
			dir := dhStage(t, "tool-code-changed", dhRead(t, from))
			if got := scDerived(t, dir, "tool-code-changed"); !strings.Contains(got, "derived allow/consistent") {
				t.Fatalf("want a derived allow, got %q", got)
			}
		})
	}
}

func TestDurableHistoryUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{"[]", "record.json is not an object"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/durable-history/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := dhStage(t, "allow-clean-run", []byte(tc.body))
			if got := scDerived(t, dir, "allow-clean-run"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
