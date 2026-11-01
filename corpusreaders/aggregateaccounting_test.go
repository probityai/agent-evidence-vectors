package corpora_test

// The aggregate-accounting reader derives every decision from the record alone.
// Swapping one member's record for another's must move the derived decision,
// and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const aaDir = "vectors-aggregate-accounting"

func aaStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), aaDir)
	copyTree(t, corpusPath(aaDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func aaRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(aaDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAggregateAccountingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(aaDir))
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

func TestAggregateAccountingEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "identity-missing-subtree",
		"latency-bound-admitted", "unknown-outcome-released-after-expiry", "race-both-admitted",
		"fitting-request-refused", "effect-counts-disagree"}
	for _, from := range denied {
		t.Run("allow-concurrent-both-fit with the record of "+from, func(t *testing.T) {
			dir := aaStage(t, "allow-concurrent-both-fit", aaRead(t, from))
			if got := scDerived(t, dir, "allow-concurrent-both-fit"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := aaStage(t, "race-both-admitted", aaRead(t, "allow-race-one-admitted"))
		if got := scDerived(t, dir, "race-both-admitted"); !strings.Contains(got, "derived allow/aggregate_held") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
	t.Run("an answer one millisecond past the bound is not admitted", func(t *testing.T) {
		later := strings.Replace(aaRead(t, "allow-latency-at-bound-admitted"),
			`"latencyMs": 200`, `"latencyMs": 201`, 1)
		dir := aaStage(t, "allow-latency-at-bound-admitted", later)
		if got := scDerived(t, dir, "allow-latency-at-bound-admitted"); !strings.Contains(got, "derived deny/latency_bound_admitted") {
			t.Fatalf("want a latency denial, got %q", got)
		}
	})
}

func TestAggregateAccountingUnreadableInputsAreFindings(t *testing.T) {
	dir := aaStage(t, "allow-concurrent-both-fit", "{")
	if got := scDerived(t, dir, "allow-concurrent-both-fit"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}

func TestAggregateAccountingDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), aaDir)
	copyTree(t, corpusPath(aaDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"aggregate_held"`, `"aggregate_held "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("want a corpusDigest finding")
	}
	if err := os.WriteFile(path, []byte(`{"suite":"aggregate-accounting/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
