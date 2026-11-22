package corpusreaders_test

// The budget-lineage reader derives every decision from the record alone.
// Swapping one member's record for another's must move the derived decision,
// and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const blDir = "vectors-budget-lineage"

func blStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), blDir)
	copyTree(t, corpusPath(blDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func blRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(blDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestBudgetLineageCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(blDir))
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

func TestBudgetLineageEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":                   "contract_id_missing",
		"contract-id-unknown":                   "contract_id_unknown",
		"malformed-ledger-units-negative":       "malformed_record",
		"delegation-recorded-only-by-delegator": "delegation_unilateral",
		"delegation-from-outside-tree":          "delegation_detached",
		"depth-reset-by-fresh-root":             "depth_limit_exceeded",
		"carve-wider-than-parent":               "carve_exceeds_parent",
		"subagent-rerooted-budget":              "charge_outside_lineage",
		"overspend-across-subtrees":             "lineage_overspend",
	}
	for from, reason := range denied {
		t.Run("allow-two-hop-tree-within-budget with the record of "+from, func(t *testing.T) {
			dir := blStage(t, "allow-two-hop-tree-within-budget", blRead(t, from))
			if got := scDerived(t, dir, "allow-two-hop-tree-within-budget"); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("the rerooted record with its charge booked on the principal's budget", func(t *testing.T) {
		body := strings.Replace(blRead(t, "subagent-rerooted-budget"), `"budget-fresh-root"`, `"budget-1"`, 1)
		dir := blStage(t, "subagent-rerooted-budget", body)
		if got := scDerived(t, dir, "subagent-rerooted-budget"); !strings.Contains(got, "derived deny/lineage_overspend") {
			t.Fatalf("booked where it belongs, twelve units overspend ten: got %q", got)
		}
	})
	t.Run("a charge at the revocation instant is outside the grant", func(t *testing.T) {
		body := strings.Replace(blRead(t, "rerooted-charge-before-revocation"),
			`"at": "2026-11-16T12:04:00Z"`, `"at": "2026-11-16T12:05:00Z"`, 1)
		dir := blStage(t, "rerooted-charge-before-revocation", body)
		if got := scDerived(t, dir, "rerooted-charge-before-revocation"); !strings.Contains(got, "derived allow/lineage_held") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestBudgetLineageUnreadableInputsAreFindings(t *testing.T) {
	dir := blStage(t, "allow-two-hop-tree-within-budget", "{")
	if got := scDerived(t, dir, "allow-two-hop-tree-within-budget"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}

func TestBudgetLineageDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), blDir)
	copyTree(t, corpusPath(blDir), copied)
	path := filepath.Join(copied, corpusreaders.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"lineage_held"`, `"lineage_held "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("want a corpusDigest finding")
	}
}
