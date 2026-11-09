package corpusreaders_test

// The execution-billing-finality reader derives every decision from the
// record alone. Swapping one member's record for another's must move the
// derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const ebDir = "vectors-execution-billing-finality"

func ebStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ebDir)
	copyTree(t, corpusPath(ebDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ebRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ebDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestExecutionBillingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(ebDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 21 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] != 6 || counts["deny"] != 15 {
		t.Fatalf("want 6 allow and 15 deny: %v", counts)
	}
}

func TestExecutionBillingEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":                      "contract_id_missing",
		"contract-id-unknown":                      "contract_id_unknown",
		"money-as-boolean":                         "record_malformed",
		"dispatch-state-missing":                   "dispatch_state_missing",
		"dispatch-state-null":                      "dispatch_state_missing",
		"external-effect-established":              "claim_boundary_dropped",
		"claim-boundary-dropped":                   "claim_boundary_dropped",
		"reopen-changed-state":                     "reopen_changed_state",
		"f04-invoice-implies-execution":            "execution_outcome_without_observation",
		"f01-success-releases-reservation":         "held_released_before_final_billing",
		"f03-guard-removed-redispatch":             "same_attempt_redispatched",
		"f04-final-billing-redispatch":             "same_attempt_redispatched",
		"x1-invoice-opens-dispatch":                "same_attempt_redispatched",
		"x1-dispatch-state-reserved-after-invoice": "dispatch_state_reserved_after_billing",
		"x1-invoice-replay-refinalized":            "invoice_replay_refinalized",
	}
	for from, reason := range denied {
		t.Run("allow-x1-invoice-before-dispatch with the record of "+from, func(t *testing.T) {
			dir := ebStage(t, "allow-x1-invoice-before-dispatch", ebRead(t, from))
			if got := scDerived(t, dir, "allow-x1-invoice-before-dispatch"); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := ebStage(t, "x1-dispatch-state-reserved-after-invoice", ebRead(t, "allow-x1-invoice-before-dispatch"))
		if got := scDerived(t, dir, "x1-dispatch-state-reserved-after-invoice"); !strings.Contains(got, "derived allow/finality_held") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestExecutionBillingIntegerIsNotABooleanReturn(t *testing.T) {
	body := strings.Replace(ebRead(t, "allow-x1-invoice-before-dispatch"), `"dispatchAllowed": false`, `"dispatchAllowed": 0`, 1)
	dir := ebStage(t, "allow-x1-invoice-before-dispatch", body)
	if got := scDerived(t, dir, "allow-x1-invoice-before-dispatch"); !strings.Contains(got, "derived deny/record_malformed") {
		t.Fatalf("want a derived deny/record_malformed, got %q", got)
	}
	dir = ebStage(t, "allow-x1-invoice-before-dispatch", "{")
	if got := scDerived(t, dir, "allow-x1-invoice-before-dispatch"); !strings.Contains(got, "derived deny/record_malformed") {
		t.Fatalf("an unparseable record must derive deny/record_malformed, got %q", got)
	}
}

func TestExecutionBillingDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), ebDir)
	copyTree(t, corpusPath(ebDir), copied)
	path := filepath.Join(copied, corpusreaders.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"finality_held"`, `"finality_held "`, 1)
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
