package corpusreaders_test

// The evidence-state reader derives every decision from the record alone.
// Swapping the control's record for a denied member's must move the decision.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const esDir = "vectors-evidence-state"

func esStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), esDir)
	copyTree(t, corpusPath(esDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func esRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(esDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestEvidenceStateCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(esDir))
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

func TestEvidenceStateEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"reject-contract-id-missing", "reject-contract-id-unknown",
		"reject-record-malformed", "reject-state-unregistered",
		"reject-pathway-without-propagation", "reject-propagation-without-anomaly",
		"reject-verified-containment-unrecorded", "reject-clean-without-coverage",
		"reject-es3-below-threshold", "reject-es6-containment-unverified",
		"reject-es8-containment-unrecorded", "reject-es1-with-anomaly",
		"reject-es2-with-propagation", "reject-es6-with-external-effects"}
	for _, from := range denied {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := esStage(t, "allow-es1", esRead(t, from))
			if got := scDerived(t, dir, "allow-es1"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	dir := esStage(t, "reject-clean-without-coverage", esRead(t, "allow-es1"))
	if got := scDerived(t, dir, "reject-clean-without-coverage"); !strings.Contains(got, "derived allow/state_supported") {
		t.Fatalf("want a derived allow, got %q", got)
	}
}

func TestEvidenceStateMalformedShapesAreDenied(t *testing.T) {
	control := esRead(t, "allow-es2")
	edits := map[string]string{
		"a non-text contract":      strings.Replace(control, `"contractId": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/evidence-state"`, `"contractId": 7`, 1),
		"a fractional count":       strings.Replace(control, `"anomaliesRecorded": 1`, `"anomaliesRecorded": 1.0`, 1),
		"a zero threshold":         strings.Replace(control, `"changeThreshold": 5`, `"changeThreshold": 0`, 1),
		"a flag that is not true":  strings.Replace(control, `"coverageMeasured": true`, `"coverageMeasured": 1`, 1),
		"an empty system":          strings.Replace(control, `"system": "agent-system-1"`, `"system": ""`, 1),
		"an extra member":          strings.Replace(control, `"system": "agent-system-1"`, `"system": "agent-system-1", "extra": 1`, 1),
		"observations not a table": strings.Replace(control, `"observations": {`, `"observations": [], "o": {`, 1),
	}
	for name, body := range edits {
		t.Run(name, func(t *testing.T) {
			if body == control {
				t.Fatal("the edit did not apply")
			}
			dir := esStage(t, "allow-es2", body)
			if got := scDerived(t, dir, "allow-es2"); !strings.Contains(got, "derived deny/record_malformed") {
				t.Fatalf("want record_malformed, got %q", got)
			}
		})
	}
}

func TestEvidenceStateUnreadableInputsAreFindings(t *testing.T) {
	for body, want := range map[string]string{"{": "record.json does not parse", "[]": "not a JSON object"} {
		dir := esStage(t, "allow-es1", body)
		if got := scDerived(t, dir, "allow-es1"); !strings.Contains(got, want) {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
}
