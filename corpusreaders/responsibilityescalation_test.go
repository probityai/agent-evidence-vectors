package corpusreaders_test

// The responsibility-escalation reader derives every outcome from the record
// alone. Swapping one member's record for another's must move the outcome.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const resDir = "vectors-responsibility-escalation"

func resStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), resDir)
	copyTree(t, corpusPath(resDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func resRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(resDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestResponsibilityEscalationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(resDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 9 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	want := map[string]int{"established": 2, "not_established": 2, "partial": 4, "unresolved": 1}
	for verdict, n := range want {
		if counts[verdict] != n {
			t.Fatalf("verdict %s: want %d, got %v", verdict, n, counts)
		}
	}
}

func TestResponsibilityEscalationEachRecordMovesTheOutcome(t *testing.T) {
	control := "h09-clean-path-closed-on-time"
	others := map[string]string{
		"h02-referral-without-receipt":                  "derived partial/receipt_not_evidenced",
		"h03-acknowledged-without-acceptance":           "derived partial/acceptance_not_evidenced",
		"h04-unanswered-escalation":                     "derived unresolved/escalation_unanswered",
		"h05-reference-unavailable":                     "derived not_established/reference_unavailable",
		"h06-authority-narrowed-before-acknowledgement": "derived partial/authority_narrowed_before_acknowledgement",
		"h07-current-record-resolved":                   "derived not_established/current_record_resolved_not_decision_time",
		"h08-acknowledged-outside-role":                 "derived partial/acknowledged_outside_designated_role",
		"h01-authority-narrowed-after-decision":         "derived established/authority_held_at_decision_time",
	}
	for from, want := range others {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := resStage(t, control, resRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, want) {
				t.Fatalf("want %q, got %q", want, got)
			}
		})
	}
	dir := resStage(t, "h02-referral-without-receipt", resRead(t, control))
	if got := scDerived(t, dir, "h02-referral-without-receipt"); !strings.Contains(got, "derived established/closed_as_accepted") {
		t.Fatalf("want a derived established, got %q", got)
	}
}

func TestResponsibilityEscalationClosureIsHeldToItsRole(t *testing.T) {
	control := "h09-clean-path-closed-on-time"
	body := strings.Replace(resRead(t, control), `"by": "hiring-manager",
        "evidenced": true
      },
      "receipt"`, `"by": "recruiter",
        "evidenced": true
      },
      "receipt"`, 1)
	if body == resRead(t, control) {
		t.Fatal("the closure slot was not found in the record")
	}
	dir := resStage(t, control, body)
	if got := scDerived(t, dir, control); !strings.Contains(got, "derived partial/closed_outside_designated_role") {
		t.Fatalf("want closed_outside_designated_role, got %q", got)
	}
}

func TestResponsibilityEscalationUnreadableInputsAreFindings(t *testing.T) {
	dir := resStage(t, "h09-clean-path-closed-on-time", "{")
	if got := scDerived(t, dir, "h09-clean-path-closed-on-time"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}
