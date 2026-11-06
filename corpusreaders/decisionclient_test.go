package corpusreaders_test

// The decision-client reader derives every decision from the record alone.
// Swapping one member's record for another's must move the derived decision,
// and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const dcDir = "vectors-decision-client-failure-modes"

func dcStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dcDir)
	copyTree(t, corpusPath(dcDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func dcRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(dcDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestDecisionClientCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(dcDir))
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

// Each denied member forces one check; staging its record where the conforming
// control sits must move the control's derived decision to deny with that
// member's reason.
func TestDecisionClientEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"reject-contract-id-missing":                  "contract_id_missing",
		"reject-contract-id-unknown":                  "contract_id_unknown",
		"reject-basis-outside-vocabulary":             "record_malformed",
		"reject-status-without-reply":                 "record_malformed",
		"reject-unknown-verdict-read-as-allow":        "condition_misclassified",
		"reject-unknown-verdict-read-as-allow-strict": "condition_misclassified",
		"reject-missing-verdict-read-as-allow":        "condition_misclassified",
		"reject-fault-recorded-as-policy":             "fault_recorded_as_policy",
		"reject-unreachable-allowed":                  "fault_allowed",
		"reject-timeout-allowed":                      "fault_allowed",
		"reject-unparseable-allowed":                  "fault_allowed",
		"reject-unauthorized-allowed":                 "fault_allowed",
		"reject-block-not-followed":                   "verdict_not_followed",
		"reject-allow-recorded-as-fallback":           "verdict_not_followed",
		"reject-halt-not-honoured":                    "halt_not_honoured",
		"reject-halt-claimed-on-block":                "halt_not_honoured",
		"reject-effect-on-deny":                       "effect_on_deny",
	}
	const control = "accept-control-block"
	for from, reason := range denied {
		t.Run(control+" with the record of "+from, func(t *testing.T) {
			dir := dcStage(t, control, dcRead(t, from))
			if got := scDerived(t, dir, control); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied record with an allowed record", func(t *testing.T) {
		dir := dcStage(t, "reject-timeout-allowed", dcRead(t, "accept-timeout--default"))
		if got := scDerived(t, dir, "reject-timeout-allowed"); !strings.Contains(got, "derived allow/decision_sound") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

// A boolean is not a number: a status of true or a timeout of true is a
// malformed record, as the Python reader reads it.
func TestDecisionClientBooleansAreNotNumbers(t *testing.T) {
	cases := map[string][2]string{
		"httpStatus true":    {"accept-control-block", `"httpStatus": 200`},
		"timeoutMillis true": {"accept-control-block", `"timeoutMillis": 1000`},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			body := dcRead(t, edit[0])
			if !strings.Contains(body, edit[1]) {
				t.Fatalf("the control no longer carries %s", edit[1])
			}
			key := strings.SplitN(edit[1], ":", 2)[0]
			dir := dcStage(t, edit[0], strings.Replace(body, edit[1], key+": true", 1))
			if got := scDerived(t, dir, edit[0]); !strings.Contains(got, "derived deny/record_malformed") {
				t.Fatalf("want record_malformed, got %q", got)
			}
		})
	}
}

func TestDecisionClientUnreadableInputsAreFindings(t *testing.T) {
	dir := dcStage(t, "accept-control-allow", "{")
	if got := scDerived(t, dir, "accept-control-allow"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	dir = dcStage(t, "accept-control-allow", "[]")
	if got := scDerived(t, dir, "accept-control-allow"); !strings.Contains(got, "not a JSON object") {
		t.Fatalf("want a not-an-object finding, got %q", got)
	}
}

func TestDecisionClientDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), dcDir)
	copyTree(t, corpusPath(dcDir), copied)
	path := filepath.Join(copied, corpusreaders.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"decision_sound"`, `"decision_sound "`, 1)
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
	if err := os.WriteFile(path, []byte(`{"suite":"decision-client-failure-modes/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpusreaders.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
