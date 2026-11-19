package corpusreaders_test

// The lifecycle-binding reader derives every decision and reason from the
// record bytes alone. Swapping the control member's record for a refusing
// member's must move the derived verdict to that member's own, so a reader
// missing the rule that refuses it fails here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const lbDir = "vectors-lifecycle-binding"

func lbStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), lbDir)
	copyTree(t, corpusPath(lbDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func lbRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(lbDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestLifecycleBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(lbDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"satisfied", "failure", "missing", "not_evaluated", "indeterminate", "refused"} {
		if counts[verdict] == 0 {
			t.Fatalf("every decision must be present: %v", counts)
		}
	}
}

// Each refusing member carries one rule's evidence; the control is a satisfied
// member, so its record under the control's id must derive the refusing verdict.
func TestLifecycleBindingEachRuleMovesTheVerdict(t *testing.T) {
	control := "shape-complete"
	rules := map[string]string{
		"shape-no-execution":                       "missing/missing",
		"shape-no-control":                         "not_evaluated/not_evaluated",
		"shape-no-decision":                        "missing/missing",
		"shape-authorized-differs-from-executed":   "failure/failure",
		"shape-broken-decision":                    "failure/failure",
		"shape-broken-control":                     "failure/failure",
		"shape-broken-execution":                   "failure/failure",
		"shape-revoked-governor":                   "not_evaluated/not_evaluated",
		"scope-v1-cross-instruction":               "not_evaluated/not_evaluated",
		"scope-v2-receiver-disagrees":              "failure/failure",
		"scope-v3-duplicate-execution-identity":    "indeterminate/indeterminate",
		"scope-v3b-duplicate-identity-reordered":   "indeterminate/indeterminate",
		"scope-v4-revoked-executor":                "not_evaluated/not_evaluated",
		"scope-v5-unbound-key":                     "failure/failure",
		"scope-v6-unsigned-valid-self-hash":        "failure/failure",
		"scope-v8-duplicate-identity-other-action": "indeterminate/indeterminate",
		"tag-a1-hashed-under-another-type-tag":     "failure/failure",
		"tag-a2-decision-retyped-as-execution":     "failure/failure",
		"tag-a3-decision-signature-on-control":     "failure/failure",
		"tag-a5-untagged-pre-image":                "failure/failure",
		"tag-a6-unregistered-type":                 "refused/unregistered_tag",
		"tag-a7-case-folded-type":                  "refused/unregistered_tag",
		"tag-a8-crlf-separator":                    "failure/failure",
		"tag-a8-double-lf-separator":               "failure/failure",
		"tag-a9-other-version":                     "refused/unregistered_tag",
		"tag-a9-body-rewritten-after-signing":      "failure/failure",
		"tag-a11b-other-suite-in-pre-image":        "failure/failure",
		"tag-cross-format-dsse-pae-replayed":       "failure/failure",
		"json-duplicate-after-escape":              "refused/no_duplicate_member",
		"json-lone-surrogate":                      "refused/record_shape",
		"json-number-overflow":                     "refused/record_shape",
		"json-unsafe-integer":                      "refused/record_shape",
	}
	for from, want := range rules {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			dir := lbStage(t, control, lbRead(t, from))
			wantText := "derived " + want + ", the manifest declares satisfied/satisfied"
			if got := scDerived(t, dir, control); !strings.Contains(got, wantText) {
				t.Fatalf("want %q, got %q", wantText, got)
			}
		})
	}
}

// A refused or failing member given a satisfied record derives satisfied, so
// the reader is not refusing by member name or by position.
func TestLifecycleBindingSatisfiedRecordsDeriveSatisfied(t *testing.T) {
	for _, from := range []string{"shape-complete", "shape-issuer-only-authorization",
		"shape-two-instructions-both-complete", "scope-c0-honest",
		"tag-a11a-wire-alg-relabelled", "json-negative-zero-admitted"} {
		for _, into := range []string{"shape-broken-control", "json-lone-surrogate"} {
			dir := lbStage(t, into, lbRead(t, from))
			if got := scDerived(t, dir, into); !strings.Contains(got, "derived satisfied/satisfied, the manifest declares") {
				t.Fatalf("%s in %s: want a derived satisfied, got %q", from, into, got)
			}
		}
	}
}

func TestLifecycleBindingUnreadableInputsAreFindings(t *testing.T) {
	dir := lbStage(t, "shape-complete", "{")
	if got := scDerived(t, dir, "shape-complete"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
}

// An empty record set has no group, so it is missing for want of a denominator.
func TestLifecycleBindingEmptySetHasNoDenominator(t *testing.T) {
	body := strings.Replace(lbRead(t, "shape-no-control"), `"records_text": "`, `"records_text": "[]", "x": "`, 1)
	dir := lbStage(t, "shape-complete", body)
	if got := scDerived(t, dir, "shape-complete"); !strings.Contains(got, "derived missing/empty_denominator") {
		t.Fatalf("want empty_denominator, got %q", got)
	}
}
