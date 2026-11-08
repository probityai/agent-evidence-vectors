package corpusreaders_test

// The approval-binding v2 reader derives every decision from the record and
// recomputes every digest. Swapping one member's record into another must move
// the derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const ab2Dir = "vectors-approval-binding-v2"

func ab2Stage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ab2Dir)
	copyTree(t, corpusPath(ab2Dir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ab2Read(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ab2Dir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestApprovalBindingV2CommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(ab2Dir))
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

// One denied member per check, each swapped into the conformant member.
func TestApprovalBindingV2EachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{
		"contract-id-missing", "contract-id-v1", "malformed-number-not-integer", "malformed-time-not-utc",
		"malformed-witness-sequence-gap", "consumption-ledger-not-read", "delegation-removes-approver",
		"approval-for-another-proposal", "approver-named-only-in-body", "body-claim-differs-from-authenticated",
		"approval-signed-under-another-key", "approver-not-in-policy", "proposer-approves-through-delegate",
		"delegate-and-delegator-both-counted", "conflicting-approvers-both-counted", "reject-counted-as-approval",
		"reject-at-consumption-instant-vetoes", "one-approval-of-two", "approval-covers-bytes-never-shown",
		"resume-field-replaces-args", "validator-rewrites-after-approval", "transform-none-changes-digest",
		"approval-from-another-run", "dispatched-at-expiry", "approval-issued-after-consumption",
		"quorum-reached-at-timeout", "same-approval-resent", "double-submit-with-fresh-approval",
		"worker-consumed-its-own-approvals", "witness-records-another-execution",
		"witness-saw-consumption-after-dispatch", "failed-outcome-approval-spent",
	}
	for _, from := range denied {
		t.Run("allow-two-of-three-distinct with the record of "+from, func(t *testing.T) {
			dir := ab2Stage(t, "allow-two-of-three-distinct", ab2Read(t, from))
			if got := scDerived(t, dir, "allow-two-of-three-distinct"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := ab2Stage(t, "same-approval-resent", ab2Read(t, "allow-two-of-three-distinct"))
		if got := scDerived(t, dir, "same-approval-resent"); !strings.Contains(got, "derived allow/quorum_bound") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

// A digest in the record is a claim: editing the shown arguments without
// recomputing anything must be refused, because the reader recomputes.
func TestApprovalBindingV2RecomputesDigests(t *testing.T) {
	body := strings.Replace(string(ab2Read(t, "allow-two-of-three-distinct")),
		`"amountCents": 2000`, `"amountCents": 2001`, 1)
	dir := ab2Stage(t, "allow-two-of-three-distinct", []byte(body))
	if got := scDerived(t, dir, "allow-two-of-three-distinct"); !strings.Contains(got, "derived deny/") {
		t.Fatalf("an edited argument passed: %q", got)
	}
}

func TestApprovalBindingV2UnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{"[]", "derived deny/malformed_record"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v2"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := ab2Stage(t, "allow-two-of-three-distinct", []byte(tc.body))
			if got := scDerived(t, dir, "allow-two-of-three-distinct"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
