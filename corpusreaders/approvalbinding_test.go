package corpora_test

// The approval-binding reader derives every decision from the record and the
// used bytes. Swapping one member's record or bytes into the conformant member
// must move the derived decision, and the reader must report the move.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const abDir = "vectors-approval-binding"

func abStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), abDir)
	copyTree(t, corpusPath(abDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func abRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(abDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestApprovalBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(abDir))
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

func TestApprovalBindingEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "approval-id-reused-different-content",
		"approval-already-consumed", "approval-key-not-approvers", "same-client-other-user", "event-differs",
		"phase-differs", "target-differs", "tool-differs", "used-at-expiry", "used-before-issued",
		"release-lookup-unavailable", "release-first-served-after-decision", "release-retired-beyond-grace"}
	for _, from := range denied {
		t.Run("allow-bound with the record of "+from, func(t *testing.T) {
			dir := abStage(t, "allow-bound", "record.json", abRead(t, from, "record.json"))
			if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("allow-bound with mutated bytes", func(t *testing.T) {
		dir := abStage(t, "allow-bound", "payload.bin", abRead(t, "payload-mutated-after-approval", "payload.bin"))
		got := scDerived(t, dir, "allow-bound")
		for _, want := range []string{"derived deny/payload_mismatch", "use matches approval: false"} {
			if !strings.Contains(got, want) {
				t.Fatalf("want %q in %q", want, got)
			}
		}
	})
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := abStage(t, "same-client-other-user", "record.json", abRead(t, "allow-bound", "record.json"))
		if got := scDerived(t, dir, "same-client-other-user"); !strings.Contains(got, "derived allow/bound") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestApprovalBindingUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"use":{"payloadFile":"absent.bin"}}`, "absent.bin cannot be read"},
		{`{"decisionTime":"soon","use":{"payloadFile":"payload.bin"}}`, "does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := abStage(t, "allow-bound", "record.json", []byte(tc.body))
			if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}

func TestApprovalBindingRenewalChecksNameTheirOwnReason(t *testing.T) {
	reasons := map[string]string{
		"approval-reused-after-renewal":                   "approval_superseded",
		"approval-renewal-transition-not-accepted":        "renewal_transition_missing",
		"approval-renewal-decision-not-distinct":          "renewal_binding_invalid",
		"approval-renewal-predecessor-decision-not-cited": "renewal_binding_invalid",
		"approval-renewal-bounds-differ":                  "renewal_binding_invalid",
		"approval-renewal-reopens-consumed-effect":        "effect_already_closed",
		"approval-renewal-reopens-uncertain-effect":       "effect_already_closed",
		"approval-renewal-accepted-after-use":             "renewal_transition_missing",
		"approval-renewal-predecessor-ambiguous":          "renewal_binding_invalid",
		"approval-use-cites-predecessor":                  "approval_not_cited",
		"approval-use-cites-no-approval":                  "approval_not_cited",
	}
	for from, reason := range reasons {
		t.Run(from, func(t *testing.T) {
			dir := abStage(t, "allow-bound", "record.json", abRead(t, from, "record.json"))
			if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, "derived deny/"+reason+",") {
				t.Fatalf("want derived deny/%s, got %q", reason, got)
			}
		})
	}
	for _, from := range []string{"approval-renewed-same-bounds", "allow-predecessor-before-replacement"} {
		t.Run("a denied record with the record of "+from, func(t *testing.T) {
			dir := abStage(t, "approval-reused-after-renewal", "record.json", abRead(t, from, "record.json"))
			if got := scDerived(t, dir, "approval-reused-after-renewal"); !strings.Contains(got, "derived allow/bound") {
				t.Fatalf("want a derived allow, got %q", got)
			}
		})
	}
}

// The ambiguous-predecessor member puts the matching predecessor first, the
// order a reader that takes the first match allows. Moving the conflicting
// record ahead of it must leave the derived verdict where it was.
func TestApprovalBindingAmbiguousPredecessorIgnoresOrder(t *testing.T) {
	const member = "approval-renewal-predecessor-ambiguous"
	body := abRead(t, member, "record.json")
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	presented := record["presentedApprovals"].([]any)
	presented[0], presented[1] = presented[1], presented[0]
	swapped, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	dir := abStage(t, "allow-bound", "record.json", append(swapped, '\n'))
	if got := scDerived(t, dir, "allow-bound"); !strings.Contains(got, "derived deny/renewal_binding_invalid,") {
		t.Fatalf("want derived deny/renewal_binding_invalid with the conflicting record first, got %q", got)
	}
}
