package corpusreaders_test

// The grant-use reader derives every decision from the record. Swapping one
// member's record into another must move the derived decision, and the reader
// must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const guDir = "vectors-grant-use"

func guStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), guDir)
	copyTree(t, corpusPath(guDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func guRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(guDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestGrantUseCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(guDir))
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
var guDeniedByCheck = []string{
	"contract-id-missing", "contract-id-unknown", "malformed-call-missing", "chain-parent-digest-stale",
	"widened-range", "use-at-leaf-expiry", "tool-not-in-leaf", "call-args-not-the-effects",
	"arg-above-range", "permit-not-minted", "uses-beyond-max", "permit-for-parent-grant",
	"permit-not-from-holder", "permit-authority-unknown", "authority-key-in-worker",
	"permit-expired-at-effect", "permit-reused", "permit-run-differs",
	"effect-args-differ-from-permit", "effect-grant-unlinked", "witness-log-gap",
}

func TestGrantUseEachCheckMovesTheVerdict(t *testing.T) {
	for _, from := range guDeniedByCheck {
		t.Run("allow-two-hop-attenuated with the record of "+from, func(t *testing.T) {
			dir := guStage(t, "allow-two-hop-attenuated", guRead(t, from))
			if got := scDerived(t, dir, "allow-two-hop-attenuated"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := guStage(t, "permit-reused", guRead(t, "allow-two-hop-attenuated"))
		if got := scDerived(t, dir, "permit-reused"); !strings.Contains(got, "derived allow/authorized_use") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

// A digest field is a claim: editing a constraint in the root grant without
// touching any digest field must break the chain, because the reader recomputes
// the digest the child names.
func TestGrantUseRecomputesDigests(t *testing.T) {
	body := strings.Replace(string(guRead(t, "allow-two-hop-attenuated")), "\"prefix\": \"ord-\"",
		"\"prefix\": \"or\"", 1)
	dir := guStage(t, "allow-two-hop-attenuated", []byte(body))
	if got := scDerived(t, dir, "allow-two-hop-attenuated"); !strings.Contains(got, "derived deny/grant_chain_broken") {
		t.Fatalf("want a broken chain, got %q", got)
	}
}

func TestGrantUseUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/grant-use/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := guStage(t, "allow-two-hop-attenuated", []byte(tc.body))
			if got := scDerived(t, dir, "allow-two-hop-attenuated"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
