package corpusreaders_test

// The attenuated-delegation reader derives every decision from the record and
// recomputes every grant digest. Swapping one member's record into another
// must move the derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const attnDir = "vectors-attenuated-delegation"

const attnControl = "allow-equal-scope-hop"

func attnStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), attnDir)
	copyTree(t, corpusPath(attnDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func attnRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(attnDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAttenuatedDelegationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(attnDir))
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

func TestAttenuatedDelegationEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":             "contract_id_missing",
		"contract-id-unknown":             "contract_id_unknown",
		"malformed-constraint-two-kinds":  "malformed_record",
		"parent-digest-names-other-grant": "chain_unlinked",
		"root-issuer-untrusted":           "root_untrusted",
		"child-issued-by-parent-issuer":   "issuer_not_parent_holder",
		"hop-kind-forbidden-by-parent":    "hop_kind_not_permitted",
		"depth-one-past-max":              "depth_exceeded",
		"tool-added-by-child":             "tool_widened",
		"closed-world-argument-added":     "constraint_widened",
		"expiry-one-second-later":         "lifetime_extended",
		"caveat-dropped":                  "caveat_dropped",
		"uses-raised":                     "uses_raised",
		"presented-by-parent-holder":      "presenter_not_holder",
		"presented-at-expiry":             "presentation_outside_leaf",
	}
	for from, reason := range denied {
		t.Run(attnControl+" with the record of "+from, func(t *testing.T) {
			dir := attnStage(t, attnControl, attnRead(t, from))
			if got := scDerived(t, dir, attnControl); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := attnStage(t, "uses-raised", attnRead(t, attnControl))
		if got := scDerived(t, dir, "uses-raised"); !strings.Contains(got, "derived allow/attenuated") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

// A one-byte change to the root grant leaves every parentDigest claim in place
// and must still unlink the chain, because the reader recomputes the digest.
func TestAttenuatedDelegationRecomputesGrantDigests(t *testing.T) {
	body := string(attnRead(t, attnControl))
	edited := strings.Replace(body, `"grant-root"`, `"grant-rooT"`, 1)
	if edited == body {
		t.Fatal("the control has no root grant id to edit")
	}
	dir := attnStage(t, attnControl, []byte(edited))
	if got := scDerived(t, dir, attnControl); !strings.Contains(got, "derived deny/chain_unlinked") {
		t.Fatalf("want a derived deny/chain_unlinked, got %q", got)
	}
}

func TestAttenuatedDelegationUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/attenuated-delegation/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := attnStage(t, attnControl, []byte(tc.body))
			if got := scDerived(t, dir, attnControl); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
