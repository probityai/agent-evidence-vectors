package corpusreaders_test

// The revocation-epoch reader derives every decision from the record. Swapping
// one member's record into another must move the derived decision, and the
// reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const reDir = "vectors-revocation-epoch"

func reStage(t *testing.T, member string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), reDir)
	copyTree(t, corpusPath(reDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func reRead(t *testing.T, member string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(reDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRevocationEpochCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(reDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		for _, m := range result.Members {
			for _, f := range m.Findings {
				t.Errorf("%s: %s", m.ID, f)
			}
		}
		t.Fatalf("findings: %v", result.Findings)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestRevocationEpochEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":                           "contract_id_missing",
		"contract-id-unknown":                           "contract_id_unknown",
		"malformed-epoch-not-integer":                   "malformed_record",
		"srl-issuer-untrusted":                          "srl_issuer_untrusted",
		"grant-binding-permit-names-other-grant":        "grant_binding_mismatch",
		"epoch-rolled-back-in-witness-log":              "srl_epoch_not_monotonic",
		"srl-absent-at-effect":                          "srl_absent",
		"srl-epoch-unknown-at-permit":                   "srl_digest_mismatch",
		"srl-stale-permit-backdated":                    "srl_stale_at_permit",
		"revoked-at-permit-authority-key":               "revoked_at_permit",
		"effect-after-revocation-dropped-in-later-list": "effect_after_revocation",
		"ambiguous-witness-log-gap":                     "revocation_order_ambiguous",
		"effect-epoch-behind":                           "effect_epoch_behind",
		"srl-stale-at-effect-backdated":                 "srl_stale_at_effect",
	}
	for from, reason := range denied {
		t.Run("allow-other-grant-revoked with the record of "+from, func(t *testing.T) {
			dir := reStage(t, "allow-other-grant-revoked", reRead(t, from))
			if got := scDerived(t, dir, "allow-other-grant-revoked"); !strings.Contains(got, "derived deny/"+reason+",") {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied record with the conformant record", func(t *testing.T) {
		dir := reStage(t, "revoked-at-permit-grant", reRead(t, "allow-other-grant-revoked"))
		if got := scDerived(t, dir, "revoked-at-permit-grant"); !strings.Contains(got, "derived allow/not_revoked") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
	t.Run("an enforced refusal is its own allow reason", func(t *testing.T) {
		dir := reStage(t, "allow-other-grant-revoked", reRead(t, "allow-revoked-in-flight-refused-at-effect"))
		if got := scDerived(t, dir, "allow-other-grant-revoked"); !strings.Contains(got, "derived allow/revocation_enforced_at_effect") {
			t.Fatalf("want the enforced allow, got %q", got)
		}
	})
}

// An edit to what a list revokes changes the list's digest, so a permit that
// names the old digest names no list: the reader recomputes the digest rather
// than trusting the one the permit carries.
func TestRevocationEpochRecomputesListDigests(t *testing.T) {
	body := strings.Replace(string(reRead(t, "allow-empty-list-epoch-1")), `"revoked": []`,
		`"revoked": ["key:agent-9"]`, 1)
	dir := reStage(t, "allow-empty-list-epoch-1", []byte(body))
	if got := scDerived(t, dir, "allow-empty-list-epoch-1"); !strings.Contains(got, "derived deny/srl_digest_mismatch") {
		t.Fatalf("want srl_digest_mismatch, got %q", got)
	}
}

func TestRevocationEpochUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"x"}`, "derived deny/contract_id_unknown"},
		{`{"contractId":"` + "https://probityai.github.io/agent-evidence-vectors/contract/revocation-epoch/v1" + `"}`,
			"derived deny/malformed_record"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := reStage(t, "allow-other-grant-revoked", []byte(tc.body))
			if got := scDerived(t, dir, "allow-other-grant-revoked"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}
