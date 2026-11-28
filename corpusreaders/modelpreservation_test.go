package corpusreaders_test

// The model-preservation reader derives every decision from the stored record and the
// copy. The committed corpus reaches each rule once; the cases below put one member's
// record or case file in another member's place, so the derived decision moves, and
// require the reader to report the move. A reader that echoed the declared decision passes
// the committed corpus and fails each case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const mpDir = "vectors-model-preservation"

func mpStageWithFile(t *testing.T, member, file, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), mpDir)
	copyTree(t, corpusPath(mpDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestModelPreservationCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(mpDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 || len(result.Members) != 21 {
		t.Fatalf("findings %v, members %d", result.Findings, len(result.Members))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestModelPreservationEachRuleMovesTheDecision(t *testing.T) {
	const ref, swap = "reference-copy-matches", "swap-passed"
	cases := []struct{ member, file, from, want string }{
		{ref, "record.dsse.json", "reference-wrong-signer", "derived rejected/signer_not_trusted"},
		{ref, "record.dsse.json", "reference-wrong-signer-names-trusted-keyid", "derived rejected/signature_invalid"},
		{ref, "record.dsse.json", "reference-root-digest-inconsistent", "derived rejected/root_digest_inconsistent"},
		{ref, "record.dsse.json", "reference-record-is-a-swap-record", "derived rejected/unexpected_predicate_type"},
		{ref, "case.json", "reference-recorded-after-withdrawal", "derived not_established/record_after_withdrawal"},
		{ref, "case.json", "reference-copy-file-missing", "derived mismatch/file_missing"},
		{ref, "case.json", "reference-copy-extra-file", "derived mismatch/file_not_in_record"},
		{ref, "copy-model.safetensors", "reference-copy-file-tampered", "derived mismatch/file_digest_mismatch"},
		{"reference-gated-pointer-matches", "copy-model.safetensors", "reference-copy-file-tampered", "derived mismatch/file_digest_mismatch"},
		{"reference-copy-file-tampered", "record.dsse.json", "reference-record-digest-tampered", "derived rejected/signature_invalid"},
		{swap, "record.dsse.json", "swap-failed-test", "derived failed/swap_failed_test"},
		{swap, "record.dsse.json", "swap-verdict-tampered", "derived rejected/signature_invalid"},
		{swap, "record.dsse.json", "swap-wrong-signer", "derived rejected/signer_not_trusted"},
		{swap, "record.dsse.json", "swap-signed-by-another-trusted-party", "derived rejected/signer_not_swapper"},
		{swap, "record.dsse.json", "swap-passed-hosted-old-model", "derived verified/swap_passed_old_model_unproven"},
		{swap, "record.dsse.json", "swap-old-model-not-identified", "derived not_established/old_model_not_identified"},
		{swap, "record.dsse.json", "swap-test-set-not-required", "derived mismatch/test_set_not_required"},
		{swap, "case.json", "swap-deployed-model-differs", "derived mismatch/deployed_model_not_swapped_in"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := mpStageWithFile(t, tc.member, tc.file, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
