package corpusreaders_test

// The empty-interval reader derives every value from the stored bytes. The committed
// corpus reaches each check once; the cases below swap one file of a member for the same
// file of another, so the derived value moves, and require the reader to report the move.
// A reader that echoed the declared value passes the committed corpus and fails each case
// here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const eiDir = "vectors-empty-interval-statement"

func eiStageWithFiles(t *testing.T, member, from string, files ...string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), eiDir)
	copyTree(t, corpusPath(eiDir), copied)
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copied
}

func TestEmptyIntervalCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(eiDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) == 0 {
		t.Fatal("no members judged")
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestEmptyIntervalEachCheckMovesTheValue(t *testing.T) {
	const clean = "interval-empty-not-recorded"
	// A swapped ledger alone changes the head the checkpoint names, so a ledger that
	// carries a revocation is swapped together with the statement signed over it.
	cases := []struct {
		member, file, from, want string
	}{
		{clean, "ledger.jsonl+statement.json", "statement-omits-recorded-event", "derived recorded/statement_omits_recorded_event"},
		{"interval-holds-revocation", "ledger.jsonl+statement.json", clean, "derived not_recorded/no_revocation_in_covered_interval"},
		{clean, "ledger.jsonl", "event-deleted-from-interval", "derived undetermined/chain_link_broken"},
		{clean, "ledger.jsonl", "event-edited-in-place", "derived undetermined/ledger_event_invalid"},
		{clean, "ledger.jsonl", "ledger-rolled-back-to-abandoned-branch", "derived undetermined/checkpoint_head_mismatch"},
		{clean, "case.json", "cross-federation-unsynchronised", "derived cross_federation_unsynchronised/federation_not_synchronised"},
		{clean, "case.json", "query-failed", "derived query_failed/ledger_query_failed"},
		{clean, "statement.json", "forged-statement-signature", "derived undetermined/statement_signature_invalid"},
		{clean, "statement.json", "statement-for-other-credential", "derived undetermined/statement_for_other_interval"},
		{clean, "statement.json", "forged-checkpoint-signature", "derived undetermined/checkpoint_signature_invalid"},
		{clean, "statement.json", "checkpoint-without-time", "derived undetermined/checkpoint_not_timestamped"},
		{clean, "statement.json", "checkpoint-stops-short", "derived undetermined/checkpoint_does_not_cover_range"},
		{"forged-statement-signature", "statement.json", clean, "statement and checkpoint signatures verify: true/true"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := eiStageWithFiles(t, tc.member, tc.from, strings.Split(tc.file, "+")...)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}
