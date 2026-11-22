package corpusreaders_test

// The print-witness reader derives every decision from the job file and the
// signed log. The committed corpus reaches each check once; the cases below
// swap one member's file for another member's, so the derived decision moves,
// and require the reader to report the move. A reader that echoed the declared
// decision passes the committed corpus and fails every case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const pwDir = "vectors-print-witness"

func pwStageWithFile(t *testing.T, member, from, name string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), pwDir)
	copyTree(t, corpusPath(pwDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, name)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestPrintWitnessCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(pwDir))
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

func TestPrintWitnessEachCheckMovesTheVerdict(t *testing.T) {
	cases := []struct {
		member, from, file, want string
	}{
		{"log-stops-early", "intact", "log.jsonl", "derived verified/print_witnessed"},
		{"intact", "log-stops-early", "log.jsonl", "derived rejected/log_truncated"},
		{"intact", "log-closes-early", "log.jsonl", "derived rejected/print_not_finished"},
		{"intact", "gcode-changed-after-signing", "job.gcode", "derived rejected/gcode_altered"},
		{"intact", "witness-changed-mid-print", "log.jsonl", "derived rejected/witness_changed"},
		{"intact", "log-from-other-print", "log.jsonl", "derived rejected/job_mismatch"},
		{"intact", "log-reordered", "log.jsonl", "derived rejected/chain_link_broken"},
		{"intact", "log-without-intake", "log.jsonl", "derived rejected/intake_missing"},
		{"intact", "untrusted-witness", "log.jsonl", "every log signature verifies: false"},
		{"log-record-edited", "intact", "log.jsonl", "every log signature verifies: true"},
		{"witness-changed-mid-print", "intact-other-witness", "log.jsonl", "derived verified/print_witnessed"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := pwStageWithFile(t, tc.member, tc.from, tc.file)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

// The order check reads the consumer's own digest, not the log: a case whose
// order names another job file is refused although its log and file agree.
func TestPrintWitnessOrderIsTheConsumersInput(t *testing.T) {
	dir := pwStageWithFile(t, "intact", "gcode-not-ordered", "job.gcode")
	other, err := os.ReadFile(filepath.Join(dir, "cases", "gcode-not-ordered", "log.jsonl")) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cases", "intact", "log.jsonl"), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scDerived(t, dir, "intact"); !strings.Contains(got, "derived rejected/gcode_not_ordered") {
		t.Fatalf("want gcode_not_ordered, got %q", got)
	}
}
