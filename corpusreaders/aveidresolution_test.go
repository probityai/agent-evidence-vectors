package corpusreaders_test

// The AVE id resolution reader judges each member's tool output against the
// pinned snapshot, so the verdict moves when the output or the snapshot does.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const aveDir = "vectors-ave-id-resolution"

func aveStage(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), aveDir)
	copyTree(t, corpusPath(aveDir), copied)
	return copied
}

func aveWrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAVEIDResolutionCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(aveDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"resolves", "fails", "no-ids"} {
		if counts[verdict] == 0 {
			t.Fatalf("verdict %s has no member: %v", verdict, counts)
		}
	}
}

// An output whose bytes change is a corpus finding (its pinned digest no longer
// holds) and a member finding (its verdict moves): a JSON output naming an id
// the snapshot does not hold fails with id-unknown, not resolves.
func TestAVEIDResolutionVerdictMovesWithTheOutput(t *testing.T) {
	dir := aveStage(t)
	aveWrite(t, dir, "cases/active-resolves-json/output.json", `{"findings":[{"ave_id":"AVE-2099-99999"}]}`)
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if got := scDerived(t, dir, "active-resolves-json"); !strings.Contains(got, "answered fails [id-unknown]") {
		t.Fatalf("want an id-unknown answer, got %q", got)
	}
	if !strings.Contains(strings.Join(result.Findings, "; "), "file digest mismatch") {
		t.Fatalf("want the corpus digest to refuse the changed output, got %v", result.Findings)
	}
}

// A snapshot that is not the pinned bytes cannot judge anything: every member
// answers unreadable and the corpus says which release broke.
func TestAVEIDResolutionTamperedSnapshotIsUnreadable(t *testing.T) {
	dir := aveStage(t)
	aveWrite(t, dir, "snapshots/v1.2.0/ave-records.json", "[]")
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if got := scDerived(t, dir, "active-resolves-json"); !strings.Contains(got, "answered unreadable") {
		t.Fatalf("want an unreadable answer, got %q", got)
	}
	if !strings.Contains(strings.Join(result.Findings, "; "), "v1.2.0") {
		t.Fatalf("want a finding naming the release, got %v", result.Findings)
	}
}

// The places an id is read from, and each rule, as resolve_ids.py reads them.
// Each output replaces the SARIF control's file; the answer the reader gives is
// in the member's finding because the manifest still declares resolves.
func TestAVEIDResolutionReadsIDsWhereTheReferenceDoes(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"a rule id that is not an AVE id is the tool's own": {
			`{"runs":[{"tool":{"driver":{"rules":[{"id":"TOOL-1"}]}},"results":[{"ruleId":"TOOL-1"}]}]}`,
			"answered no-ids []"},
		"a lower-case AVE prefix is still a claim, and malformed": {
			`{"runs":[{"tool":{"driver":{"rules":[{"id":"ave-2026-00001"}]}}}]}`,
			"answered fails [id-malformed]"},
		"properties.ave_id is read whatever its value": {
			`{"runs":[{"results":[{"ruleId":"TOOL-1","properties":{"ave_id":7}}]}]}`,
			"answered fails [id-malformed]"},
		"rule.id is read when ruleId is absent": {
			`{"runs":[{"results":[{"rule":{"id":"AVE-2099-99999"}}]}]}`,
			"answered fails [id-unknown]"},
		"a run declaring another snapshot": {
			`{"runs":[{"properties":{"ave_records_sha256":"00"},"tool":{"driver":{"rules":[{"id":"AVE-2099-99999"}]}}}]}`,
			"answered fails [id-unknown run-snapshot-differs]"},
		"a JSON key ave_ids in any case, at any depth": {
			`{"a":[{"AVE_IDS":["AVE-2099-99999","x"]}]}`,
			"answered fails [id-malformed id-unknown]"},
		"a JSON output that is not readable": {
			`{`, "answered unreadable []"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := aveStage(t)
			aveWrite(t, dir, "cases/active-resolves-sarif/output.sarif", c.body)
			if got := scDerived(t, dir, "active-resolves-sarif"); !strings.Contains(got, c.want) {
				t.Fatalf("want %q, got %q", c.want, got)
			}
		})
	}
}
