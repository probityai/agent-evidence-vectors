package corpora_test

// The trace-anchor reader derives every decision from case.json. The committed
// corpus reaches each of the nine checks; the cases below change one field of a
// control member, so the derived decision moves, and require the reader to
// report the move. A reader that echoed the declared decision passes the
// committed corpus and fails every case here.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const taDir = "vectors-trace-anchor"

// taStageEdited copies the corpus and rewrites one member's case.json through
// edit, keeping integers as integer tokens.
func taStageEdited(t *testing.T, member string, edit func(map[string]any)) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), taDir)
	copyTree(t, corpusPath(taDir), copied)
	path := filepath.Join(copied, "cases", member, "case.json")
	body, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var c map[string]any
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	edit(c)
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func taPart(c map[string]any, key string) map[string]any {
	return c[key].(map[string]any)
}

func TestTraceAnchorCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(taDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) != 27 {
		t.Fatalf("judged %d members, the corpus holds 27", len(result.Members))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestTraceAnchorEachCheckMovesTheVerdict(t *testing.T) {
	otherRoot := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name, member string
		edit         func(map[string]any)
		want         string
	}{
		{"receipt removed", "anchored-one-leaf",
			func(c map[string]any) { delete(c, "receipt") }, "derived refused/receipt_absent"},
		{"leaf index a boolean", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "receipt")["leaf_index"] = true }, "derived refused/receipt_malformed"},
		{"leaf index a float token", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "receipt")["leaf_index"] = json.Number("0.0") },
			"derived refused/receipt_malformed"},
		{"entry removed", "anchored-one-leaf",
			func(c map[string]any) { delete(c, "entry") }, "derived refused/entry_absent"},
		{"entry batch id empty", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "entry")["batch_id"] = "" }, "derived refused/entry_malformed"},
		{"carried root names another tree", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "receipt")["merkle_root"] = otherRoot },
			"derived refused/receipt_root_mismatch"},
		{"carried count disagrees", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "receipt")["leaf_count"] = json.Number("2") },
			"derived refused/receipt_count_mismatch"},
		{"index past the batch", "anchored-five-leaves-right-edge",
			func(c map[string]any) { taPart(c, "receipt")["leaf_index"] = json.Number("5") },
			"derived refused/index_out_of_range"},
		{"claim carries a float", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "claim")["iat"] = json.Number("1792000000.5") },
			"derived refused/claim_outside_profile"},
		{"claim edited after anchoring", "anchored-one-leaf",
			func(c map[string]any) { taPart(c, "claim")["subject"] = "someone-else" },
			"derived refused/proof_does_not_replay"},
		{"count lie corrected", "receipt-count-lies",
			func(c map[string]any) { taPart(c, "receipt")["leaf_count"] = json.Number("5") },
			"derived anchored/included_link_unchecked"},
		{"proof-only receipt handed no entry", "anchored-proof-only-receipt",
			func(c map[string]any) { delete(c, "entry") }, "derived refused/entry_absent"},
		{"self anchor handed a matching one-leaf entry", "self-anchored-no-entry",
			func(c map[string]any) { c["entry"] = taSelfEntry(c) },
			"derived anchored/included_link_unchecked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := taStageEdited(t, tc.member, tc.edit)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

// A member whose case.json no longer matches its manifest digest is reported,
// so an edit to a committed case cannot pass silently.
func TestTraceAnchorEditedCaseIsReported(t *testing.T) {
	dir := taStageEdited(t, "anchored-one-leaf", func(map[string]any) {})
	got := scDerived(t, dir, "anchored-one-leaf")
	if !strings.Contains(got, "case.json does not match its manifest digest") {
		t.Fatalf("a re-encoded case.json was not reported: %q", got)
	}
}

// taSelfEntry builds the registry entry a self-anchored record would need: a
// one-leaf batch whose root is the root its own receipt carries. Handed that
// entry, the record is anchored, which is why the entry has to come from the
// registry and never from the record's holder.
func taSelfEntry(c map[string]any) map[string]any {
	return map[string]any{
		"ts": "2026-10-15T12:00:00Z", "producer": "trace-gateway/1.0.0", "batch_id": "self",
		"leaf_count": json.Number("1"), "merkle_root": taPart(c, "receipt")["merkle_root"],
	}
}
