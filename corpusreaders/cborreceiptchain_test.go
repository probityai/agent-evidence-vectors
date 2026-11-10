package corpusreaders_test

// The cbor-receipt-chain reader derives every decision from the stored bytes.
// The committed corpus reaches each check once; the cases below swap one
// member's stream or consumer inputs for another member's, so the derived
// decision moves, and require the reader to report the move. A reader that
// echoed the declared decision passes the committed corpus and fails every
// case here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const crcDir = "vectors-cbor-receipt-chain"

func crcStage(t *testing.T, member, file, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), crcDir)
	copyTree(t, corpusPath(crcDir), copied)
	body, err := os.ReadFile(filepath.Join(copied, "cases", from, file)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, file), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestCborReceiptChainCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(crcDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("corpus findings: %v", result.Findings)
	}
	if len(result.Members) != 18 {
		t.Fatalf("want 18 members judged, got %d", len(result.Members))
	}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
	}
}

func TestCborReceiptChainEachCheckMovesTheVerdict(t *testing.T) {
	const intact = "control-intact-anchored"
	cases := []struct {
		member, file, from, want string
	}{
		{intact, "chain.jsonl", "cut-tail-anchored", "derived contradicted/head_anchor"},
		{intact, "chain.jsonl", "duplicate-line", "derived contradicted/no_duplicate_receipt"},
		{intact, "chain.jsonl", "receipts-swapped", "derived contradicted/chain_order"},
		{intact, "chain.jsonl", "middle-receipt-dropped", "derived contradicted/chain_order"},
		{intact, "chain.jsonl", "signature-flipped", "derived contradicted/signature"},
		{intact, "chain.jsonl", "receipt-malformed", "derived contradicted/receipt_shape"},
		{intact, "chain.jsonl", "embedded-key-unpinned", "derived contradicted/signer_pinned"},
		{intact, "chain.jsonl", "reissued-authorization", "derived contradicted/single_use"},
		{"unanchored-intact", "case.json", intact, "derived supported/receipt_chain_holds"},
		{intact, "case.json", "unanchored-intact", "derived not_established/head_not_anchored"},
		{intact, "case.json", "no-effect-member", "derived not_established/effect_not_recorded"},
		{"restart-hides-lost-tail", "case.json", "restart-honest", "derived not_established/chain_reset"},
	}
	for _, tc := range cases {
		t.Run(tc.member+" with the "+tc.file+" of "+tc.from, func(t *testing.T) {
			dir := crcStage(t, tc.member, tc.file, tc.from)
			got := scDerived(t, dir, tc.member)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want a finding containing %q, got %q", tc.want, got)
			}
		})
	}
}

func TestCborReceiptChainRefusesAChangedProfile(t *testing.T) {
	copied := filepath.Join(t.TempDir(), crcDir)
	copyTree(t, corpusPath(crcDir), copied)
	flipOneByte(t, filepath.Join(copied, "profile.json"))
	result, err := corpusreaders.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	joined := strings.Join(result.Findings, "; ")
	if !strings.Contains(joined, "profile.json does not match its manifest digest") {
		t.Fatalf("want the profile digest finding, got %q", joined)
	}
}
