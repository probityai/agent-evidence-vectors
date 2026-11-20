package corpusreaders_test

import (
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

func TestX402EvidenceJoinCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath("vectors-x402-evidence-join"))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["accepted"] != 3 || counts["rejected"] != 11 || counts["indeterminate"] != 3 {
		t.Fatalf("counts: %v", counts)
	}
}

func TestX402EvidenceJoinReaderDerivesRatherThanEchoes(t *testing.T) {
	rlReaderDerivesRatherThanEchoes(t, "vectors-x402-evidence-join")
}
