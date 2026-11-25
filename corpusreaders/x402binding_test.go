package corpusreaders_test

import (
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

func TestX402PaymentBindingCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath("vectors-x402-payment-binding"))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["verified/verified"] != 3 || len(result.Members) != 21 {
		t.Fatalf("counts: %v", counts)
	}
	if counts["verified/indeterminate"] == 0 || counts["indeterminate/indeterminate"] == 0 {
		t.Fatalf("case C and case A must both be present: %v", counts)
	}
}

func TestX402PaymentBindingReaderDerivesRatherThanEchoes(t *testing.T) {
	rlReaderDerivesRatherThanEchoes(t, "vectors-x402-payment-binding")
}
