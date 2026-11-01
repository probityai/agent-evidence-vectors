package corpora_test

import "testing"

func TestPaymentMandateCommittedCorpusIsClean(t *testing.T) {
	rlCommittedCorpusIsClean(t, "vectors-agent-payment-mandate", 4, 11)
}

func TestPaymentMandateReaderDerivesRatherThanEchoes(t *testing.T) {
	rlReaderDerivesRatherThanEchoes(t, "vectors-agent-payment-mandate")
}
