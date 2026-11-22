package corpusreaders_test

import "testing"

func TestPaymentMandateCommittedCorpusIsClean(t *testing.T) {
	rlCommittedCorpusIsClean(t, "vectors-agent-payment-mandate", 6, 15)
}

func TestPaymentMandateReaderDerivesRatherThanEchoes(t *testing.T) {
	rlReaderDerivesRatherThanEchoes(t, "vectors-agent-payment-mandate")
}
