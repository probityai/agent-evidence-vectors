package corpora_test

import "testing"

func TestPaymentMandateCommittedCorpusIsClean(t *testing.T) {
	rcCommittedCorpusIsClean(t, "vectors-agent-payment-mandate", 4, 11)
}

func TestPaymentMandateReaderDerivesRatherThanEchoes(t *testing.T) {
	rcReaderDerivesRatherThanEchoes(t, "vectors-agent-payment-mandate")
}
