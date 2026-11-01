package corpora_test

import "testing"

func TestConnectorScopeCommittedCorpusIsClean(t *testing.T) {
	rlCommittedCorpusIsClean(t, "vectors-connector-scope", 4, 9)
}

func TestConnectorScopeReaderDerivesRatherThanEchoes(t *testing.T) {
	rlReaderDerivesRatherThanEchoes(t, "vectors-connector-scope")
}
