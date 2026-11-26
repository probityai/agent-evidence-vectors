package corpusreaders

import "testing"

// The audit-record and control-decision members are DSSE envelopes signed with
// keys this repository does not hold, so the corpus rewrite in
// identifierhost_test.go reaches only the type their manifests name. The record
// side of the same comparison is tested here, on the functions that make it.

const (
	ihPath = "agent-evidence-vectors/predicate/v1/"
	ihOld  = "https://probityai.github.io/"
	ihNew  = "https://probityai.org/"
	ihNear = "http://probityai.org/"
)

func TestControlDecisionStatementReadsBothHostSpellings(t *testing.T) {
	expected := ihOld + ihPath + "control-decision"
	for _, c := range []struct {
		statementType string
		ok            bool
	}{
		{ihOld + ihPath + "control-decision", true},
		{ihNew + ihPath + "control-decision", true},
		{ihNear + ihPath + "control-decision", false},
		{ihNew + ihPath + "control-decision-v2", false},
	} {
		payload := []byte(`{"_type":"` + cdStatementType + `","predicateType":"` + c.statementType +
			`","subject":[{}],"predicate":{"input":{},"policy":{},"interventionPoint":"pre-tool"}}`)
		for _, want := range []string{expected, ihNew + ihPath + "control-decision"} {
			if _, _, ok := cdStatement(payload, want); ok != c.ok {
				t.Errorf("statement type %q against %q: ok=%t, want %t", c.statementType, want, ok, c.ok)
			}
		}
	}
}

func TestAuditRecordStatementRuleReadsBothHostSpellings(t *testing.T) {
	v1 := ihOld + ihPath + "agent-audit-record"
	for _, c := range []struct {
		statementType string
		ok            bool
	}{
		{v1, true},
		{ihNew + ihPath + "agent-audit-record", true},
		{ihNear + ihPath + "agent-audit-record", false},
		{"https://www.probityai.org/" + ihPath + "agent-audit-record", false},
	} {
		for _, configured := range []string{v1, ihNew + ihPath + "agent-audit-record"} {
			state := &arState{statement: map[string]any{"_type": arStatementType, "predicateType": c.statementType}}
			err := arRules(configured)[0].check(state)
			if (err == nil) != c.ok {
				t.Errorf("statement type %q under %q: %v, want ok=%t", c.statementType, configured, err, c.ok)
			}
		}
	}
	// The v2 input set follows the configured type under either spelling, and
	// only under the v2 URI.
	base := []string{"x"}
	for _, v2 := range []string{arPredicateTypeV2, ihNew + "agent-evidence-vectors/predicate/v2/agent-audit-record"} {
		if got := arInputsUnder(v2, base); len(got) != len(base)+len(arV2Inputs) {
			t.Errorf("%q does not select the v2 inputs: %v", v2, got)
		}
	}
	if got := arInputsUnder(ihNear+"agent-evidence-vectors/predicate/v2/agent-audit-record", base); len(got) != 1 {
		t.Errorf("a near spelling of the v2 URI selected the v2 inputs: %v", got)
	}
}
