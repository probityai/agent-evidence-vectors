package observedeffect

import "testing"

// The envelopes in the corpus are signed and this package holds no signing key,
// so the record side of the host rule is tested on the rule itself: a statement
// naming the type under either spelling of our host passes for a policy naming
// it under either, and a near spelling keeps today's refusal.
func TestPredicateTypeRuleReadsBothHostSpellingsAsOneType(t *testing.T) {
	const (
		path    = "agent-evidence-vectors/predicate/v1/observed-effect"
		oldType = "https://probityai.github.io/" + path
		newType = "https://probityai.org/" + path
	)
	cases := []struct {
		statement, policy string
		passes            bool
	}{
		{oldType, oldType, true},
		{newType, oldType, true},
		{oldType, newType, true},
		{newType, newType, true},
		{"http://probityai.org/" + path, oldType, false},
		{"http://probityai.github.io/" + path, oldType, false},
		{"https://www.probityai.org/" + path, oldType, false},
		{"https://probityai.org.example/" + path, newType, false},
		{"", oldType, false},
		{newType, "", false},
	}
	for _, c := range cases {
		got := rulePredicateType(&ctx{stmt: map[string]any{"predicateType": c.statement},
			policy: Policy{PredicateType: c.policy}})
		if (got == nil) != c.passes {
			t.Errorf("statement %q under policy %q: fault %+v, want passes=%t", c.statement, c.policy, got, c.passes)
		}
		if got != nil && got.code != "predicate-type-unexpected" {
			t.Errorf("statement %q under policy %q: code %q", c.statement, c.policy, got.code)
		}
	}
}
