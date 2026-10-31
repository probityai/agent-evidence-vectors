package corpora

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// arWeakened runs the corpus with a weakened reader and returns the members it
// fails, in manifest order.
func arWeakened(t *testing.T, weaken func() func()) string {
	t.Helper()
	if got := arFailingDraftIDs(t); len(got) != 0 {
		t.Fatalf("the tracked corpus must judge clean first, failing: %v", got)
	}
	restore := weaken()
	defer restore()
	return strings.Join(arFailingDraftIDs(t), ",")
}

func arDropCheck(name string) func() func() {
	return func() func() {
		arConsumptionChecks[name] = false
		return func() { arConsumptionChecks[name] = true }
	}
}

func arDropSetRule(drop string) func() func() {
	return func() func() {
		saved := arSetRules
		var kept []arSetRule
		for _, rule := range saved {
			if rule.name != drop && drop != "" {
				kept = append(kept, rule)
			}
		}
		arSetRules = kept
		claim := arClaimReading["check"]
		if drop == "" {
			arClaimReading["check"] = false
		}
		return func() { arSetRules = saved; arClaimReading["check"] = claim }
	}
}

// arStaleByDigest is the stale-state check keyed on the request digest, as a
// reader that identifies an operation by its content would write it.
func arStaleByDigest(group []map[string]any) bool {
	digests := func(pred map[string]any) map[string]bool {
		out := map[string]bool{}
		held, _ := arConsumptionOf(pred)["held"].([]any)
		for _, item := range held {
			entry, _ := item.(map[string]any)
			digest, _ := entry["requestDigest"].(string)
			out[digest] = true
		}
		return out
	}
	for i, later := range group {
		for j, earlier := range group {
			if i == j || arRevision(later) >= arRevision(earlier) || !arPermitted(later) {
				continue
			}
			seen := digests(later)
			seen[arStr(later, "decision.requestDigest")] = true
			for digest := range digests(earlier) {
				if !seen[digest] {
					return true
				}
			}
		}
	}
	return false
}

// TestAuditRecordConsumptionSentencesAreLoadBearing drops one sentence of the
// consumption rule at a time and requires exactly the members that test it to
// fail; a retry keyed on the request digest fails CS10 and CS12.
func TestAuditRecordConsumptionSentencesAreLoadBearing(t *testing.T) {
	for name, want := range map[string]string{
		"misplaced":      "CS6",
		"reserved":       "CS3",
		"distinct-keys":  "CS13",
		"operation-key":  "CS14",
		"counts":         "CS5",
		"state-revision": "CS9",
		"key-reuse":      "CS10",

		"supersedes-digest": "CS24",
		"supersedes-self":   "CS23",

		"asset-id":        "CS35",
		"asset-decimals":  "CS36",
		"asset-exclusive": "CS37",
	} {
		if got := arWeakened(t, arDropCheck(name)); got != want {
			t.Errorf("without the %s sentence: failing %q, want %q", name, got, want)
		}
	}
	byDigest := func() func() {
		saved := arRetryOf
		arRetryOf = func(held, decision map[string]any) bool {
			return held["requestDigest"] == decision["requestDigest"]
		}
		return func() { arRetryOf = saved }
	}
	if got := arWeakened(t, byDigest); got != "CS10,CS12" {
		t.Errorf("a retry keyed on the request digest: failing %q, want CS10,CS12", got)
	}
}

// TestAuditRecordSetRulesAreLoadBearing: dropping the set checks fails the set
// members that test them, and a stale-state check keyed on the request digest
// fails CS17, the control that proves the check keys on the operation key.
func TestAuditRecordSetRulesAreLoadBearing(t *testing.T) {
	for _, c := range []struct{ drop, want string }{
		{"", "CS7,CS8,CS17,CS20,CS21,CS30,CS31,CS32,CS38,CS39"},
		{"stale-revision", "CS7,CS17,CS21"},
		{"release-unshown", "CS8,CS20,CS30"},
		{"asset-mismatch", "CS38,CS39"},
	} {
		if got := arWeakened(t, arDropSetRule(c.drop)); got != c.want {
			t.Errorf("dropping set check %q: failing %q, want %q", c.drop, got, c.want)
		}
	}
	byDigest := func() func() {
		saved := arSetRules
		arSetRules = append([]arSetRule{{"stale-revision", "consumption-set-stale-revision", arStaleByDigest}}, saved[1:]...)
		return func() { arSetRules = saved }
	}
	if got := arWeakened(t, byDigest); got != "CS17" {
		t.Errorf("stale-state check keyed on the request digest: failing %q, want CS17", got)
	}
}

// TestAuditRecordSetChainJoinIsLoadBearing: reading the set checks per
// limitDigest, a replacement not joining the limit documents it links, fails
// CS20 and CS21 and nothing else.
func TestAuditRecordSetChainJoinIsLoadBearing(t *testing.T) {
	dropJoin := func() func() {
		arSetChainJoin = false
		return func() { arSetChainJoin = true }
	}
	if got := arWeakened(t, dropJoin); got != "CS20,CS21,CS30" {
		t.Errorf("without the chain join: failing %q, want CS20,CS21,CS30", got)
	}
}

// TestAuditRecordSetLedgerBoundaryIsLoadBearing: reading every record as one
// ledger whatever its limit document fails CS25 and nothing else, the control
// that a verifier does not join limit documents no supersedes links.
func TestAuditRecordSetLedgerBoundaryIsLoadBearing(t *testing.T) {
	joinAll := func() func() {
		arSetJoinAll = true
		return func() { arSetJoinAll = false }
	}
	if got := arWeakened(t, joinAll); got != "CS25,CS40" {
		t.Errorf("grouping every record into one ledger: failing %q, want CS25,CS40", got)
	}
}

// TestAuditRecordClaimReadingIsLoadBearing: each reading of the claim check
// fails exactly the members that test it. Without the check a retry presented
// as new passes (CS31, CS32); keyed by the limit document an unlinked limit
// drops the claim (CS32); without the principal and agent key another scope's
// key reads as the same claim (CS33); and a record showing none that does not
// end a claim refuses a legitimate new operation (CS28).
func TestAuditRecordClaimReadingIsLoadBearing(t *testing.T) {
	for _, c := range []struct {
		name  string
		value bool
		want  string
	}{
		{"check", false, "CS31,CS32"},
		{"ledger", true, "CS32"},
		{"scope", false, "CS33"},
		{"release", false, "CS28"},
	} {
		set := func() func() {
			saved := arClaimReading[c.name]
			arClaimReading[c.name] = c.value
			return func() { arClaimReading[c.name] = saved }
		}
		if got := arWeakened(t, set); got != c.want {
			t.Errorf("claim reading %s=%v: failing %q, want %q", c.name, c.value, got, c.want)
		}
	}
}

// TestAuditRecordAssetDecimalsAreLoadBearing: matching an asset by its id alone
// fails CS39 and nothing else.
func TestAuditRecordAssetDecimalsAreLoadBearing(t *testing.T) {
	drop := func() func() {
		arAssetMatchDecimals = false
		return func() { arAssetMatchDecimals = true }
	}
	if got := arWeakened(t, drop); got != "CS39" {
		t.Errorf("an asset matched by its id alone: failing %q, want CS39", got)
	}
}

// arMutated re-encodes the CS1 record with its predicate changed and judges it
// with the signature rule off, so the refusal is the consumption rule's own.
func arMutated(t *testing.T, change func(pred map[string]any)) arReport {
	t.Helper()
	manifest, bodies := arLoad(t)
	for _, v := range manifest.Vectors {
		if v.DraftID != "CS1" {
			continue
		}
		var envelope map[string]any
		if err := json.Unmarshal(bodies[v.ID], &envelope); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var statement map[string]any
		dec := json.NewDecoder(strings.NewReader(string(payload)))
		dec.UseNumber()
		if err := dec.Decode(&statement); err != nil {
			t.Fatal(err)
		}
		change(statement["predicate"].(map[string]any))
		changed, err := json.Marshal(statement)
		if err != nil {
			t.Fatal(err)
		}
		envelope["payload"] = base64.StdEncoding.EncodeToString(changed)
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return arVerify(raw, manifest.PredicateType, manifest.Keys.Observer.PublicKey, "signature")
	}
	t.Fatal("no CS1 member")
	return arReport{}
}

func arConsumptionEntry(pred map[string]any) map[string]any {
	for _, item := range arList(pred, "evaluation.inputs") {
		entry := item.(map[string]any)
		if entry["input"] == arConsumptionInput {
			return entry["consumption"].(map[string]any)
		}
	}
	panic("CS1 carries no consumption entry")
}

// TestAuditRecordConsumptionShapeRefusals covers the refusals no corpus member
// reaches: each one is a shape defect in the consumption member or the key.
func TestAuditRecordConsumptionShapeRefusals(t *testing.T) {
	digest := strings.Repeat("a", 64)
	held := func(extra map[string]any) []any {
		entry := map[string]any{"operationKey": "k", "requestDigest": digest, "amount": json.Number("0")}
		for name, value := range extra {
			if value == nil {
				delete(entry, name)
			} else {
				entry[name] = value
			}
		}
		return []any{entry}
	}
	setHeld := func(extra map[string]any) func(map[string]any) {
		return func(p map[string]any) { arConsumptionEntry(p)["held"] = held(extra) }
	}
	cases := map[string]struct {
		change func(pred map[string]any)
		code   string
	}{
		"empty operation key":      {func(p map[string]any) { arObj(p, "decision")["operationKey"] = "" }, "operation-key-invalid"},
		"numeric operation key":    {func(p map[string]any) { arObj(p, "decision")["operationKey"] = json.Number("7") }, "operation-key-invalid"},
		"extra consumption member": {func(p map[string]any) { arConsumptionEntry(p)["note"] = "x" }, "consumption-malformed"},
		"bad limit digest":         {func(p map[string]any) { arConsumptionEntry(p)["limitDigest"] = "abc" }, "consumption-value-invalid"},
		"empty unit":               {func(p map[string]any) { arConsumptionEntry(p)["unit"] = "" }, "consumption-value-invalid"},
		"held not a list":          {func(p map[string]any) { arConsumptionEntry(p)["held"] = "none" }, "consumption-malformed"},
		"held entry not an object": {func(p map[string]any) { arConsumptionEntry(p)["held"] = []any{"x"} }, "consumption-malformed"},
		"held entry no amount":     {setHeld(map[string]any{"amount": nil}), "member-missing"},
		"held entry extra member":  {setHeld(map[string]any{"note": "x"}), "consumption-malformed"},
		"held entry empty key":     {setHeld(map[string]any{"operationKey": ""}), "consumption-value-invalid"},
		"held entry bad digest":    {setHeld(map[string]any{"requestDigest": "z"}), "consumption-value-invalid"},
		"held entry negative":      {setHeld(map[string]any{"amount": json.Number("-1")}), "consumption-value-invalid"},
	}
	for name, c := range cases {
		if got := arMutated(t, c.change); got.verdict != "malformed" || got.code != c.code {
			t.Errorf("%s: got %s %q, want malformed %q", name, got.verdict, got.code, c.code)
		}
	}
	if got := arMutated(t, func(map[string]any) {}); got.verdict != "valid" {
		t.Errorf("an unchanged CS1 must stay valid, got %s %q", got.verdict, got.code)
	}
}

// TestAuditRecordSetRefusals covers a set no member reaches: an unreadable
// bundle, and a bundle with a record that is itself malformed.
func TestAuditRecordSetRefusals(t *testing.T) {
	manifest, bodies := arLoad(t)
	key := manifest.Keys.Observer.PublicKey
	for name, raw := range map[string]string{"not json": "{", "no records": `{}`} {
		got := arVerifySet([]byte(raw), manifest.PredicateType, key, "")
		if got.joint.verdict != "malformed" || got.joint.codes[0] != "set-unreadable" {
			t.Errorf("%s: got %v, want set-unreadable", name, got.joint)
		}
	}
	if got := arVerifySet([]byte(`{"records":[]}`), manifest.PredicateType, key, ""); got.joint.verdict != "valid" {
		t.Errorf("an empty set judges valid, got %v", got.joint)
	}
	for _, v := range manifest.Vectors {
		if v.DraftID != "CS1" {
			continue
		}
		raw := `{"records":[` + string(bodies[v.ID]) + `,{"payload":"@@"}]}`
		got := arVerifySet([]byte(raw), manifest.PredicateType, key, "")
		if got.joint.verdict != "malformed" || got.joint.codes[0] != "set-record-malformed" {
			t.Errorf("a malformed record: got %v, want set-record-malformed", got.joint)
		}
	}
	if arWithinLimit(map[string]any{}) != nil {
		t.Error("a predicate with no consumption derives no withinLimit")
	}
}
