package corpora

import "testing"

// arNarrowVocabulary removes one value from a closed set for the test's span.
func arNarrowVocabulary(t *testing.T, path, drop string) func() func() {
	t.Helper()
	return func() func() {
		for i := range arVocabularies {
			if arVocabularies[i].path != path {
				continue
			}
			saved := arVocabularies[i].allowed
			var kept []string
			for _, value := range saved {
				if value != drop {
					kept = append(kept, value)
				}
			}
			arVocabularies[i].allowed = kept
			return func() { arVocabularies[i].allowed = saved }
		}
		t.Fatalf("no %s vocabulary", path)
		return func() {}
	}
}

// TestAuditRecordApiKeyIsForced: a reader whose agent.authentication set lacks
// api-key fails A21 and no other member.
func TestAuditRecordApiKeyIsForced(t *testing.T) {
	got := arWeakened(t, arNarrowVocabulary(t, "agent.authentication", "api-key"))
	if got != "A21" {
		t.Errorf("agent.authentication without api-key: failing %q, want A21", got)
	}
}

// TestAuditRecordSequenceSentencesAreLoadBearing: tolerating a member sequence
// does not define fails SQ2, and admitting a seq below 1 fails SQ3.
func TestAuditRecordSequenceSentencesAreLoadBearing(t *testing.T) {
	for name, want := range map[string]string{"members": "SQ2", "positive": "SQ3"} {
		drop := func() func() {
			arSequenceChecks[name] = false
			return func() { arSequenceChecks[name] = true }
		}
		if got := arWeakened(t, drop); got != want {
			t.Errorf("without the %s sentence: failing %q, want %q", name, got, want)
		}
	}
}

// TestAuditRecordSequenceSetChecksAreLoadBearing: accepting two records at one
// place in a series fails SQ5, and leaving a missing number unnamed fails SQ4.
func TestAuditRecordSequenceSetChecksAreLoadBearing(t *testing.T) {
	for name, want := range map[string]string{"duplicate": "SQ5", "gap": "SQ4"} {
		drop := func() func() {
			arSequenceSetChecks[name] = false
			return func() { arSequenceSetChecks[name] = true }
		}
		if got := arWeakened(t, drop); got != want {
			t.Errorf("without the %s check: failing %q, want %q", name, got, want)
		}
	}
}
