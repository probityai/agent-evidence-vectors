package corpora

import "testing"

func TestGenerationRevisionRangeGrammar(t *testing.T) {
	for _, tc := range []struct {
		text       string
		start, end int
		valid      bool
	}{
		{"1", 1, 1, true}, {"3-7", 3, 7, true}, {"2-2", 2, 2, true},
		{"0", 0, 0, false}, {"7-3", 0, 0, false}, {"+1", 0, 0, false},
		{"1-", 0, 0, false}, {"1-2-3", 0, 0, false}, {" 1", 0, 0, false},
		{"1.0", 0, 0, false}, {"999999999999999999999999", 0, 0, false},
	} {
		t.Run(tc.text, func(t *testing.T) {
			start, end, valid := agRange(tc.text)
			if start != tc.start || end != tc.end || valid != tc.valid {
				t.Fatalf("range %q: got %d, %d, %v", tc.text, start, end, valid)
			}
		})
	}
}

func TestGenerationRevisionTrailerTools(t *testing.T) {
	tools := map[string]bool{"search": true, "edit": true}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"model", true}, {"model search", true}, {"model edit search", true},
		{"other search", false}, {"model shell", false}, {"", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := agTrailerMatches(tc.value, "model", tools); got != tc.valid {
				t.Fatalf("trailer %q: got %v", tc.value, got)
			}
		})
	}
}
