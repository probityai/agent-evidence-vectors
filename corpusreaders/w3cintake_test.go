package corpora

import "testing"

// A manifest root or a record path that leaves the directory the operator
// named lists nothing; the same walk over a record path inside it does.
func TestIntakeWalkStaysUnderTheRoot(t *testing.T) {
	root := "../vectors-w3c-intake"
	if got := intakeWalk(root, "vectors", ".json", true); len(got) == 0 {
		t.Fatal("control: the corpus's own vectors directory listed nothing")
	}
	for _, rel := range []string{"..", "../corpora", "vectors/..", "/etc", "", "."} {
		if got := intakeWalk(root, rel, "", true); got != nil {
			t.Errorf("intakeWalk(%q) listed %d files outside the root", rel, len(got))
		}
	}
}
