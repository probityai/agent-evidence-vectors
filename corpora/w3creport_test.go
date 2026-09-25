package corpora

// The tree-shape rules of the v0.1 report reader that the corpus alone cannot
// pin. A corpus member shows how a report is judged; it cannot show what the
// root function does with a shape no member carries. The failure this guards
// against is the silent one: a name outside the closed set hashed as another
// shape, so a root computed one way is compared against a root computed another
// and nothing says the shape was never recognised.

import "testing"

var shapeChecks = []map[string]any{
	{"check": "c-pass", "state": "pass"},
	{"check": "c-pass-2", "state": "pass"},
	{"check": "c-pass-3", "state": "pass"},
}

func TestW3CUnregisteredShapeIsRefused(t *testing.T) {
	for _, shape := range []string{"RFC 9162 SHA-256", "rfc9162", "", "FLAT"} {
		if root, err := w3cCheckSetRoot(shapeChecks, shape); err == nil {
			t.Errorf("shape %q is outside the closed set and was hashed to %s", shape, root)
		}
	}
}

func TestW3CEveryRegisteredShapeHasItsOwnRoot(t *testing.T) {
	for shape := range w3cShapes {
		if _, err := w3cCheckSetRoot(shapeChecks, shape); err != nil {
			t.Errorf("registered shape %q has no root: %v", shape, err)
		}
	}
}
