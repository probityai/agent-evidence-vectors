package corpora

// The tree-shape rules of the v0.1 report reader that the corpus alone cannot
// pin. A corpus member shows how a report is judged; it cannot show what the
// root function does with a shape no member carries. The failure this guards
// against is the silent one: a name outside the closed set hashed as another
// shape, so a root computed one way is compared against a root computed another
// and nothing says the shape was never recognised.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

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

// rfc9162MTH is RFC 9162 section 2.1.1 written from the RFC text, not the
// reader's mth, so the comparison below is between two statements of the rule.
func rfc9162MTH(entries [][]byte) []byte {
	switch len(entries) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		sum := sha256.Sum256(append([]byte{0x00}, entries[0]...))
		return sum[:]
	}
	k := 1
	for k*2 < len(entries) {
		k *= 2
	}
	node := append([]byte{0x01}, rfc9162MTH(entries[:k])...)
	node = append(node, rfc9162MTH(entries[k:])...)
	sum := sha256.Sum256(node)
	return sum[:]
}

// TestW3CRFC9162SHA256IsTheRFC9162Tree: the RFC 9942 identifier RFC9162_SHA256
// names the Merkle tree of RFC 9162 section 2.1.1 over SHA-256.
func TestW3CRFC9162SHA256IsTheRFC9162Tree(t *testing.T) {
	if !w3cShapes["RFC9162_SHA256"] {
		t.Fatal("RFC9162_SHA256 is not in the closed set")
	}
	leaves := make([][]byte, 0, len(shapeChecks))
	for _, check := range shapeChecks {
		leaf, err := pythonCompactJSON(check)
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, leaf)
	}
	got, err := w3cCheckSetRoot(shapeChecks, "RFC9162_SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(rfc9162MTH(leaves)); got != want {
		t.Errorf("RFC9162_SHA256 root %s is not the RFC 9162 tree %s", got, want)
	}
	if got == hex.EncodeToString(flatRoot(leaves)) {
		t.Error("RFC9162_SHA256 hashed as the flat shape")
	}
}
