package aee_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func TestCanonicalizeSortsAndMinifies(t *testing.T) {
	in := []byte("{\n  \"b\": 1,\n  \"a\": [\"x\", 2.0, true, null]\n}")
	got, err := aee.Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":["x",2,true,null],"b":1}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCanonicalizeRejectsDuplicateMember(t *testing.T) {
	_, err := aee.Canonicalize([]byte(`{"a":1,"a":2}`))
	if !errors.Is(err, aee.ErrDuplicateMember) {
		t.Fatalf("expected duplicate-member error, got %v", err)
	}
}

func TestCanonicalizeRejectsUnsafeInteger(t *testing.T) {
	_, err := aee.Canonicalize([]byte(`{"a":9007199254740992}`)) // 2^53
	if !errors.Is(err, aee.ErrUnsafeInteger) {
		t.Fatalf("expected unsafe-integer error, got %v", err)
	}
	// 2^53 - 1 is the largest safe integer and must round-trip.
	got, err := aee.Canonicalize([]byte(`{"a":9007199254740991}`))
	if err != nil || string(got) != `{"a":9007199254740991}` {
		t.Fatalf("safe integer failed: %s %v", got, err)
	}
}

func TestCanonicalizeStringEscapes(t *testing.T) {
	in := "{\"a\":\"line\\nbreak\\u0001\\t\\\"q\\\"\"}"
	got, err := aee.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	// JCS: two-char escapes for \n \t and the quote; \u0001 stays a
	// lowercase \u escape because it has no two-char form.
	want := "{\"a\":\"line\\nbreak\\u0001\\t\\\"q\\\"\"}"
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestPAEKnownAnswer(t *testing.T) {
	got := aee.PAE("application/vnd.example+json", []byte(`{"a":1}`))
	want := "DSSEv1 28 application/vnd.example+json 7 " + `{"a":1}`
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// RFC 6962 structural known answers: domain separation, the recursive
// split for an odd leaf count, and the no-pad rule.
func TestMerkleRootStructure(t *testing.T) {
	pae := func(s string) []byte { return []byte(s) }
	l0 := aee.LeafHash(pae("r0"))
	l1 := aee.LeafHash(pae("r1"))
	l2 := aee.LeafHash(pae("r2"))

	// Leaf domain separation: H(0x00||b), not H(b).
	plain := sha256.Sum256(pae("r0"))
	if l0 == plain {
		t.Fatal("leaf hash missing 0x00 domain separation")
	}

	node := func(l, r [32]byte) [32]byte {
		h := sha256.New()
		h.Write([]byte{0x01})
		h.Write(l[:])
		h.Write(r[:])
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}

	// Single-record tree: root == leaf.
	if got := aee.MerkleRoot([][32]byte{l0}); got != l0 {
		t.Fatal("single-leaf root is not the leaf hash")
	}
	// Two leaves.
	if got := aee.MerkleRoot([][32]byte{l0, l1}); got != node(l0, l1) {
		t.Fatal("two-leaf root mismatch")
	}
	// Three leaves: RFC 6962 split is (2,1): H(01 || H(01||l0||l1) || l2).
	want3 := node(node(l0, l1), l2)
	if got := aee.MerkleRoot([][32]byte{l0, l1, l2}); got != want3 {
		t.Fatal("three-leaf root does not follow the recursive split")
	}
	// The Bitcoin-style pad (duplicate the trailing node) must NOT match.
	padded := node(node(l0, l1), node(l2, l2))
	if got := aee.MerkleRoot([][32]byte{l0, l1, l2}); got == padded {
		t.Fatal("root matches duplicate-last-node padding")
	}
}

func TestRunBindingPreimageShape(t *testing.T) {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	cp, co, np, ov, re, su, sb := h("cp"), h("co"), h("np"), h("ov"), h("re"), h("su"), h("sb")
	pre := aee.RunBindingPreimage(cp, co, np, ov, re, su, sb)
	want := `{"aeeBindingVersion":"2","catchPolicy":"` + cp + `","corpus":"` + co +
		`","networkPosture":"` + np + `","observationVocabulary":"` + ov +
		`","runEntropy":"` + re +
		`","subject":"` + su + `","substrate":"` + sb + `"}`
	if string(pre) != want {
		t.Fatalf("preimage bytes drifted:\n got %s\nwant %s", pre, want)
	}
	// The pre-image must itself be JCS-canonical.
	canon, err := aee.Canonicalize(pre)
	if err != nil || !bytes.Equal(canon, pre) {
		t.Fatalf("binding pre-image is not canonical: %v", err)
	}
	if got := aee.DeriveRunBinding(cp, co, np, ov, re, su, sb); got != aee.SHA256Hex(pre) {
		t.Fatal("binding digest is not the SHA-256 of the pre-image")
	}
}

func TestIsLowerHex64(t *testing.T) {
	ok := aee.SHA256Hex([]byte("x"))
	if !aee.IsLowerHex64(ok) {
		t.Fatal("valid digest rejected")
	}
	for _, bad := range []string{"", ok[:63], ok + "0", "G" + ok[1:], "A" + ok[1:]} {
		if aee.IsLowerHex64(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}
