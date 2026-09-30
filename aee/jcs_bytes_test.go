package aee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type byteVector struct {
	ID           string `json:"id"`
	Input        string `json:"input"`
	CanonicalHex string `json:"canonicalHex"`
	Bounded      string `json:"bounded"`
	BoundedError string `json:"boundedError"`
	JCSError     string `json:"jcsError"`
}

func TestJCSByteVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "corpora", "jcs-byte-vectors", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		CanonicalCases []byteVector `json:"canonicalCases"`
		RejectCases    []byteVector `json:"rejectCases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.CanonicalCases) == 0 || len(corpus.RejectCases) == 0 {
		t.Fatal("byte corpus needs accept and reject cases")
	}
	for _, c := range append(corpus.CanonicalCases, corpus.RejectCases...) {
		t.Run(c.ID, func(t *testing.T) {
			got, err := Canonicalize([]byte(c.Input))
			if c.Bounded == "accept" {
				if err != nil {
					t.Fatal(err)
				}
				want, err := hex.DecodeString(c.CanonicalHex)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("got %x, want %x", got, want)
				}
				return
			}
			reason := c.BoundedError
			if reason == "" {
				reason = c.JCSError
			}
			var want error
			switch reason {
			case "unsafe-integer":
				want = ErrUnsafeInteger
			case "non-integer":
				want = ErrNonIntegerNumber
			case "duplicate-member":
				want = ErrDuplicateMember
			case "invalid-unicode":
				want = ErrStringNotScalar
			}
			if want == nil || !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}
