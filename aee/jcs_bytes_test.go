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

// TestJCSDriftAndDepthVectors holds Canonicalize to the drift and depth
// families. Output must never be the drifted bytes, the string families must
// canonicalize to the pinned bytes, and nesting past the cap must be refused.
func TestJCSDriftAndDepthVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "corpora", "jcs-byte-vectors", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		DriftCases []struct {
			ID           string `json:"id"`
			Family       string `json:"family"`
			Presented    string `json:"presented"`
			CanonicalHex string `json:"canonicalHex"`
		} `json:"driftCases"`
		DepthCases []struct {
			ID           string `json:"id"`
			Input        string `json:"input"`
			Expect       string `json:"expect"`
			CanonicalHex string `json:"canonicalHex"`
		} `json:"depthCases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.DriftCases) == 0 || len(corpus.DepthCases) == 0 {
		t.Fatal("byte corpus needs drift and depth cases")
	}
	for _, c := range corpus.DriftCases {
		t.Run(c.ID, func(t *testing.T) {
			want, err := hex.DecodeString(c.CanonicalHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonicalize([]byte(c.Presented))
			if err == nil && !bytes.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
			if err != nil && c.Family != "number-format" {
				t.Fatalf("a string-family case must canonicalize: %v", err)
			}
			if err == nil && string(got) == c.Presented {
				t.Fatalf("Canonicalize echoed the drifted bytes %q", got)
			}
		})
	}
	for _, c := range corpus.DepthCases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := Canonicalize([]byte(c.Input))
			if c.Expect == "reject" {
				if !errors.Is(err, ErrInputTooDeep) {
					t.Fatalf("got %v, want %v", err, ErrInputTooDeep)
				}
				return
			}
			want, _ := hex.DecodeString(c.CanonicalHex)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
}
