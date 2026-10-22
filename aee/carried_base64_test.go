package aee

import (
	"slices"
	"testing"
)

// TestDecodeCarriedBase64 pins every clause of the canonical-base64 rule on
// carried text. The line-break cases are the ones encoding/base64's Strict()
// decoder accepts on its own, which is why the helper exists.
func TestDecodeCarriedBase64(t *testing.T) {
	if b, err := decodeCarriedBase64("aGVsbG8="); err != nil || string(b) != "hello" {
		t.Fatalf("canonical text must decode: got %q, %v", b, err)
	}
	for _, s := range []string{
		"aGVs\nbG8=",   // line feed inside the text
		"aGVs\r\nbG8=", // CRLF inside the text
		"aGVsbG8=\n",   // trailing line feed
		"aGVsbG8",      // padding dropped
		"aGVsbG8==",    // padding beyond the minimum
		"aGVs bG8=",    // a non-alphabet byte
		"a-Vs",         // the URL-safe alphabet
		"QUJ=",         // nonzero trailing bits
	} {
		if b, err := decodeCarriedBase64(s); err == nil {
			t.Errorf("%q must be refused, decoded to %q", s, b)
		}
	}
}

// TestRecordPayloadLineBreakUndecodable drives the helper through the record
// path: a payload whose only fault is a line break is undecodable.
func TestRecordPayloadLineBreakUndecodable(t *testing.T) {
	p := &Predicate{
		RecordsPresent:   true,
		BatchRootPresent: true,
		Records:          []Record{{PayloadB64: "e30=\n", PayloadType: "application/x.aee+json"}},
	}
	states, codes := checkRecordsStatementLevel(p)
	if !states[0].decodeErr || !slices.Contains(codes, CodeRecordUndecodable) {
		t.Fatalf("a line break must make the record undecodable; decodeErr=%v codes=%v", states[0].decodeErr, codes)
	}
}
