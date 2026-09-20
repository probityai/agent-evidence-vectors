package observedeffect

// The refusals the CORPUS cannot reach, and the facts it does not name.
//
// The corpus is a set of well-formed DSSE envelopes: every member decodes, every
// member carries a statement, and one signature is checked at the end. That is
// the right shape for a conformance corpus and it leaves a whole class of this
// rail's refusals unexercised -- a truncated envelope, a payload that is not
// base64, a statement that is a list, a signature block with no signature in it.
// Those paths were 26 statements of this file that nothing ran, which is how a
// refusal stops being a refusal without anybody editing it.
//
// They are reached here directly rather than through a corpus member, and that is
// deliberate: a member that could reach them would have to be malformed in a way
// the corpus deliberately does not publish, and adding one would make the corpus
// worse to make a coverage figure better. An in-package test is the honest place
// for the paths a published corpus should not contain.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envelope builds a DSSE envelope around a payload, base64 as the format requires.
func envelopeAround(payload string) []byte {
	return []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` +
		base64.StdEncoding.EncodeToString([]byte(payload)) +
		`","signatures":[{"keyid":"k","sig":"` +
		base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `"}]}`)
}

func TestTheEnvelopePathRefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"envelope is not json", `{`, "not-parseable"},
		{"envelope is a list", `[]`, "not-parseable"},
		{"payload is not a string", `{"payload":5}`, "not-parseable"},
		{"payload is not base64", `{"payload":"!!!not base64!!!"}`, "not-parseable"},
		{
			"payload is not json",
			`{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{`)) + `"}`,
			"not-parseable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := Verify([]byte(tc.raw), Policy{})
			if report.Verdict != verdictMalformed {
				t.Fatalf("verdict %q, want %q", report.Verdict, verdictMalformed)
			}
			if len(report.Codes) != 1 || report.Codes[0] != tc.want {
				t.Errorf("codes %v, want [%s]", report.Codes, tc.want)
			}
		})
	}
}

func TestAStatementThisRailCannotIndexIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    string
	}{
		{"statement is a list", `[]`, "not-parseable"},
		{
			"statement type is not the one this rail reads",
			`{"_type":"https://in-toto.io/Statement/v0.1","predicate":{}}`,
			"statement-type-unexpected",
		},
		{
			"predicate is absent",
			`{"_type":"` + StatementType + `"}`,
			"unhandled-shape:predicate",
		},
		{
			"predicate is not an object",
			`{"_type":"` + StatementType + `","predicate":[]}`,
			"unhandled-shape:predicate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := Verify(envelopeAround(tc.payload), Policy{})
			if report.Verdict != verdictMalformed {
				t.Fatalf("verdict %q, want %q", report.Verdict, verdictMalformed)
			}
			if len(report.Codes) != 1 || report.Codes[0] != tc.want {
				t.Errorf("codes %v, want [%s]", report.Codes, tc.want)
			}
		})
	}
}

// TestTheSignatureGateRefusesEveryUnreadableShape reaches verifyEnvelopeSignature
// directly. Through Verify it is the LAST gate, so every one of these cases would
// need a statement that satisfies all thirty-two rules and then carries a broken
// signature block -- which is a fixture whose only purpose is to be wrong in one
// place, and there is no reason for a published corpus to hold six of them.
func TestTheSignatureGateRefusesEveryUnreadableShape(t *testing.T) {
	goodKey := strings.Repeat("ab", ed25519.PublicKeySize)
	signature := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for _, tc := range []struct {
		name     string
		envelope map[string]any
		keyHex   string
		want     string
	}{
		{"no signatures member", map[string]any{"payloadType": "t"}, goodKey, "envelope-signature-unreadable"},
		{"signatures is empty", map[string]any{"signatures": []any{}}, goodKey, "envelope-signature-unreadable"},
		{"signature entry is not an object", map[string]any{"signatures": []any{"x"}}, goodKey, "envelope-signature-unreadable"},
		{
			"sig is not a string",
			map[string]any{"signatures": []any{map[string]any{"sig": 5}}},
			goodKey, "envelope-signature-unreadable",
		},
		{
			"sig is not base64",
			map[string]any{"signatures": []any{map[string]any{"sig": "!!!"}}},
			goodKey, "envelope-signature-unreadable",
		},
		{
			"the consumer's key is not hex",
			map[string]any{"signatures": []any{map[string]any{"sig": signature}}},
			"nothex", "envelope-signature-unreadable",
		},
		{
			"the consumer's key is the wrong length",
			map[string]any{"signatures": []any{map[string]any{"sig": signature}}},
			"abcd", "envelope-signature-unreadable",
		},
		{
			"payloadType is absent",
			map[string]any{"signatures": []any{map[string]any{"sig": signature}}},
			goodKey, "envelope-signature-unreadable",
		},
		{
			"the signature does not verify",
			map[string]any{
				"payloadType": "application/vnd.in-toto+json",
				"signatures":  []any{map[string]any{"sig": signature}},
			},
			goodKey, "envelope-signature-invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := verifyEnvelopeSignature(tc.envelope, []byte("{}"), tc.keyHex)
			if f == nil {
				t.Fatal("the gate accepted it, so a consumer would read this envelope as signed")
			}
			if f.code != tc.want {
				t.Errorf("code %q, want %q", f.code, tc.want)
			}
		})
	}
}

func TestTheTypeURIIsReadFromTheDocumentOrRefused(t *testing.T) {
	t.Run("the document is absent", func(t *testing.T) {
		if _, err := PredicateTypeFromSpec(filepath.Join(t.TempDir(), "nothing-here.md")); err == nil {
			t.Fatal("reading a Type URI out of a document that is not there returned no error, " +
				"so a caller would proceed with an empty predicate type")
		}
	})
	t.Run("the document states no Type URI", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "spec.md")
		if err := os.WriteFile(path, []byte("# A document\n\nNo type line here.\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := PredicateTypeFromSpec(path)
		if err == nil {
			t.Fatal("a document with no Type URI line produced no error")
		}
		if !strings.Contains(err.Error(), "states no Type URI line") {
			t.Errorf("the refusal does not say what is missing: %v", err)
		}
	})
	t.Run("the corpus document states one", func(t *testing.T) {
		// The positive control. Without it the two refusals above would pass
		// against a function that only ever fails.
		uri, err := PredicateTypeFromSpec(specPath)
		if err != nil {
			t.Fatalf("the repository's own predicate document did not yield a Type URI: %v", err)
		}
		if !strings.HasPrefix(uri, "https://") {
			t.Errorf("Type URI %q is not a URI", uri)
		}
	})
}

// TestEverySelfDerivableFactIsComputedFromTheRecord covers the fact table. The
// corpus names writes.count and interval.afterRoot; the other four are supported
// and unexercised, so a wrong one would ship unnoticed -- and the whole point of
// the table is that these facts are recomputed rather than read, so a fact that
// computes the wrong thing hands a lying producer back its own number.
func TestEverySelfDerivableFactIsComputedFromTheRecord(t *testing.T) {
	c := &ctx{pred: map[string]any{
		"authorityDigest": "dd",
		"pathScope":       []any{"/a/", "/b/", "/c/"},
		"reads":           []any{map[string]any{}, map[string]any{}},
		"writes":          []any{map[string]any{}},
		"interval": map[string]any{
			"beforeRoot": "before",
			"afterRoot":  "after",
		},
	}}
	for _, tc := range []struct{ fact, want string }{
		{"writes.count", "1"},
		{"reads.count", "2"},
		{"pathScope.count", "3"},
		{"interval.beforeRoot", "before"},
		{"interval.afterRoot", "after"},
		{"authorityDigest", "dd"},
	} {
		derive, known := selfDerivable[tc.fact]
		if !known {
			t.Errorf("%s is not in the table, so a record naming it is not recomputed", tc.fact)
			continue
		}
		if got := derive(c); got != tc.want {
			t.Errorf("%s computed %q, want %q", tc.fact, got, tc.want)
		}
	}
	if len(selfDerivable) != 6 {
		t.Errorf("the table holds %d facts and this test covers 6; a fact nobody computes here "+
			"is a fact that can be wrong in the direction the table exists to prevent",
			len(selfDerivable))
	}
}

// TestTheAccessorsReadAnAbsentObjectAsEmpty pins the nil behaviour the rules lean
// on. Every rule indexes through these, and a nil map is what an absent member
// decodes to, so "absent reads as empty" is the property that lets the rules state
// their own refusals instead of each guarding for a shape.
func TestTheAccessorsReadAnAbsentObjectAsEmpty(t *testing.T) {
	c := &ctx{}
	if got := c.str(nil, "anything"); got != "" {
		t.Errorf("str on an absent object returned %q", got)
	}
	if got := c.list(nil, "anything"); got != nil {
		t.Errorf("list on an absent object returned %v", got)
	}
	if got := c.obj(nil, "anything"); got != nil {
		t.Errorf("obj on an absent object returned %v", got)
	}
	if got := c.interval(); got != nil {
		t.Errorf("interval with no predicate returned %v", got)
	}
	if commitment, present := c.commitment(); present || commitment != nil {
		t.Errorf("commitment with no observation returned (%v, %v)", commitment, present)
	}
	// An absent object owes the same named refusal as a present one missing the
	// member: a caller cannot act on "something was incomplete".
	f := requireMembers(nil, "tier")
	if f == nil {
		t.Fatal("requireMembers accepted an absent object")
	}
	if f.code != "required-member-absent:tier" {
		t.Errorf("code %q does not name the absent member", f.code)
	}
}

// TestHexKeyLengthIsCheckedNotAssumed is the guard behind the key-length branch
// above: a 31-byte key is valid hex and cannot verify anything.
func TestHexKeyLengthIsCheckedNotAssumed(t *testing.T) {
	short := hex.EncodeToString(make([]byte, ed25519.PublicKeySize-1))
	f := verifyEnvelopeSignature(
		map[string]any{
			"payloadType": "t",
			"signatures": []any{map[string]any{
				"sig": base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
			}},
		},
		[]byte("{}"), short)
	if f == nil || f.code != "envelope-signature-unreadable" {
		t.Fatalf("a key one byte short was not refused: %v", f)
	}
}
