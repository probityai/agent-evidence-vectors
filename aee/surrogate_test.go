package aee_test

// Byte-level string-scalar rejection (RFC 7493 I-JSON section 2.1).
//
// These tests exist because the fault they cover is UNOBSERVABLE one layer
// later. Go's encoding/json substitutes U+FFFD for an unpaired surrogate
// escape and for invalid UTF-8 while decoding, so every check that reads a
// decoded Go string — the observationVocabulary sortedness, duplicate-freedom,
// BMP-only and digest rules among them — sees a legal BMP scalar and cannot
// tell it from one the producer actually wrote. The check therefore has to sit
// on the raw bytes, and so does its regression pin: each test below asserts a
// rejection that the pre-fix rail did not make.
//
// The independent Rust rail (aee-checker, src/json.rs) rejects the same inputs
// at its parser with "lone high surrogate" / "lone low surrogate" / "invalid
// surrogate pair" / "invalid UTF-8", so these are also the cross-rail
// agreement pins.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

// ---------------------------------------------------------------------------
// Byte level: the strict I-JSON parser
// ---------------------------------------------------------------------------

// esc builds the JSON source text of a \uXXXX escape sequence from the UTF-16
// code units it names. Escapes are built rather than typed so the test input
// cannot be silently folded into the character it denotes by an editor or a
// source transform: what these tests are about is the difference between the
// escape and the character, and every case below must stay on the escape side
// of it. escUpper is the same with upper-case hex digits (JSON permits both).
func esc(units ...uint16) string {
	var b strings.Builder
	for _, u := range units {
		fmt.Fprintf(&b, `\u%04x`, u)
	}
	return b.String()
}

func escUpper(units ...uint16) string {
	var b strings.Builder
	for _, u := range units {
		fmt.Fprintf(&b, `\u%04X`, u)
	}
	return b.String()
}

func TestCheckIJSONRejectsNonScalarStrings(t *testing.T) {
	rejected := []struct {
		name string
		raw  string
	}{
		{"lone high surrogate escape", `{"a":"\ud800"}`},
		{"lone low surrogate escape", `{"a":"\udc00"}`},
		{"high surrogate followed by a BMP escape", `{"a":"\ud800A"}`},
		{"high surrogate followed by a literal character", `{"a":"\ud800x"}`},
		{"high surrogate followed by a second high surrogate", `{"a":"\ud83d\ud83d"}`},
		{"low surrogate followed by a high surrogate", `{"a":"\ude00\ud83d"}`},
		{"lone surrogate in a member NAME", `{"\ud800":1}`},
		{"lone surrogate nested in an array", `{"a":[{"b":["\udfff"]}]}`},
		{"lone surrogate at the end of a longer string", `{"a":"egress_captured\ud800"}`},
		{"raw invalid UTF-8 byte", "{\"a\":\"\xff\"}"},
		{"surrogate encoded directly in UTF-8 (CESU-8)", "{\"a\":\"\xed\xa0\x80\"}"},
		{"overlong UTF-8 encoding of '/'", "{\"a\":\"\xc0\xaf\"}"},
		{"truncated UTF-8 sequence", "{\"a\":\"\xe2\x82\"}"},
		// The scan must track string state, not just look for "\u": the fault
		// here follows a string carrying escaped quotes and backslashes.
		{"fault after a string with escaped quotes", `{"a":"say \"hi\" \\ ok","b":"\udc00"}`},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			err := aee.CheckIJSON([]byte(tc.raw))
			if !errors.Is(err, aee.ErrStringNotScalar) {
				t.Fatalf("CheckIJSON(%q) = %v, want ErrStringNotScalar", tc.raw, err)
			}
		})
	}
}

// TestCheckIJSONAcceptsWellFormedStrings is the over-rejection guard: a fix
// that simply refused every \u escape, or every 0xD800-range code unit, would
// turn these red. A well-formed surrogate PAIR is legal JSON and legal I-JSON
// and must parse — the predicate's separate BMP-only profile is what rejects
// the supplementary code point it denotes, and it rejects it on the decoded
// value, at the surface that profile is scoped to (see
// TestVocabularyValidSurrogatePairIsRejectedAsNonBMP).
func TestCheckIJSONAcceptsWellFormedStrings(t *testing.T) {
	accepted := []struct {
		name string
		raw  string
	}{
		{"well-formed surrogate pair", `{"a":"` + esc(0xD83D, 0xDE00) + `"}`},
		{"two consecutive surrogate pairs", `{"a":"` + esc(0xD83D, 0xDE00, 0xD83D, 0xDE01) + `"}`},
		{"surrogate pair in a member name", `{"` + esc(0xD83D, 0xDE00) + `":1}`},
		{"upper-case hex digits in a surrogate pair", `{"a":"` + escUpper(0xD83D, 0xDE00) + `"}`},
		{"BMP escape", `{"a":"caf` + esc(0x00E9) + `"}`},
		{"escaped NUL", `{"a":"` + esc(0x0000) + `"}`},
		{"escaped backslash immediately before a surrogate pair", `{"a":"\\` + esc(0xD83D, 0xDE00) + `"}`},
		{"the two-character escapes", `{"a":"\"\\\/\b\f\n\r\t"}`},
		{"literal U+FFFD (a legal scalar the producer may write)", "{\"a\":\"\ufffd\"}"},
		{"literal supplementary character in UTF-8", "{\"a\":\"\U0001F600\"}"},
		{"empty string", `{"a":""}`},
		{"no strings at all", `[1,2,true,null]`},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if err := aee.CheckIJSON([]byte(tc.raw)); err != nil {
				t.Fatalf("CheckIJSON(%q) = %v, want nil", tc.raw, err)
			}
		})
	}
}

// TestCanonicalizeSurrogateCollisionIsClosed pins the collision directly.
// Before the fix all three inputs canonicalized to the SAME bytes — the U+FFFD
// the decoder substituted — so two distinct wire strings became one value and
// any sortedness or duplicate check downstream read them as a duplicate. Only
// the literal U+FFFD, which is a real Unicode scalar, still canonicalizes.
func TestCanonicalizeSurrogateCollisionIsClosed(t *testing.T) {
	high := []byte(`["\ud800"]`)
	low := []byte(`["\udc00"]`)
	literal := []byte("[\"�\"]")

	for _, raw := range [][]byte{high, low} {
		if _, err := aee.Canonicalize(raw); !errors.Is(err, aee.ErrStringNotScalar) {
			t.Fatalf("Canonicalize(%s) = %v, want ErrStringNotScalar", raw, err)
		}
	}
	canon, err := aee.Canonicalize(literal)
	if err != nil {
		t.Fatalf("Canonicalize(literal U+FFFD) = %v, want nil", err)
	}
	if !bytes.Equal(canon, literal) {
		t.Fatalf("Canonicalize(literal U+FFFD) = %q, want %q", canon, literal)
	}
}

// ---------------------------------------------------------------------------
// The vocabulary path, end to end
// ---------------------------------------------------------------------------

// origLabels is the labels array aeetest.Build emits before any mutation.
var origLabels = []string{"egress_captured", "no_egress"}

// withVocabularyLabels returns a statement whose observationVocabulary labels
// array is the given RAW JSON element sources, so a test can put bytes on the
// wire that no Go string can carry through a decode.
//
// It gets there by BUILDING with the decoded labels and substituting the raw
// sources afterwards, rather than by rewriting the array and patching up the
// digest beside it. The two produce the same bytes for the label array and
// different bytes for everything derived from it, and the difference is what
// makes each test below a single-fault vector. The vocabulary digest is one
// such derived value; so is the run binding, which folds that digest in, and so
// is every record signature and the batch root over them. Patching only the
// digest left the records bound to a vocabulary the statement no longer
// carried, and the mutation cases then reported a binding mismatch rather than
// the byte-level fault they exist to pin. Deriving over the DECODED labels is
// deliberate and unchanged: those are the values a lenient rail reads, so the
// statement is exactly the one such a rail computed as self-consistent.
func withVocabularyLabels(t *testing.T, rawLabels []string) []byte {
	t.Helper()
	var decoded []string
	if err := json.Unmarshal([]byte(`[`+strings.Join(rawLabels, ",")+`]`), &decoded); err != nil {
		t.Fatalf("mutated labels are not a JSON array of strings: %v", err)
	}
	if len(decoded) < len(origLabels) {
		t.Fatalf("mutated labels drop one of the built-in labels: %q", decoded)
	}
	extras := decoded[len(origLabels):]
	out := aeetest.Build(aeetest.Options{ExtraVocabularyLabels: extras})

	// Each appended label was serialized by the builder's canonicalizer; swap
	// that serialization for the raw source the case names. One occurrence at a
	// time, because two distinct raw sources may share one decoded form and the
	// second substitution must not land on the first source's site.
	for i, extra := range extras {
		encoded, err := json.Marshal(extra)
		if err != nil {
			t.Fatal(err)
		}
		canon, err := aee.Canonicalize(encoded)
		if err != nil {
			t.Fatalf("canonicalize appended label %q: %v", extra, err)
		}
		if !bytes.Contains(out, canon) {
			t.Fatalf("built statement does not carry the appended label %q", extra)
		}
		out = bytes.Replace(out, canon, []byte(rawLabels[len(origLabels)+i]), 1)
	}
	return out
}

// TestVocabularyMutationHarnessIsSound is the control for every mutation test
// below: the same rewrite with an ordinary ASCII label that sorts last leaves a
// statement that still verifies VALID. Whatever the surrogate cases report is
// therefore caused by the surrogate and by nothing the harness did.
func TestVocabularyMutationHarnessIsSound(t *testing.T) {
	mutated := withVocabularyLabels(t,
		[]string{`"egress_captured"`, `"no_egress"`, `"zz_extra"`})
	r := aee.Verify(mutated, pinnedPolicy())
	if r.Verdict != aee.VerdictValid {
		t.Fatalf("control mutation must stay valid, got invalid %v", r.Codes)
	}
}

// TestVocabularyLoneSurrogateIsRejected is the defect's regression pin.
//
// Each label below sorts last under BOTH UTF-16 code-unit and code-point order
// once decoded (U+FFFD is 0xFFFD, above every ASCII label), the caught array
// stays a subset, and the carried digest is the one the rail derives, so BEFORE
// the fix every one of these statements verified VALID: the lone surrogate
// decoded to U+FFFD, which the BMP-only profile accepts. The Rust rail rejected
// the identical bytes at its parser — a two-rail split on one attestation.
func TestVocabularyLoneSurrogateIsRejected(t *testing.T) {
	cases := []struct {
		name      string
		rawLabels []string
	}{
		{
			"lone high surrogate escape in a label",
			[]string{`"egress_captured"`, `"no_egress"`, `"\ud800"`},
		},
		{
			"lone low surrogate escape in a label",
			[]string{`"egress_captured"`, `"no_egress"`, `"\udc00"`},
		},
		{
			"lone surrogate inside an otherwise ordinary label",
			[]string{`"egress_captured"`, `"no_egress"`, `"zz\udfffz"`},
		},
		{
			// The false-DUPLICATE half of the defect: \ud800 and \udc00 are two
			// distinct wire strings that both decode to U+FFFD, so the decoded
			// array read as a duplicate that the bytes never contained. The
			// statement is rejected either way now, but for what the bytes say.
			"two DISTINCT lone surrogates in one vocabulary",
			[]string{`"egress_captured"`, `"no_egress"`, `"\ud800"`, `"\udc00"`},
		},
		{
			"raw invalid UTF-8 byte in a label",
			[]string{`"egress_captured"`, `"no_egress"`, "\"zz\xffz\""},
		},
		{
			"surrogate encoded directly in UTF-8 in a label",
			[]string{`"egress_captured"`, `"no_egress"`, "\"zz\xed\xa0\x80\""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := withVocabularyLabels(t, tc.rawLabels)

			// The statement must not parse at all: the fault is on the bytes,
			// and the decode that follows would erase it.
			if _, err := aee.ParseStatement(mutated); !errors.Is(err, aee.ErrStringNotScalar) {
				t.Fatalf("ParseStatement = %v, want ErrStringNotScalar", err)
			}
			// End to end: statement-malformed, the same code the sibling
			// statement-wide strict-I-JSON rule reports for a duplicate member.
			r := aee.Verify(mutated, pinnedPolicy())
			if r.Verdict != aee.VerdictInvalid {
				t.Fatalf("verdict %s (result %q), want invalid", r.Verdict, r.Result)
			}
			if r.PrimaryCode != aee.CodeStatementMalformed {
				t.Fatalf("primary code %s, want %s (all: %v)", r.PrimaryCode, aee.CodeStatementMalformed, r.Codes)
			}
			if r.Result != "" || r.Tiers != nil {
				t.Fatal("invalid verdict leaked result/tiers")
			}
		})
	}
}

// TestVocabularyValidSurrogatePairIsRejectedAsNonBMP pins the boundary between
// the two rules. A well-formed pair is legal I-JSON, so the byte-level check
// must let it through; the code point it denotes is supplementary, so the
// BMP-only vocabulary profile rejects it — with vocabulary-not-canonical, NOT
// with statement-malformed (spec Prerequisites: "no code point above U+FFFF,
// no surrogate pair", treated exactly as non-canonical bytes). A fix that
// rejected surrogate escapes wholesale would report the wrong code here.
func TestVocabularyValidSurrogatePairIsRejectedAsNonBMP(t *testing.T) {
	for _, label := range []string{
		`"` + esc(0xD83D, 0xDE00) + `"`, // U+1F600 written as a well-formed escape pair
		"\"\U0001F600\"",                // and as the literal character in UTF-8
	} {
		mutated := withVocabularyLabels(t,
			[]string{`"egress_captured"`, `"no_egress"`, label})
		if _, err := aee.ParseStatement(mutated); err != nil {
			t.Fatalf("ParseStatement(%s) = %v, want nil: a well-formed pair is legal I-JSON", label, err)
		}
		checkNonBMPVocabulary(t, mutated)
	}
}

func checkNonBMPVocabulary(t *testing.T, mutated []byte) {
	t.Helper()
	r := aee.Verify(mutated, pinnedPolicy())
	if r.Verdict != aee.VerdictInvalid {
		t.Fatalf("verdict %s, want invalid", r.Verdict)
	}
	if r.PrimaryCode != aee.CodeVocabularyNotCanonical {
		t.Fatalf("primary code %s, want %s (all: %v)", r.PrimaryCode, aee.CodeVocabularyNotCanonical, r.Codes)
	}
}

// ---------------------------------------------------------------------------
// The covering-payload path
// ---------------------------------------------------------------------------

// TestPayloadLoneSurrogateIsNotIJSON pins the payload path's new code. The path
// was already sound — analyzePayload compares Canonicalize(payload) against the
// payload bytes, and the substituted U+FFFD made that comparison fail — but it
// reported payload-not-canonical for what is an I-JSON violation. With the
// strict parser now byte-strict the fault is caught where it belongs and the
// code is payload-not-ijson, matching the Rust rail, which also rejects the
// payload at its parser. Behavior change with no corpus vector affected: no
// committed vector carries a \u escape or a non-UTF-8 byte anywhere.
func TestPayloadLoneSurrogateIsNotIJSON(t *testing.T) {
	statement := aeetest.Build(aeetest.Options{})

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(statement, &doc); err != nil {
		t.Fatal(err)
	}
	var pred map[string]json.RawMessage
	if err := json.Unmarshal(doc["predicate"], &pred); err != nil {
		t.Fatal(err)
	}
	var records []struct {
		Payload     string          `json:"payload"`
		PayloadType string          `json:"payloadType"`
		Signatures  json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(pred["observationRecords"], &records); err != nil {
		t.Fatal(err)
	}
	// The caught shape carries an interception and the seal that 0.7 makes
	// unconditional. The interception is the record under test and it is
	// first; the seal is rerooted over unchanged.
	if len(records) != 2 {
		t.Fatalf("expected the interception and the seal, got %d record(s)", len(records))
	}

	// "zz" sorts last, so the payload stays canonically ordered and the lone
	// surrogate is the single fault.
	old, err := base64.StdEncoding.DecodeString(records[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload := append(bytes.TrimSuffix(old, []byte("}")), []byte(`,"zz":"\ud800"}`)...)

	other, err := base64.StdEncoding.DecodeString(records[1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	root := aee.MerkleRoot([][32]byte{
		aee.LeafHash(aee.PAE(records[0].PayloadType, payload)),
		aee.LeafHash(aee.PAE(records[1].PayloadType, other)),
	})
	mutated := bytes.Replace(statement, []byte(records[0].Payload),
		[]byte(base64.StdEncoding.EncodeToString(payload)), 1)
	mutated = bytes.Replace(mutated, []byte(mustBatchRoot(t, pred)),
		[]byte(hex.EncodeToString(root[:])), 1)

	r := aee.Verify(mutated, pinnedPolicy())
	if r.Verdict != aee.VerdictInvalid {
		t.Fatalf("verdict %s, want invalid", r.Verdict)
	}
	if r.PrimaryCode != aee.CodePayloadNotIJSON {
		t.Fatalf("primary code %s, want %s (all: %v)", r.PrimaryCode, aee.CodePayloadNotIJSON, r.Codes)
	}
}

func mustBatchRoot(t *testing.T, pred map[string]json.RawMessage) string {
	t.Helper()
	var root string
	if err := json.Unmarshal(pred["batchRoot"], &root); err != nil {
		t.Fatal(err)
	}
	return root
}
