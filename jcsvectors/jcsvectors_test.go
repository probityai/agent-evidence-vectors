package jcsvectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

func TestCanonicalCasesAreWellFormed(t *testing.T) {
	vectors, err := Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no canonical vectors")
	}
	for _, v := range vectors {
		if !json.Valid(v.Input) {
			t.Errorf("%s/%s: input is not JSON", v.Corpus, v.ID)
		}
		if !json.Valid(v.Canonical) {
			t.Errorf("%s/%s: canonical bytes are not JSON", v.Corpus, v.ID)
		}
	}
}

func TestRejectCasesCarryNoCanonicalBytes(t *testing.T) {
	vectors, err := Reject()
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no reject vectors")
	}
	for _, v := range vectors {
		// The empty input is itself a refusal case, so the input may be empty.
		if v.Canonical != nil {
			t.Errorf("%s/%s: a reject case carries no canonical bytes", v.Corpus, v.ID)
		}
	}
}

func TestIdentifiersAreUnique(t *testing.T) {
	accept, reject, err := load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range append(accept, reject...) {
		key := v.Corpus + "/" + v.ID
		if seen[key] {
			t.Errorf("duplicate vector %s", key)
		}
		seen[key] = true
	}
}

func TestOnlyRFC8785ClausesFromTheA2ACorpus(t *testing.T) {
	accept, reject, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range append(accept, reject...) {
		if v.Corpus == a2aCorpus && !strings.HasPrefix(v.Clause, rfc8785Clause) {
			t.Errorf("%s: clause %q is not an RFC 8785 clause", v.ID, v.Clause)
		}
	}
}

// TestVectorsDiscriminate runs encoding/json, which is not an RFC 8785
// canonicalizer, over the accept cases. If it matched them all, the vectors
// could not tell a canonicalizer from a plain encoder.
func TestVectorsDiscriminate(t *testing.T) {
	vectors, err := Canonical()
	if err != nil {
		t.Fatal(err)
	}
	misses := 0
	for _, v := range vectors {
		var value any
		if err := json.Unmarshal(v.Input, &value); err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		got, err := json.Marshal(value)
		if err != nil || string(got) != string(v.Canonical) {
			misses++
		}
	}
	if misses == 0 {
		t.Fatal("encoding/json reproduced every canonical vector")
	}
}

func TestDigestMismatchIsRefused(t *testing.T) {
	if err := checkDigest("x", []byte("{}"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("a wrong digest was accepted")
	}
	if err := checkDigest("x", []byte("{}"), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"); err != nil {
		t.Fatal(err)
	}
}

// TestDriftIsWhatGoPrints holds the Go-sourced drift cases to a real run of
// encoding/json: it must print exactly the presented bytes, and those must
// differ from the canonical ones. A case whose claimed source did not behave
// that way would blame Go for output it does not produce.
func TestDriftIsWhatGoPrints(t *testing.T) {
	drifts, err := Drifts()
	if err != nil {
		t.Fatal(err)
	}
	if len(drifts) == 0 {
		t.Fatal("no drift vectors")
	}
	goCases := 0
	families := map[string]bool{}
	for _, d := range drifts {
		families[d.Family] = true
		if string(d.Presented) == string(d.Canonical) {
			t.Errorf("%s: the presented bytes are the canonical bytes", d.ID)
		}
		if d.Source != SourceGo {
			continue
		}
		goCases++
		var value any
		if err := json.Unmarshal(d.Input, &value); err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		got, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		if string(got) != string(d.Presented) {
			t.Errorf("%s: encoding/json printed %q, the case presents %q", d.ID, got, d.Presented)
		}
	}
	if goCases == 0 {
		t.Fatal("no drift vector is sourced from encoding/json")
	}
	for _, family := range []string{"html-escape", "non-ascii-escape", "number-format"} {
		if !families[family] {
			t.Errorf("no drift vector in the %s family", family)
		}
	}
}

func TestDepthCasesStraddleTheCap(t *testing.T) {
	reject, err := TooDeep()
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := DepthAdmitted()
	if err != nil {
		t.Fatal(err)
	}
	if len(reject) != 8 || len(admitted) != 2 {
		t.Fatalf("got %d too deep and %d admitted, want 8 and 2", len(reject), len(admitted))
	}
	for _, v := range reject {
		if got := nesting(v.Input); got <= DepthCap {
			t.Errorf("%s: nested %d deep, not past the cap of %d", v.ID, got, DepthCap)
		}
	}
	for _, v := range admitted {
		if got := nesting(v.Input); got != DepthCap {
			t.Errorf("%s: nested %d deep, want exactly %d", v.ID, got, DepthCap)
		}
		if string(v.Input) != string(v.Canonical) {
			t.Errorf("%s: an already canonical nest must canonicalize to itself", v.ID)
		}
	}
}

func nesting(text []byte) int {
	depth, deepest := 0, 0
	for _, b := range text {
		switch b {
		case '[', '{':
			depth++
			deepest = max(deepest, depth)
		case ']', '}':
			depth--
		}
	}
	return deepest
}

func byteCasesRaw(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := readFile(byteCorpus + "/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// TestRejectCarriesEveryRefusalCase: version 0.1.0 returned none of the 23
// refusal cases, so a canonicalizer that accepted an escaped duplicate name,
// invalid UTF-8 or trailing content passed every test the module offered.
func TestRejectCarriesEveryRefusalCase(t *testing.T) {
	reject, err := Reject()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string][]byte{}
	for _, v := range reject {
		if v.Corpus == byteCorpus {
			byID[v.ID] = v.Input
		}
	}
	var refusals []struct {
		ID       string  `json:"id"`
		Input    *string `json:"input"`
		InputHex *string `json:"inputHex"`
	}
	if err := json.Unmarshal(byteCasesRaw(t)["refusalCases"], &refusals); err != nil {
		t.Fatal(err)
	}
	if len(refusals) == 0 {
		t.Fatal("no refusal cases")
	}
	for _, r := range refusals {
		var want []byte
		switch {
		case r.InputHex != nil:
			decoded, err := hex.DecodeString(*r.InputHex)
			if err != nil {
				t.Fatalf("%s: inputHex: %v", r.ID, err)
			}
			want = decoded
		case r.Input != nil:
			want = []byte(*r.Input)
		default:
			t.Fatalf("%s: no input", r.ID)
		}
		got, ok := byID[r.ID]
		if !ok {
			t.Errorf("%s: refusal case missing from Reject()", r.ID)
		} else if !bytes.Equal(got, want) {
			t.Errorf("%s: input bytes differ", r.ID)
		}
	}
	for _, id := range []string{
		"refuse-duplicate-member-escaped-spelling",
		"refuse-unicode-invalid-utf8-byte",
		"refuse-unicode-surrogate-encoded-in-utf8",
		"refuse-trailing-second-value",
		"refuse-trailing-garbage",
		"refuse-non-finite-overflow-positive",
		"refuse-non-finite-overflow-negative",
		"refuse-non-finite-overflow-large-mantissa",
	} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s: a lenient canonicalizer's counter-example is not in Reject()", id)
		}
	}
}

// TestEveryByteCorpusFamilyIsRead: a family added to cases.json fails this
// test until the module reads it, rather than being dropped silently.
func TestEveryByteCorpusFamilyIsRead(t *testing.T) {
	read := map[string]bool{
		"format": true, "canonicalCases": true, "rejectCases": true,
		"driftCases": true, "depthCases": true, "refusalCases": true,
		"invalidInputCases": true, "noncharacterCases": true,
		// Field-digest preimages are not canonicalizer cases.
		"preimageCases": true,
	}
	for key := range byteCasesRaw(t) {
		if !read[key] {
			t.Errorf("cases.json family %s is not read by this module", key)
		}
	}
}

// TestEveryEmbeddedFileHasItsDigest: every file under FS is in the generated
// digest table and hashes to it.
func TestEveryEmbeddedFileHasItsDigest(t *testing.T) {
	n := 0
	err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		_, err = readFile(path)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != len(fileDigests) {
		t.Fatalf("%d embedded files, %d recorded digests", n, len(fileDigests))
	}
}
