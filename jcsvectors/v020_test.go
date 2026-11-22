package jcsvectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

func TestNumberFeatures(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []Feature
	}{
		{`{"n":1}`, []Feature{FeatureInteger}},
		{`{"n":9007199254740991}`, []Feature{FeatureInteger}},
		{`{"n":-9007199254740991}`, []Feature{FeatureInteger}},
		{`{"n":9007199254740992}`, []Feature{FeatureUnsafeInteger}},
		{`{"n":-9007199254740993}`, []Feature{FeatureUnsafeInteger}},
		{`{"n":1000.0}`, []Feature{FeatureFraction}},
		{`{"n":1e3}`, []Feature{FeatureExponent}},
		{`{"n":1E3}`, []Feature{FeatureExponent}},
		{`{"n":-1.5e-7}`, []Feature{FeatureExponent, FeatureFraction}},
		{`{"n":00000000000000000000001}`, []Feature{FeatureInteger}},
		{`{"n":-00000000000000009007199254740992}`, []Feature{FeatureUnsafeInteger}},
		{`{"n":1-2}`, []Feature{}},
		{`{"n":-0}`, []Feature{FeatureInteger, FeatureNegativeZero}},
		{`{"n":-0.0}`, []Feature{FeatureFraction, FeatureNegativeZero}},
		{`{"n":-Infinity}`, []Feature{}},
		{`{"s":"1.5e3"}`, []Feature{}},
		{`{"s":"a\"1.5"}`, []Feature{FeatureEscape}},
		{`{"s":"caf\u00e9"}`, []Feature{FeatureEscape}},
		{"{\"s\":\"caf\xc3\xa9\"}", []Feature{FeatureNonASCII}},
		{"[\"\xff\"]", []Feature{FeatureNonASCII, FeatureNotUTF8}},
	} {
		got := features([]byte(tc.input), nil)
		if !slices.Equal(got, tc.want) {
			t.Errorf("features(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
	// A token of a million digits is read in one pass, as unsafe.
	long := bytes.Repeat([]byte("1"), 1<<20)
	long[0], long[len(long)-1] = '[', ']'
	if got := features(long, nil); !slices.Equal(got, []Feature{FeatureUnsafeInteger}) {
		t.Errorf("features of a million-digit integer = %v", got)
	}
	// An escaped non-ASCII character prints as raw UTF-8, so the canonical
	// bytes carry the feature even where the input is ASCII.
	if got := features([]byte(`["\u00e9"]`), []byte("[\"\xc3\xa9\"]")); !slices.Contains(got, FeatureNonASCII) {
		t.Errorf("non-ascii canonical output not detected: %v", got)
	}
}

func TestEveryVectorCarriesItsFeatures(t *testing.T) {
	accept, reject, err := load()
	if err != nil {
		t.Fatal(err)
	}
	deep, err := TooDeep()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range append(append(accept, reject...), deep...) {
		if !slices.IsSorted(v.Features) || len(slices.Compact(slices.Clone(v.Features))) != len(v.Features) {
			t.Errorf("%s/%s: features %v are not sorted and unique", v.Corpus, v.ID, v.Features)
		}
		if !slices.Equal(v.Features, features(v.Input, v.Canonical)) {
			t.Errorf("%s/%s: features differ from its bytes", v.Corpus, v.ID)
		}
	}
}

// TestIntegerOnlyProfile: the profile excludes exactly the accept cases that
// write a fraction, an exponent or an unsafe integer, keeps every case that
// must be refused, and the frozen a2a corpus splits as the matrix reported
// for an integer-only canonicalizer: 11 of its 53 RFC 8785 vectors carry such
// a number.
func TestIntegerOnlyProfile(t *testing.T) {
	accept, reject, err := load()
	if err != nil {
		t.Fatal(err)
	}
	all := append(accept, reject...)
	in, out, err := Filter(ProfileIntegerOnly, all)
	if err != nil {
		t.Fatal(err)
	}
	if len(in)+len(out) != len(all) || len(in) == 0 || len(out) == 0 {
		t.Fatalf("split %d in and %d out of %d", len(in), len(out), len(all))
	}
	nonInteger := func(v Vector) bool {
		return slices.Contains(v.Features, FeatureFraction) || slices.Contains(v.Features, FeatureExponent) ||
			slices.Contains(v.Features, FeatureUnsafeInteger)
	}
	for _, v := range in {
		if v.Canonical != nil && nonInteger(v) {
			t.Errorf("%s/%s is in the integer-only profile with %v", v.Corpus, v.ID, v.Features)
		}
	}
	a2aOut := 0
	for _, v := range out {
		if !nonInteger(v) {
			t.Errorf("%s/%s is out of the integer-only profile with %v", v.Corpus, v.ID, v.Features)
		}
		if v.Canonical == nil {
			t.Errorf("%s/%s must be refused, yet is out of the integer-only profile", v.Corpus, v.ID)
		}
		if v.Corpus == a2aCorpus {
			a2aOut++
		}
	}
	if a2aOut != 11 {
		t.Errorf("%d a2a vectors out of the integer-only profile, want 11", a2aOut)
	}
	// "[1e999]" is refused by every profile: an integer-only canonicalizer
	// that accepts it and prints anything has failed, not left its profile.
	reject, err = Reject()
	if err != nil {
		t.Fatal(err)
	}
	keptRefusals, skipped, err := Filter(ProfileIntegerOnly, reject)
	if err != nil || len(skipped) != 0 || len(keptRefusals) != len(reject) {
		t.Errorf("integer-only kept %d and dropped %d of %d refusals (%v)", len(keptRefusals), len(skipped), len(reject), err)
	}
	nonFinite := 0
	for _, v := range keptRefusals {
		if strings.HasPrefix(v.ID, "refuse-non-finite-overflow") && nonInteger(v) {
			nonFinite++
		}
	}
	if nonFinite != 3 {
		t.Errorf("%d non-finite overflow refusals with an exponent kept in the integer-only profile, want 3", nonFinite)
	}
	if ok, err := Profile("integer").Includes(Vector{}); ok || err == nil {
		t.Error("an unknown profile included a refusal")
	}
	full, none, err := Filter(ProfileRFC8785, all)
	if err != nil || len(full) != len(all) || len(none) != 0 {
		t.Errorf("rfc8785 profile split %d and %d of %d (%v)", len(full), len(none), len(all), err)
	}
	if _, _, err := Filter(Profile("integer"), all); err == nil {
		t.Error("an unknown profile was accepted")
	}
	if ok, err := Profile("").Admits(nil); ok || err == nil {
		t.Error("the empty profile was accepted")
	}
	if got := Profiles(); len(got) != len(excluded) {
		t.Errorf("Profiles() lists %d, %d are defined", len(got), len(excluded))
	}
}

// TestOneByteEditIsRefused edits one byte of an embedded file in a copy of
// the module's files: every reader must refuse it rather than return a
// silently different test.
func TestOneByteEditIsRefused(t *testing.T) {
	for _, name := range []string{
		byteCorpus + "/cases.json",
		a2aCorpus + "/MANIFEST.json",
		a2aCorpus + "/a3-object-key-ordering/A3-001.json",
	} {
		copied := fstest.MapFS{}
		err := fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := fs.ReadFile(FS, path)
			if err != nil {
				return err
			}
			if path == name {
				data = slices.Clone(data)
				data[len(data)/2] ^= 0x01
			}
			copied[path] = &fstest.MapFile{Data: data}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		source = copied
		_, errCanonical := Canonical()
		_, errDiff := ParserDifferential()
		source = FS
		if errCanonical == nil {
			t.Errorf("%s edited by one byte: Canonical returned no error", name)
		}
		if name == byteCorpus+"/cases.json" && errDiff == nil {
			t.Errorf("%s edited by one byte: ParserDifferential returned no error", name)
		}
	}
	if _, err := Canonical(); err != nil {
		t.Fatalf("the module's own files were not restored: %v", err)
	}
}

func TestParserDifferential(t *testing.T) {
	cases, err := ParserDifferential()
	if err != nil {
		t.Fatal(err)
	}
	var all []Differential
	cases(func(d Differential) bool {
		all = append(all, d)
		return true
	})
	if len(all) == 0 {
		t.Fatal("no parser-differential cases")
	}
	seen := map[string]bool{}
	families := map[string]int{}
	for _, d := range all {
		if seen[d.ID] {
			t.Errorf("duplicate case %s", d.ID)
		}
		seen[d.ID] = true
		families[d.Family]++
		if d.BoundedError == "" {
			t.Errorf("%s: every differential is refused by the bounded profile", d.ID)
		}
		if !d.Accepted() && d.Canonical != nil {
			t.Errorf("%s: a case RFC 8785 refuses carries canonical bytes", d.ID)
		}
		if strings.HasPrefix(d.ID, "noncharacter-neighbour") {
			t.Errorf("%s: a control case was yielded", d.ID)
		}
	}
	for _, family := range []string{"duplicate-member", "invalid-unicode", "non-finite", "trailing-content", "syntax", "noncharacter", "unsafe-integer", "non-integer"} {
		if families[family] == 0 {
			t.Errorf("no differential in the %s family", family)
		}
	}
	// Every byte-corpus refusal is yielded.
	reject, err := Reject()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range reject {
		if v.Corpus == byteCorpus && !seen[v.ID] {
			t.Errorf("%s: a byte-corpus refusal is not a differential", v.ID)
		}
	}
	// The cases discriminate: encoding/json, a lenient reader, decodes some
	// input the bounded profile refuses (the duplicate members among them),
	// and not all of it.
	lenient := 0
	for _, d := range all {
		var value any
		if json.Unmarshal(d.Input, &value) == nil {
			lenient++
		}
	}
	if lenient == 0 || lenient == len(all) {
		t.Errorf("encoding/json decoded %d of %d differentials; the set does not discriminate", lenient, len(all))
	}
	// A reader that edits its input in place cannot change the next pass.
	cases(func(d Differential) bool {
		for _, b := range [][]byte{d.Input, d.Canonical} {
			for i := range b {
				b[i] ^= 0xff
			}
		}
		if len(d.Features) > 0 {
			d.Features[0] = "edited"
		}
		return true
	})
	// Compare with a fresh read: the cases collected above may share bytes
	// with the iterator, so they cannot serve as the reference.
	fresh, err := ParserDifferential()
	if err != nil {
		t.Fatal(err)
	}
	var want []Differential
	fresh(func(d Differential) bool {
		want = append(want, d)
		return true
	})
	i := 0
	cases(func(d Differential) bool {
		if i >= len(want) {
			i++
			return true
		}
		w := want[i]
		if !bytes.Equal(d.Input, w.Input) || !bytes.Equal(d.Canonical, w.Canonical) || !slices.Equal(d.Features, w.Features) ||
			(d.Canonical == nil) != (w.Canonical == nil) {
			t.Errorf("%s: an edit in one pass reached the next", d.ID)
		}
		i++
		return true
	})
	if i != len(want) {
		t.Errorf("second pass yielded %d of %d", i, len(want))
	}
	// A yield that returns false stops the iterator, as a break does.
	n := 0
	cases(func(Differential) bool {
		n++
		return false
	})
	if n != 1 {
		t.Errorf("the iterator ran %d times after a break", n)
	}
}

// summaryRow is one case as the npm twin also prints it. The cross-language
// test compares the two lists, so a disposition, a digest or a feature that
// differs between the packages fails it.
type summaryRow struct {
	Kind            string    `json:"kind"`
	Corpus          string    `json:"corpus"`
	ID              string    `json:"id"`
	Clause          string    `json:"clause"`
	Family          string    `json:"family"`
	InputSHA256     string    `json:"input_sha256"`
	CanonicalSHA256 *string   `json:"canonical_sha256"`
	Features        []Feature `json:"features"`
	Error           string    `json:"error"`
	BoundedError    string    `json:"bounded_error"`
	IntegerOnly     bool      `json:"integer_only"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func summary(t *testing.T) []summaryRow {
	t.Helper()
	var rows []summaryRow
	// inProfile is what Filter decides for a vector, and what Admits decides
	// for a drift or a differential, which no reader filters.
	row := func(kind, corpus, id, clause, family string, input, canonical []byte, feats []Feature, errCode, bounded string,
		inProfile func() (bool, error)) {
		r := summaryRow{Kind: kind, Corpus: corpus, ID: id, Clause: clause, Family: family, InputSHA256: digest(input),
			Features: feats, Error: errCode, BoundedError: bounded}
		if feats == nil {
			r.Features = []Feature{}
		}
		if canonical != nil {
			s := digest(canonical)
			r.CanonicalSHA256 = &s
		}
		ok, err := inProfile()
		if err != nil {
			t.Fatal(err)
		}
		r.IntegerOnly = ok
		rows = append(rows, r)
	}
	for _, kind := range []struct {
		name string
		read func() ([]Vector, error)
	}{{"canonical", Canonical}, {"reject", Reject}, {"too-deep", TooDeep}, {"depth-admitted", DepthAdmitted}} {
		vectors, err := kind.read()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vectors {
			row(kind.name, v.Corpus, v.ID, v.Clause, "", v.Input, v.Canonical, v.Features, "", "",
				func() (bool, error) { return ProfileIntegerOnly.Includes(v) })
		}
	}
	drifts, err := Drifts()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range drifts {
		feats := features(d.Input, d.Canonical)
		row("drift", byteCorpus, d.ID, "", d.Family, d.Input, d.Canonical, feats, "", "",
			func() (bool, error) { return ProfileIntegerOnly.Admits(feats) })
	}
	cases, err := ParserDifferential()
	if err != nil {
		t.Fatal(err)
	}
	cases(func(d Differential) bool {
		row("differential", byteCorpus, d.ID, "", d.Family, d.Input, d.Canonical, d.Features, d.Error, d.BoundedError,
			func() (bool, error) { return ProfileIntegerOnly.Admits(d.Features) })
		return true
	})
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Corpus != b.Corpus {
			return a.Corpus < b.Corpus
		}
		return a.ID < b.ID
	})
	return rows
}

// TestWriteSummary builds the summary the npm twin's cross-language test
// compares with its own, and writes it when JCSVECTORS_SUMMARY names a file.
// CI sets it.
func TestWriteSummary(t *testing.T) {
	rows := summary(t)
	if len(rows) == 0 {
		t.Fatal("empty summary")
	}
	path := os.Getenv("JCSVECTORS_SUMMARY")
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(rows, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("[")) {
		t.Fatal("summary is not a list")
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
