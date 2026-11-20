package corpusreaders

// The strict I-JSON reader and the Python-equality helpers behind the OCSF
// decision reader, each held to a value or refusal worked out from RFC 7493 and
// Python's semantics rather than from this code's own output.

import (
	"math/big"
	"strings"
	"testing"
)

func TestOCSFParseRefusals(t *testing.T) {
	deep := strings.Repeat("[", 130) + strings.Repeat("]", 130)
	cases := []struct{ name, text, want string }{
		{"bad utf8", "\"\xff\"", "not-utf8"},
		{"byte order mark", "\xef\xbb\xbf{}", "not-utf8"},
		{"extra data", "{} 1", "not-parseable"},
		{"empty", "  ", "not-parseable"},
		{"NaN", "NaN", "non-json-number"},
		{"Infinity", "Infinity", "non-json-number"},
		{"stray character", "?", "not-parseable"},
		{"duplicate member", `{"a":1,"a":2}`, "duplicate-member"},
		{"duplicate after escape", `{"a":1,"a":2}`, "duplicate-member"},
		{"non-string name", `{1:2}`, "not-parseable"},
		{"missing colon", `{"a" 1}`, "not-parseable"},
		{"missing comma", `{"a":1 "b":2}`, "not-parseable"},
		{"unterminated object", `{"a":1`, "not-parseable"},
		{"unterminated array", `[1`, "not-parseable"},
		{"missing array comma", `[1 2]`, "not-parseable"},
		{"unterminated string", `"abc`, "not-parseable"},
		{"control character", "\"a\x01b\"", "not-parseable"},
		{"invalid escape", `"\x"`, "not-parseable"},
		{"short unicode escape", `"\u12"`, "not-parseable"},
		{"lone high surrogate", `"\ud800"`, "lone-surrogate"},
		{"lone low surrogate", `"\udc00"`, "lone-surrogate"},
		{"high surrogate then non-low", `"\ud800A"`, "lone-surrogate"},
		{"bare minus", `-`, "not-parseable"},
		{"integer past 64 bits", `18446744073709551616`, "unsafe-integer"},
		{"integer below 64 bits", `-9223372036854775809`, "unsafe-integer"},
		{"float another number", `0.10000000000000001`, "value-not-representable"},
		{"float underflow", `1e-400`, "value-not-representable"},
		{"float overflow", `1e400`, "value-not-representable"},
		{"too deep", deep, "nesting-too-deep"},
		{"too deep object", strings.Repeat(`{"a":`, 130) + "1" + strings.Repeat("}", 130), "nesting-too-deep"},
	}
	for _, c := range cases {
		_, err := ocsfParse(c.text)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s: err %v, want prefix %q", c.name, err, c.want)
		}
	}
}

func TestOCSFParseValues(t *testing.T) {
	v, err := ocsfParse(` {"s":"a\"\\\/\b\f\n\r\té😀","t":true,"f":false,"n":null,"i":-0,"a":[1,2.5,1.10,1e2]} `)
	if err != nil {
		t.Fatal(err)
	}
	if got := ocsfGet(v, "s"); got != "a\"\\/\b\f\n\r\té\U0001F600" {
		t.Errorf("string escapes read as %q", got)
	}
	if ocsfGet(v, "t") != true || ocsfGet(v, "f") != false || ocsfGet(v, "n") != nil {
		t.Errorf("literals read wrong: %v", v)
	}
	arr, _ := ocsfGet(v, "a").([]any)
	if len(arr) != 4 || !ocsfIsInt(arr[0]) || ocsfIsInt(arr[1]) || ocsfIsInt(arr[3]) {
		t.Fatalf("numbers read wrong: %v", arr)
	}
	if ocsfInt(arr[0]).Int64() != 1 {
		t.Errorf("1 read as %v", ocsfInt(arr[0]))
	}
	if s := arr[1].(ocsfNum).String(); s != "2.5" {
		t.Errorf("2.5 prints as %q", s)
	}
	if s := arr[0].(ocsfNum).String(); s != "1" {
		t.Errorf("1 prints as %q", s)
	}
}

func TestOCSFParseWideInteger(t *testing.T) {
	// 1763600000123456789 is a real nanosecond epoch: past 2**53, inside 64 bits, and
	// not a double. 1763600000000000000 happens to be one (17636 * 10**14).
	v, err := ocsfParse(`{"t":1763600000123456789,"e":1763600000000000000,"u":18446744073709551615,"s":9007199254740991}`)
	if err != nil {
		t.Fatal(err)
	}
	if paths := ocsfWidePaths(v, ""); len(paths) != 2 {
		t.Errorf("wide paths %v, want /t and /u (2**64-1 rounds to 2**64; 2**53-1 and 17636*10**14 are exact)", paths)
	}
	if paths := ocsfWidePaths(ocsfNum{isInt: true, i: big.NewInt(1), wide: false}, ""); len(paths) != 0 {
		t.Errorf("a small integer is not wide: %v", paths)
	}
	root, err := ocsfParse(`[9007199254740993]`)
	if err != nil {
		t.Fatal(err)
	}
	if paths := ocsfWidePaths(root, "x"); len(paths) != 1 || paths[0] != "x/0" {
		t.Errorf("array path %v", paths)
	}
	if paths := ocsfWidePaths(ocsfNum{isInt: true, i: big.NewInt(1 << 60), wide: true}, ""); len(paths) != 0 {
		t.Errorf("2**60 is exact as a double, so it is not wide: %v", paths)
	}
}

func TestOCSFParseEnvelopeIsUnbounded(t *testing.T) {
	big64 := `{"n":123456789012345678901234567890,"f":1.10000000000000001}`
	if _, err := ocsfParse(big64); err == nil {
		t.Error("strict mode must refuse an integer outside 64 bits")
	}
	v, err := ocsfParseEnvelope(big64)
	if err != nil {
		t.Fatalf("envelope mode: %v", err)
	}
	if ocsfInt(ocsfGet(v, "n")).String() != "123456789012345678901234567890" {
		t.Errorf("envelope integer read as %v", ocsfGet(v, "n"))
	}
	if _, err := ocsfParseEnvelope(`1e400`); err == nil || !strings.HasPrefix(err.Error(), "value-not-representable") {
		t.Errorf("envelope overflow: %v", err)
	}
}

func TestOCSFDecomposeAndFiniteFloat(t *testing.T) {
	equalPairs := [][2]string{{"1.10", "1.1"}, {"100", "1e2"}, {"0.5", "5e-1"}, {"0.0", "0e5"}, {"-2.50", "-2.5"}}
	for _, p := range equalPairs {
		a, ok1 := ocsfDecompose(p[0])
		b, ok2 := ocsfDecompose(p[1])
		if !ok1 || !ok2 || !a.equal(b) {
			t.Errorf("%s and %s name one number: %+v %+v", p[0], p[1], a, b)
		}
	}
	diff := [][2]string{{"1.1", "1.2"}, {"1.5", "-1.5"}, {"1e2", "1e3"}, {"0", "0.5"}}
	for _, p := range diff {
		a, _ := ocsfDecompose(p[0])
		b, _ := ocsfDecompose(p[1])
		if a.equal(b) {
			t.Errorf("%s and %s are different numbers", p[0], p[1])
		}
	}
	if d, ok := ocsfDecompose("1e99999999999999999999"); ok || d.digits != "" {
		t.Errorf("an exponent past int64 on a nonzero mantissa names no double: %+v %v", d, ok)
	}
	if d, ok := ocsfDecompose("0e99999999999999999999"); !ok || d.digits != "" {
		t.Errorf("a zero mantissa is zero whatever the exponent: %+v %v", d, ok)
	}
	if f, err := ocsfFiniteFloat("1.10"); err != nil || f != 1.1 {
		t.Errorf("1.10 reads as %v %v", f, err)
	}
	if _, err := ocsfFiniteFloat("1.x"); err == nil || !strings.HasPrefix(err.Error(), "not-parseable") {
		t.Errorf("a malformed token: %v", err)
	}
	if _, err := ocsfFiniteFloat("1e99999999999999999999"); err == nil {
		t.Error("an exponent past int64 must be refused")
	}
}

func num(i int64) ocsfNum   { return ocsfNum{isInt: true, i: big.NewInt(i)} }
func flt(f float64) ocsfNum { return ocsfNum{f: f} }

func TestPyEqualFollowsPython(t *testing.T) {
	equal := [][2]any{
		{num(1), true}, {num(0), false}, {flt(1.0), num(1)}, {true, flt(1.0)},
		{nil, nil}, {"a", "a"},
		{[]any{num(1), "x"}, []any{flt(1.0), "x"}},
		{map[string]any{"k": num(2)}, map[string]any{"k": flt(2.0)}},
	}
	for i, p := range equal {
		if !pyEqual(p[0], p[1]) {
			t.Errorf("equal pair %d: %v == %v is True in Python", i, p[0], p[1])
		}
	}
	unequal := [][2]any{
		{num(1), num(2)}, {num(1), "1"}, {"1", num(1)}, {nil, num(0)}, {nil, false},
		{"a", "b"}, {"a", num(1)},
		{[]any{num(1)}, []any{num(1), num(2)}}, {[]any{num(1)}, "x"}, {[]any{num(1)}, []any{num(2)}},
		{map[string]any{"k": num(1)}, map[string]any{"j": num(1)}},
		{map[string]any{"k": num(1)}, map[string]any{"k": num(2)}},
		{map[string]any{"k": num(1)}, map[string]any{"k": num(1), "j": num(1)}},
		{map[string]any{"k": num(1)}, []any{}},
		{flt(0.5), num(0)}, {struct{}{}, struct{}{}},
	}
	for i, p := range unequal {
		if pyEqual(p[0], p[1]) {
			t.Errorf("unequal pair %d: %v == %v is False in Python", i, p[0], p[1])
		}
	}
	if !pyEqualInt(flt(3.0), 3) || pyEqualInt("3", 3) {
		t.Error("pyEqualInt: 3.0 == 3 and '3' != 3")
	}
}

func TestPyTruthAcceptsZeroAndOne(t *testing.T) {
	cases := []struct {
		v         any
		val, isTF bool
	}{
		{true, true, true}, {false, false, true}, {num(1), true, true}, {num(0), false, true},
		{flt(1.0), true, true}, {flt(0.0), false, true},
		{num(2), false, false}, {flt(0.5), false, false}, {"true", false, false}, {nil, false, false},
	}
	for _, c := range cases {
		if val, ok := pyTruth(c.v); val != c.val || ok != c.isTF {
			t.Errorf("pyTruth(%v) = %v, %v; want %v, %v", c.v, val, ok, c.val, c.isTF)
		}
	}
	if _, ok := ocsfRat(flt(1)); !ok {
		t.Error("a finite float is a rational")
	}
}

func TestOCSFInstantOf(t *testing.T) {
	epoch := int64(719163) * 86400 // 1970-01-01 is day 719163 in Python's ordinal
	cases := []struct {
		in   any
		want string // "" when an instant, else the reason
		secs int64
	}{
		{"1970-01-01T00:00:00Z", "", epoch},
		{"1970-01-01T01:00:00+01:00", "", epoch},
		{"1969-12-31T19:00:00-05:00", "", epoch},
		{"1970-01-01T00:00:00Z\n", "", epoch},
		{"2024-02-29T00:00:00Z", "", 0},
		{"2023-02-29T00:00:00Z", "no such date", 0},
		{"1900-02-29T00:00:00Z", "no such date", 0},
		{"2000-02-29T00:00:00Z", "", 0},
		{"2024-04-31T00:00:00Z", "no such date", 0},
		{"2024-13-01T00:00:00Z", "no such date", 0},
		{"0000-01-01T00:00:00Z", "no such date", 0},
		{"2024-01-01T24:00:00Z", "no such time", 0},
		{"2024-01-01T00:60:00Z", "no such time", 0},
		{"2024-01-01T00:00:60Z", "no such time", 0},
		{"2024-01-01T00:00:00+24:00", "no such offset", 0},
		{"2024-01-01T00:00:00+00:60", "no such offset", 0},
		{"2024-01-01T00:00:00", "no offset", 0},
		{"yesterday", "not a time", 0},
		{12, "not a time", 0},
	}
	for _, c := range cases {
		got := ocsfInstantOf(c.in)
		if c.want != "" {
			if got.ok() || got.why != c.want {
				t.Errorf("%v: ok=%v why=%q, want %q", c.in, got.ok(), got.why, c.want)
			}
			continue
		}
		if !got.ok() {
			t.Errorf("%v: refused as %q", c.in, got.why)
			continue
		}
		if c.secs != 0 && !(got.secs.IsInt() && got.secs.Num().Int64() == c.secs) {
			t.Errorf("%v: %v seconds, want %d", c.in, got.secs, c.secs)
		}
	}
	frac := ocsfInstantOf("1970-01-01T00:00:00.25Z")
	if !frac.ok() || frac.secs.Cmp(new(big.Rat).Add(new(big.Rat).SetInt64(epoch), big.NewRat(1, 4))) != 0 {
		t.Errorf("a fraction of a second is exact: %v", frac.secs)
	}
}

func TestOCSFCanonSortsKeysAsUTF16(t *testing.T) {
	v, err := ocsfParse(`{"b":[1,{"z":null,"a":true}],"a":"é😀","😀":0,"ﬁ":1}`)
	if err != nil {
		t.Fatal(err)
	}
	// UTF-16 order puts U+1F600 (surrogate D83D) before U+FB01.
	want := `{"a":"é😀","b":[1,{"a":true,"z":null}],"😀":0,"ﬁ":1}`
	if got := ocsfCanon(v); got != want {
		t.Errorf("canonical form\n got %s\nwant %s", got, want)
	}
}
