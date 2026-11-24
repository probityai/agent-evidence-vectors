package corpusreaders

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

func drecTInt(n int64) drecInt { return drecInt{n: big.NewInt(n)} }

func drecTCode(err error) string {
	if je, ok := err.(*drecJSONError); ok {
		return je.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestDecisionRecordParserRefusesEachMalformedDocument: every shape the reference
// refuses is refused here under its code, in each mode that refuses it.
func TestDecisionRecordParserRefusesEachMalformedDocument(t *testing.T) {
	for _, text := range []string{
		``, `   `, `{`, `{1:2}`, `{"a" 1}`, `{"a":}`, `{"a":1 "b":2}`, `{"a":1,`, `[`, `[1 2]`, `[1,`,
		`"abc`, `"abc\`, `"\x"`, `"\u12"`, `"\u00g0"`, "\"tab\there\"", `-`, `-a`, `tru`, `nul`, `{} x`, `[1] 2`,
		`[1.]`,
	} {
		for _, mode := range []drecJSONMode{drecStrict, drecBounds, drecLenient} {
			if _, err := drecParse([]byte(text), mode); drecTCode(err) != "not-parseable" {
				t.Errorf("%q in mode %d: want not-parseable, got %q", text, mode, drecTCode(err))
			}
		}
	}
}

func TestDecisionRecordParserReadsWhatOnlyTheLenientModeKeeps(t *testing.T) {
	got, err := drecParse([]byte("\xef\xbb\xbf[NaN, Infinity, -Infinity, 0.10000000000000001, 1e400]"), drecLenient)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := got.([]any)
	if len(list) != 5 {
		t.Fatalf("read %v", got)
	}
	if f, _ := list[0].(float64); !math.IsNaN(f) {
		t.Errorf("NaN read as %v", list[0])
	}
	if f, _ := list[1].(float64); !math.IsInf(f, 1) {
		t.Errorf("Infinity read as %v", list[1])
	}
	if f, _ := list[2].(float64); !math.IsInf(f, -1) {
		t.Errorf("-Infinity read as %v", list[2])
	}
	if f, _ := list[4].(float64); !math.IsInf(f, 1) {
		t.Errorf("1e400 read as %v", list[4])
	}
	lone, err := drecParse([]byte(`["\ud800", "\ud800A", "\ud800\ud800"]`), drecLenient)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range lone.([]any) {
		if !strings.ContainsRune(item.(string), '�') {
			t.Errorf("lone surrogate %d is read as the replacement character, got %q", i, item)
		}
	}
	for _, text := range []string{`["\ud800A"]`, `["\ud800\ud800"]`, `["\udc00"]`} {
		if _, err := drecParse([]byte(text), drecStrict); drecTCode(err) != "lone-surrogate" {
			t.Errorf("%s: want lone-surrogate, got %q", text, drecTCode(err))
		}
	}
}

func TestDecisionRecordParserReadsNumbersAsWritten(t *testing.T) {
	got, err := drecParse([]byte(`[0, -0, 5, 1e5, 1.5E+2, 2.5e-1, 0.1, -3.25, 1e2]`), drecStrict)
	if err != nil {
		t.Fatal(err)
	}
	list := got.([]any)
	if len(list) != 9 {
		t.Fatalf("read %v", got)
	}
	for _, i := range []int{3, 4, 5, 6, 7, 8} {
		if _, isFloat := list[i].(float64); !isFloat {
			t.Errorf("item %d is a float, got %T", i, list[i])
		}
	}
	if f := list[4].(float64); f != 150 {
		t.Errorf("1.5E+2 read as %v", f)
	}
	if _, err := drecParse([]byte(`[1e]`), drecStrict); drecTCode(err) != "not-parseable" {
		t.Errorf("an exponent with no digits leaves data behind: %v", err)
	}
	bounds, err := drecParse([]byte(`[-9007199254740993, 9007199254740991]`), drecBounds)
	if err != nil {
		t.Fatal(err)
	}
	items := bounds.([]any)
	if drecJSONInteger(items[0]) || !drecJSONInteger(items[1]) {
		t.Error("an integer past the exact range is read and marked, one inside is not")
	}
	if drecJSONInteger("text") || drecJSONInteger(1.5) {
		t.Error("only an integer token is an integer")
	}
}

func TestDecisionRecordEqualityIsPythonsAndTheFormats(t *testing.T) {
	inf, nan := math.Inf(1), math.NaN()
	equal := [][2]any{
		{true, drecTInt(1)}, {drecTInt(1), 1.0}, {false, drecTInt(0)}, {nil, nil}, {"a", "a"},
		{inf, inf}, {[]any{drecTInt(1), "x"}, []any{1.0, "x"}},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"a": true}},
	}
	for _, pair := range equal {
		if !drecEq(pair[0], pair[1]) {
			t.Errorf("%v and %v are equal under ==", pair[0], pair[1])
		}
	}
	unequal := [][2]any{
		{drecTInt(1), "1"}, {inf, drecTInt(1)}, {inf, -inf}, {nan, nan}, {nil, drecTInt(0)}, {"a", "b"}, {"a", drecTInt(1)},
		{[]any{drecTInt(1)}, []any{drecTInt(1), drecTInt(2)}}, {[]any{drecTInt(1)}, []any{drecTInt(2)}}, {[]any{}, "x"},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"b": drecTInt(1)}},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"a": drecTInt(2)}},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"a": drecTInt(1), "b": drecTInt(2)}},
		{map[string]any{}, []any{}}, {struct{}{}, struct{}{}},
	}
	for _, pair := range unequal {
		if drecEq(pair[0], pair[1]) {
			t.Errorf("%v and %v are not equal under ==", pair[0], pair[1])
		}
	}
	same := [][2]any{
		{nil, nil}, {true, true}, {"a", "a"}, {drecTInt(2), drecTInt(2)}, {1.5, 1.5},
		{[]any{drecTInt(1), "x"}, []any{drecTInt(1), "x"}},
		{map[string]any{"a": []any{true}}, map[string]any{"a": []any{true}}},
	}
	for _, pair := range same {
		if !drecSame(pair[0], pair[1]) {
			t.Errorf("%v and %v are one value to the format", pair[0], pair[1])
		}
	}
	different := [][2]any{
		{nil, false}, {true, false}, {true, drecTInt(1)}, {"a", "b"}, {"a", drecTInt(1)}, {drecTInt(1), 1.0},
		{drecTInt(1), drecTInt(2)}, {1.5, 2.5}, {1.5, "x"},
		{[]any{drecTInt(1)}, []any{drecTInt(1), drecTInt(2)}}, {[]any{drecTInt(1)}, []any{drecTInt(2)}}, {[]any{}, "x"},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"b": drecTInt(1)}},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"a": drecTInt(2)}},
		{map[string]any{"a": drecTInt(1)}, map[string]any{"a": drecTInt(1), "b": drecTInt(2)}},
		{map[string]any{}, []any{}}, {struct{}{}, struct{}{}},
	}
	for _, pair := range different {
		if drecSame(pair[0], pair[1]) {
			t.Errorf("%v and %v are two values to the format", pair[0], pair[1])
		}
	}
}

func TestDecisionRecordRendersAValueForAFindingAndAKey(t *testing.T) {
	if drecIntValue(drecTInt(7)) != 7 || drecIntValue("x") != 0 {
		t.Error("an integer reads as itself, anything else as 0")
	}
	huge := drecInt{n: new(big.Int).Lsh(big.NewInt(1), 80), unsafe: true}
	if drecIntValue(huge) != 0 {
		t.Error("an integer past 64 bits reads as 0")
	}
	keys := map[string]any{
		"None": nil, "bool:true": true, "str:a": "a", "int:5": drecTInt(5), "float:1.5": 1.5, "other:[1]": []int{1},
	}
	for want, v := range keys {
		if got := drecKey(v); got != want {
			t.Errorf("key of %v: %q, want %q", v, got, want)
		}
	}
	reprs := []struct {
		in   any
		want string
	}{
		{nil, "None"}, {true, "True"}, {false, "False"}, {"a", "'a'"}, {drecTInt(5), "5"}, {2.0, "2.0"}, {1.5, "1.5"},
		{[]any{drecTInt(1), "x"}, "[1 'x']"}, {map[string]any{"b": 1, "a": 2}, "[a b]"}, {struct{}{}, "{}"},
	}
	for _, tc := range reprs {
		if got := drecRepr(tc.in); got != tc.want {
			t.Errorf("repr of %v: %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := drecKeys(map[string]any{"b": 1, "a": 2}); strings.Join(got, ",") != "a,b" {
		t.Errorf("member names sort: %v", got)
	}
}
