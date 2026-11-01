package corpora

// The CPython-compatible encoder, against the spelling it has to match.
//
// Two corpora name a member by the digest of exactly these bytes, so a
// difference anywhere -- key order, the escaping of one character, the
// spelling of a number -- reports every member of those corpora as corrupt
// while the corpus is intact. The expectations below are CPython's own output
// for the same values, and the surrogate case is the one Go's encoder gets
// differently by default.

import (
	"strings"
	"testing"
)

func TestPythonCompactJSONMatchesCPython(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		opts  pyEncodeOpts
		want  string
	}{
		{"sorted members", map[string]any{"b": "2", "a": "1"}, pyEncodeOpts{}, `{"a":"1","b":"2"}`},
		{"no space after separators", []any{"a", "b"}, pyEncodeOpts{}, `["a","b"]`},
		{"null and booleans", map[string]any{"n": nil, "t": true, "f": false}, pyEncodeOpts{},
			`{"f":false,"n":null,"t":true}`},
		{"short escapes", map[string]any{"k": "a\"b\\c\nd\re\tf\bg\fh"}, pyEncodeOpts{},
			`{"k":"a\"b\\c\nd\re\tf\bg\fh"}`},
		{"control characters take the long escape", map[string]any{"k": "\x01\x1f"}, pyEncodeOpts{},
			`{"k":"\u0001\u001f"}`},
		{"DEL is escaped, as CPython escapes everything outside 0x20 to 0x7e",
			map[string]any{"k": "\x7f"}, pyEncodeOpts{EnsureASCII: true}, `{"k":"\u007f"}`},
		{"ensure_ascii escapes above the ASCII range",
			map[string]any{"k": "é"}, pyEncodeOpts{EnsureASCII: true}, `{"k":"\u00e9"}`},
		{"ensure_ascii off emits the character",
			map[string]any{"k": "é"}, pyEncodeOpts{}, `{"k":"é"}`},
		{"a supplementary character becomes a surrogate pair",
			map[string]any{"k": "\U0001F600"}, pyEncodeOpts{EnsureASCII: true}, `{"k":"\ud83d\ude00"}`},
		{"Go's own extra escapes are not applied", map[string]any{"k": "<&>"}, pyEncodeOpts{},
			`{"k":"<&>"}`},
		{"nesting", map[string]any{"a": []any{map[string]any{"b": nil}}}, pyEncodeOpts{},
			`{"a":[{"b":null}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pythonCompactJSONOpts(tc.value, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s want %s", got, tc.want)
			}
		})
	}
}

// TestUTF16OrderDivergesFromCodePointOrder is the property the ok-013 /
// bad-116 pair turns on. A supplementary-plane member name sorts after every
// BMP name by code point and before those above U+E000 by UTF-16 code unit,
// because its high surrogate is 0xD83D.
func TestUTF16OrderDivergesFromCodePointOrder(t *testing.T) {
	value := map[string]any{"\U0001F600": "astral", "ﬀ": "bmp"}
	byCodePoint, err := pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: true})
	if err != nil {
		t.Fatal(err)
	}
	byUTF16, err := pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: true, UTF16Order: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(byCodePoint) == string(byUTF16) {
		t.Fatalf("the two orders agree on %s, so no corpus member could demonstrate a divergence",
			byCodePoint)
	}
	// The astral name is first under UTF-16 order and last under code-point
	// order, which is the whole divergence one corpus pair exists to carry.
	if !strings.HasPrefix(string(byUTF16), `{"\ud83d`) {
		t.Errorf("the astral member name does not sort first by UTF-16 code unit: %s", byUTF16)
	}
	if strings.HasPrefix(string(byCodePoint), `{"\ud83d`) {
		t.Errorf("the astral member name sorts first by code point too, so the pair proves nothing: %s",
			byCodePoint)
	}
	if !utf16Less("\U0001F600", "ﬀ") {
		t.Error("the supplementary name must sort first by UTF-16 code unit")
	}
	if utf16Less("b", "a") || !utf16Less("a", "ab") {
		t.Error("utf16Less disagrees with itself on plain ASCII")
	}
}

// TestTheEncoderRefusesRatherThanGuess: a float and an unmodelled type each
// stop the encoder. A wrong digest computed silently is worse than a refusal,
// because a wrong digest is reported as a corrupt corpus.
func TestTheEncoderRefusesRatherThanGuess(t *testing.T) {
	value, err := decodeJSONNumbers([]byte(`{"k":1.5}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pythonCompactJSON(value); err == nil {
		t.Error("a JSON float was encoded rather than refused")
	}
	if _, err := pythonCompactJSON(map[string]any{"k": 1.5}); err == nil {
		t.Error("a float64 was encoded rather than refused")
	}
	if _, err := pythonCompactJSON(map[string]any{"k": []int{1}}); err == nil {
		t.Error("an unmodelled type was encoded rather than refused")
	}
	if _, err := decodeJSONNumbers([]byte("not json")); err == nil {
		t.Error("unparseable bytes decoded")
	}
	// An integer stays an integer: decoding through float64 would print 1 as 1.0
	// and move every digest that covers it.
	integer, err := decodeJSONNumbers([]byte(`{"k":1}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := pythonCompactJSON(integer)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"k":1}` {
		t.Errorf("got %s want {\"k\":1}", got)
	}
}

// TestNegativeZeroIsWrittenAsCPythonWritesIt: CPython reads the integer token
// -0 as the int 0 and json.dumps writes 0. This encoder used to copy the token
// and wrote -0, so a digest the Go reader took over {"v":-0} differed from the
// one the Python reader took over the same bytes (list message 2026Oct/0038
// measured it: 7b2276223a2d307d against 7b2276223a307d). Every spelling option
// is checked, because agentaction.go writes one record under all three.
func TestNegativeZeroIsWrittenAsCPythonWritesIt(t *testing.T) {
	value, err := decodeJSONNumbers([]byte(`{"v":-0,"w":[-0,0,-1,9007199254740993,-9007199254740993]}`))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"v":0,"w":[0,0,-1,9007199254740993,-9007199254740993]}`
	for _, opts := range []pyEncodeOpts{{EnsureASCII: true}, {}, {UTF16Order: true}} {
		got, err := pythonCompactJSONOpts(value, opts)
		if err != nil {
			t.Fatalf("%+v: %v", opts, err)
		}
		if string(got) != want {
			t.Errorf("%+v: got %s want %s", opts, got, want)
		}
	}
}

// TestHasUnpairedSurrogateEscape covers the reader Go's JSON decoder cannot
// provide: it replaces a lone surrogate escape with U+FFFD, so a member built
// to carry one would be indistinguishable from a valid member after decoding.
func TestHasUnpairedSurrogateEscape(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{`{"k":"plain"}`, false},
		{`{"k":"\ud83d\ude00"}`, false},
		{`{"k":"\ud800"}`, true},
		{`{"k":"\udc00"}`, true},
		{`{"k":"\ud800A"}`, true},
		{`{"k":"\ud800`, true},
		{`{"k":"\uzzzz"}`, false},
		{`{"k":"\n"}`, false},
	} {
		if got := hasUnpairedSurrogateEscape([]byte(tc.line)); got != tc.want {
			t.Errorf("%s: got %t want %t", tc.line, got, tc.want)
		}
	}
}

// TestJSONDepthCountsTheCorpusWay: a scalar sits below level 1, which is the
// convention the extensions-depth pair is built against.
func TestJSONDepthCountsTheCorpusWay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  int
	}{
		{"a scalar", "x", 0},
		{"an empty object", map[string]any{}, 1},
		{"one level", map[string]any{"a": "x"}, 1},
		{"two levels", map[string]any{"a": map[string]any{"b": "x"}}, 2},
		{"through a list", map[string]any{"a": []any{map[string]any{"b": "x"}}}, 3},
	} {
		if got := jsonDepth(tc.value, 1); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}
