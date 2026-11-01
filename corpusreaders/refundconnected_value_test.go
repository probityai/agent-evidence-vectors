package corpora

// Direct tests of the value layer of the refund-connected reader: the parser
// escapes, canonical bytes, comparisons, iteration and the decoders. The
// expected values are what the Python reader gives for the same input.

import (
	"bytes"
	"math/big"
	"testing"
)

func rcMustFault(t *testing.T, class string, fn func()) {
	t.Helper()
	if got := rcCatch(fn, class); got == nil {
		t.Fatalf("expected a %s fault", class)
	}
}

func rcJ(t *testing.T, doc string) any {
	t.Helper()
	return rcParse([]byte(doc))
}

func TestRCParseEscapes(t *testing.T) {
	cases := map[string]string{
		`"é"`:                    "é",
		`"😀"`:                    "\U0001F600",
		`"a\"b\\c\/d\b\f\n\r\t"`: "a\"b\\c/d\b\f\n\r\t",
		`"\ud83dx"`:              "\xed\xa0\xbdx",
		`"\ud83dA"`:              "\xed\xa0\xbdA",
		`"\ude00"`:               "\xed\xb8\x80",
	}
	for doc, want := range cases {
		if got := rcJ(t, doc); got != want {
			t.Errorf("%s parsed to %q, want %q", doc, got, want)
		}
	}
	if !rcHasSurrogate(rcJ(t, `"\ud83d"`).(string)) {
		t.Error("a lone surrogate must be kept")
	}
	if rcHasSurrogate("plain é") {
		t.Error("no surrogate in plain text")
	}
	rcMustFault(t, "ValueError", func() { rcUTF8(rcJ(t, `"\ud83d"`).(string)) })
	if got := rcUTF8("ok"); string(got) != "ok" {
		t.Error("rcUTF8 of plain text")
	}
}

func TestRCParseBad(t *testing.T) {
	for _, doc := range []string{
		`"\x"`, `"\u12"`, `"\u12G4"`, `"\u+123"`, `"\ud83d\u12"`, `"abc`, `"abc\`, "\"a\x01b\"",
		`[1,]`, `{"a":1,"a":2}`, `1.5`, `1 2`, ``, `[`, `{"a"}`, `tru`, `-`, `NaN`,
	} {
		rcMustFault(t, "ValueError", func() { rcParse([]byte(doc)) })
	}
	rcMustFault(t, "ValueError", func() { rcParse([]byte{0xff}) })
	rcMustFault(t, "ValueError", func() { rcParse([]byte("\xef\xbb\xbf1")) })
	deep := bytes.Repeat([]byte("["), rcMaxDepth+2)
	rcMustFault(t, "RecursionError", func() { rcParse(deep) })
	deepObj := bytes.Repeat([]byte(`{"a":`), rcMaxDepth+2)
	rcMustFault(t, "RecursionError", func() { rcParse(deepObj) })
}

func TestRCJCS(t *testing.T) {
	doc := `{"b":[1,true,null,"x\u0001\"\\\n"],"a":"😀","":2,"😀k":3}`
	want := "{\"a\":\"\U0001F600\",\"b\":[1,true,null,\"x\\u0001\\\"\\\\\\n\"],\"\U0001F600k\":3,\"\":2}"
	if got := string(rcJCS(rcJ(t, doc))); got != want {
		t.Errorf("jcs gave %q, want %q", got, want)
	}
	rcMustFault(t, "ValueError", func() { rcJCS(rcJ(t, `["\ud83d"]`)) })
	rcMustFault(t, "ValueError", func() { rcJCS(rcJ(t, `{"\ud83d":1}`)) })
	if !rcUTF16Less("a", "ab") || rcUTF16Less("ab", "a") || !rcUTF16Less("\U0001F600", "") {
		t.Error("UTF-16 ordering")
	}
	if rcRefOf(rcJ(t, `{}`)) != rcFileRef([]byte("{}")) {
		t.Error("ref of an empty object")
	}
}

func TestRCDigitValueAndAtoi(t *testing.T) {
	for r, want := range map[rune]int{'7': 7, '٣': 3, 0x1D7DC: 4, 'x': 0, '0': 0} {
		if got := rcDigitValue(r); got != want {
			t.Errorf("rcDigitValue(%U) = %d, want %d", r, got, want)
		}
	}
	if rcAtoi(" 9") != 9 || rcAtoi("١٢") != 12 {
		t.Error("rcAtoi")
	}
}

func rcBig(n int64) *big.Int { return big.NewInt(n) }

func TestRCEqualityAndKinds(t *testing.T) {
	obj := rcJ(t, `{"a":1,"b":[1,2]}`)
	if rcKind(nil) != "none" || rcKind(true) != "bool" || rcKind(rcBig(1)) != "int" ||
		rcKind("s") != "str" || rcKind([]any{}) != "list" || rcKind(obj) != "dict" {
		t.Error("rcKind")
	}
	if rcBoolInt(true) != 1 || rcBoolInt(false) != 0 {
		t.Error("rcBoolInt")
	}
	if !rcEq(true, rcBig(1)) || rcEq(rcBig(2), true) || !rcEq(nil, nil) || rcEq(nil, "x") || rcEq("a", rcBig(1)) {
		t.Error("rcEq scalars")
	}
	if rcTypedEq(true, rcBig(1)) || !rcTypedEq(rcBig(1), rcBig(1)) {
		t.Error("typed equality separates bool from int")
	}
	if !rcTypedEq(rcJ(t, `{"a":[1,{"b":null}]}`), rcJ(t, `{"a":[1,{"b":null}]}`)) {
		t.Error("typed equality of equal trees")
	}
	if rcTypedEq(rcJ(t, `{"a":[1,true]}`), rcJ(t, `{"a":[1,1]}`)) ||
		rcTypedEq(rcJ(t, `{"a":1}`), rcJ(t, `{"b":1}`)) ||
		rcTypedEq(rcJ(t, `[1]`), rcJ(t, `[1,2]`)) ||
		rcTypedEq(rcJ(t, `[1]`), rcJ(t, `"x"`)) {
		t.Error("typed equality must reject differences")
	}
	if !rcEq(obj, rcJ(t, `{"b":[1,2],"a":1}`)) || rcEq([]any{rcBig(1)}, []any{rcBig(2)}) {
		t.Error("rcEq containers")
	}
}

func TestRCContainerOps(t *testing.T) {
	obj := rcJ(t, `{"k":1,"j":2}`)
	list := rcJ(t, `[1,"a",null]`)
	if !rcIn("k", obj) || rcIn("z", obj) || rcIn(rcBig(1), obj) {
		t.Error("in dict")
	}
	rcMustFault(t, "TypeError", func() { rcIn([]any{}, obj) })
	if !rcIn(rcBig(1), list) || rcIn("zz", list) {
		t.Error("in list")
	}
	if !rcIn("ab", "xaby") || rcIn("q", "xaby") {
		t.Error("in str")
	}
	rcMustFault(t, "TypeError", func() { rcIn(rcBig(1), "abc") })
	rcMustFault(t, "TypeError", func() { rcIn("a", rcBig(1)) })

	if len(rcIter(list)) != 3 || len(rcIter(obj)) != 2 || rcIter(obj)[0] != "k" {
		t.Error("rcIter container")
	}
	if it := rcIter("aé"); len(it) != 2 || it[1] != "é" {
		t.Error("rcIter str")
	}
	rcMustFault(t, "TypeError", func() { rcIter(rcBig(1)) })

	if rcLen(list) != 3 || rcLen(obj) != 2 || rcLen("aé") != 2 {
		t.Error("rcLen")
	}
	rcMustFault(t, "TypeError", func() { rcLen(nil) })

	for v, want := range map[string]string{"null": "None", "true": "True", "false": "False", "12": "12", `"s"`: "s", "[1]": "\x00container"} {
		if got := rcStr(rcJ(t, v)); got != want {
			t.Errorf("rcStr(%s) = %q, want %q", v, got, want)
		}
	}
	if !rcIsHex64(rcJ(t, `"`+string(bytes.Repeat([]byte("a"), 64))+`"`)) || rcIsHex64(rcBig(1)) {
		t.Error("rcIsHex64")
	}

	if !rcEq(rcFirst(list), rcBig(1)) {
		t.Error("first of list")
	}
	if rcFirst("éx") != "é" {
		t.Error("first of str")
	}
	rcMustFault(t, "IndexError", func() { rcFirst([]any{}) })
	rcMustFault(t, "IndexError", func() { rcFirst("") })
	rcMustFault(t, "KeyError", func() { rcFirst(obj) })
	rcMustFault(t, "TypeError", func() { rcFirst(rcBig(1)) })

	if !rcLess("a", "b") || rcLess(rcBig(2), rcBig(1)) || !rcLessEq(rcBig(1), true) {
		t.Error("ordering")
	}
	rcMustFault(t, "TypeError", func() { rcLess("a", rcBig(1)) })
}

func TestRCDict(t *testing.T) {
	d := &rcDict{}
	d.set(rcBig(1), "one")
	d.set(true, "true")
	d.set("k", "v")
	if len(d.keys) != 2 || d.item(rcBig(1)) != "true" || d.item("k") != "v" {
		t.Error("1 and True are one key")
	}
	if _, ok := d.get("missing"); ok {
		t.Error("missing key")
	}
	rcMustFault(t, "KeyError", func() { d.item("missing") })
	rcMustFault(t, "TypeError", func() { d.set([]any{}, 1) })
	obj := rcJ(t, `{"a":null}`)
	if rcGetDefault(obj, "a", "d") != nil || rcGetDefault(obj, "b", "d") != "d" {
		t.Error("rcGetDefault")
	}
}

func TestRCDecoders(t *testing.T) {
	if got, ok := rcFromHex("0a FF\n0b"); !ok || !bytes.Equal(got, []byte{0x0a, 0xff, 0x0b}) {
		t.Errorf("fromhex good: %v %v", got, ok)
	}
	for _, bad := range []string{"0", "0g", "g0", "abc"} {
		if _, ok := rcFromHex(bad); ok {
			t.Errorf("fromhex accepted %q", bad)
		}
	}
	for c, want := range map[byte]int{'0': 0, '9': 9, 'a': 10, 'f': 15, 'A': 10, 'F': 15, 'g': -1} {
		if rcHexVal(c) != want {
			t.Errorf("rcHexVal(%c)", c)
		}
	}
	if got, ok := rcB64("aGk="); !ok || string(got) != "hi" {
		t.Errorf("b64 good: %q %v", got, ok)
	}
	if got, ok := rcB64("aGkh"); !ok || string(got) != "hi!" {
		t.Errorf("b64 unpadded body: %q %v", got, ok)
	}
	for _, bad := range []string{"aGk", "a===", "aG!=", "aGk\n", "aG=k"} {
		if _, ok := rcB64(bad); ok {
			t.Errorf("b64 accepted %q", bad)
		}
	}
	if rcB64Encode([]byte("hi")) != "aGk=" {
		t.Error("rcB64Encode")
	}
	if got := rcBytesFromHex("0aff"); !bytes.Equal(got, []byte{0x0a, 0xff}) {
		t.Errorf("rcBytesFromHex %v", got)
	}
}
