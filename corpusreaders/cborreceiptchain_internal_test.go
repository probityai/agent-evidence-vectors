package corpusreaders

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// crcTHead is the minimal CBOR head for a major type and argument.
func crcTHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8 & 0xff), byte(n & 0xff)}
	}
	return []byte{major<<5 | 26, byte(n >> 24 & 0xff), byte(n >> 16 & 0xff), byte(n >> 8 & 0xff), byte(n & 0xff)}
}

func crcTUint(n uint64) []byte { return crcTHead(0, n) }

func crcTBytes(b []byte) []byte { return append(crcTHead(2, uint64(len(b))), b...) }

func crcTText(s string) []byte { return append(crcTHead(3, uint64(len(s))), s...) }

func crcTMap(kv ...[]byte) []byte {
	out := crcTHead(5, uint64(len(kv)/2))
	for _, part := range kv {
		out = append(out, part...)
	}
	return out
}

func crcTProfile() crcProfile {
	return crcProfile{
		Outer:             map[string]string{"version": "v", "payload": "p", "signer_key": "k", "signature": "s"},
		Fields:            map[string]int64{"version": 0, "prev_hash": 1, "outcome": 2, "request_hash": 3, "proof": 4},
		KeyForm:           "raw",
		signatureContextB: []byte("ctx"),
	}
}

// crcTReceipt signs one receipt under key; outer lets a case corrupt one outer member.
type crcTReceipt struct {
	key     ed25519.PrivateKey
	version uint64
	payload []byte
	outer   func(version uint64, payload, pub, sig []byte) []byte
}

func (r crcTReceipt) hex(profile crcProfile) string {
	pub, _ := r.key.Public().(ed25519.PublicKey)
	msg := append(append(append([]byte{}, profile.signatureContextB...), byte(r.version&0xff)), r.payload...)
	sig := ed25519.Sign(r.key, msg)
	if r.outer != nil {
		return hex.EncodeToString(r.outer(r.version, r.payload, pub, sig))
	}
	return hex.EncodeToString(crcTMap(
		crcTText("v"), crcTUint(r.version),
		crcTText("p"), crcTBytes(r.payload),
		crcTText("k"), crcTBytes(pub),
		crcTText("s"), crcTBytes(sig),
	))
}

func crcTKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, 32)) }

func crcTBody(prev []byte) []byte {
	prevItem := []byte{0xf6}
	if prev != nil {
		prevItem = crcTBytes(prev)
	}
	return crcTMap(crcTUint(0), crcTUint(1), crcTUint(1), prevItem, crcTUint(2), crcTText("allow"))
}

func crcTOuter(version, payload, key, sig []byte) []byte {
	return crcTMap(crcTText("v"), version, crcTText("p"), payload, crcTText("k"), key, crcTText("s"), sig)
}

func TestCrcParseReadsOneReceiptAndNamesEachDefect(t *testing.T) {
	profile := crcTProfile()
	good := crcTReceipt{key: crcTKey(), version: 1, payload: crcTBody(nil)}
	r, kind := crcParse(good.hex(profile), profile)
	if kind != crcOK || r.prev != nil || r.outcome != "allow" || r.signer == "" || !r.hasProf {
		t.Fatalf("a well formed receipt: kind %v, receipt %+v", kind, r)
	}
	linked := crcTReceipt{key: crcTKey(), version: 1, payload: crcTBody(make([]byte, 32))}
	if r, kind := crcParse(linked.hex(profile), profile); kind != crcOK || r.prev == nil {
		t.Fatalf("a receipt naming its predecessor: kind %v, receipt %+v", kind, r)
	}
	badSig := func(version uint64, payload, pub, sig []byte) []byte {
		sig = append([]byte{}, sig...)
		sig[0] ^= 1
		return crcTOuter(crcTUint(version), crcTBytes(payload), crcTBytes(pub), crcTBytes(sig))
	}
	shortSig := func(version uint64, payload, pub, _ []byte) []byte {
		return crcTOuter(crcTUint(version), crcTBytes(payload), crcTBytes(pub), crcTBytes([]byte{1}))
	}
	shortKey := func(version uint64, payload, _, sig []byte) []byte {
		return crcTOuter(crcTUint(version), crcTBytes(payload), crcTBytes([]byte{1}), crcTBytes(sig))
	}
	textPayload := func(version uint64, _, pub, sig []byte) []byte {
		return crcTOuter(crcTUint(version), crcTText("not bytes"), crcTBytes(pub), crcTBytes(sig))
	}
	textVersion := func(_ uint64, payload, pub, sig []byte) []byte {
		return crcTOuter(crcTText("one"), crcTBytes(payload), crcTBytes(pub), crcTBytes(sig))
	}
	build := func(version uint64, payload []byte, outer func(uint64, []byte, []byte, []byte) []byte) string {
		return crcTReceipt{key: crcTKey(), version: version, payload: payload, outer: outer}.hex(profile)
	}
	cases := []struct {
		name string
		line string
		want crcParseKind
	}{
		{"not hex", "zz", crcMalformed},
		{"odd hex", "0a0", crcMalformed},
		{"not cbor", "ff", crcMalformed},
		{"outer is not a map", "00", crcMalformed},
		{"outer lacks the four members", hex.EncodeToString(crcTMap(crcTText("v"), crcTUint(1))), crcMalformed},
		{"version is text", build(1, crcTBody(nil), textVersion), crcMalformed},
		{"version past one byte", build(256, crcTBody(nil), nil), crcMalformed},
		{"payload is text", build(1, crcTBody(nil), textPayload), crcMalformed},
		{"key of the wrong size", build(1, crcTBody(nil), shortKey), crcMalformed},
		{"signature of the wrong size", build(1, crcTBody(nil), shortSig), crcMalformed},
		{"signature does not verify", build(1, crcTBody(nil), badSig), crcBadSignature},
		{"payload is not a map", build(1, crcTUint(7), nil), crcMalformed},
		{"payload version differs from the outer", build(2, crcTBody(nil), nil), crcMalformed},
		{"predecessor of the wrong length", build(1, crcTBody([]byte{1, 2, 3}), nil), crcMalformed},
		{"predecessor of the wrong type", build(1, crcTMap(crcTUint(0), crcTUint(1), crcTUint(1), crcTText("x")), nil), crcMalformed},
	}
	for _, tc := range cases {
		if _, kind := crcParse(tc.line, profile); kind != tc.want {
			t.Errorf("%s: kind %v, want %v", tc.name, kind, tc.want)
		}
	}
}

func TestCrcParseReadsAPairKeyFormAndALineMember(t *testing.T) {
	member := "wire"
	profile := crcTProfile()
	profile.KeyForm = "pair"
	profile.LineMember = &member
	pub, _ := crcTKey().Public().(ed25519.PublicKey)
	payload := crcTBody(nil)
	sig := ed25519.Sign(crcTKey(), append(append([]byte("ctx"), 1), payload...))
	pair := func(b []byte) []byte { return append([]byte{0x82}, append(crcTText("ed25519"), crcTBytes(b)...)...) }
	outer := crcTOuter(crcTUint(1), crcTBytes(payload), pair(pub), pair(sig))
	line := `{"` + member + `":"` + hex.EncodeToString(outer) + `"}`
	if _, kind := crcParse(line, profile); kind != crcOK {
		t.Fatalf("a pair-form receipt in a line member: kind %v", kind)
	}
	for _, bad := range []string{`not json`, `{}`, `{"wire":5}`} {
		if _, kind := crcParse(bad, profile); kind != crcMalformed {
			t.Errorf("%q: kind %v, want malformed", bad, kind)
		}
	}
}

func TestCrcFromHexReadsLikeBytesFromhex(t *testing.T) {
	if got, ok := crcFromHex("0a \t0b\n0c"); !ok || hex.EncodeToString(got) != "0a0b0c" {
		t.Errorf("whitespace between bytes: %x %v", got, ok)
	}
	for _, bad := range []string{"0a0", "0 a", "zz", "0a 0"} {
		if _, ok := crcFromHex(bad); ok {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestCrcBytesReadsAKeyInEitherForm(t *testing.T) {
	five := []byte{1, 2, 3, 4, 5}
	if b, ok := crcBytes(five, "raw", 5); !ok || len(b) != 5 {
		t.Error("raw bytes of the right size")
	}
	if _, ok := crcBytes(five, "raw", 4); ok {
		t.Error("raw bytes of the wrong size")
	}
	if _, ok := crcBytes("text", "raw", 4); ok {
		t.Error("text is not bytes")
	}
	if b, ok := crcBytes([]any{"alg", five}, "pair", 5); !ok || len(b) != 5 {
		t.Error("a pair carrying the bytes second")
	}
	if _, ok := crcBytes([]any{"alg"}, "pair", 5); ok {
		t.Error("a pair of one")
	}
	if _, ok := crcBytes(five, "pair", 5); ok {
		t.Error("bytes are not a pair")
	}
}

func TestCrcRenderTagsEveryKindOfItem(t *testing.T) {
	got := crcRender([]any{nil, true, crcInt{neg: true, mag: 3}, []byte{0xab}, "x",
		crcMap{pairs: [][2]any{{"k", false}}}})
	want := `[null,bool:true,int:true:3,bytes:ab,text:"x",{text:"k"=bool:false}]`
	if got != want {
		t.Errorf("render %q, want %q", got, want)
	}
	if crcRender(1.5) != "?" {
		t.Error("an item the decoder never produces renders as ?")
	}
}

func TestCrcKeyEqualAndMapLookup(t *testing.T) {
	if !crcKeyEqual("a", crcText("a")) || crcKeyEqual("a", "b") || crcKeyEqual("a", crcInt{}) {
		t.Error("text keys compare by text")
	}
	if !crcKeyEqual(crcInt{mag: 2}, crcInt{mag: 2}) || crcKeyEqual(crcInt{mag: 2}, crcInt{neg: true, mag: 2}) || crcKeyEqual(crcInt{}, "a") {
		t.Error("integer keys compare by sign and magnitude")
	}
	if crcKeyEqual(true, true) {
		t.Error("a boolean is never a key")
	}
	m := crcMap{pairs: [][2]any{{"a", crcInt{mag: 1}}, {crcInt{mag: 9}, "n"}}}
	if m.get(crcText("a")) != (crcInt{mag: 1}) || m.get(crcText("zzz")) != nil {
		t.Error("lookup by text, and a miss is nil")
	}
	if m.keysAre([]string{"a"}) || m.keysAre([]string{"a", "b"}) {
		t.Error("a map with an integer key, or a missing name, is not the named keys")
	}
}

func TestCrcDecodeAcceptsEachItemKindAndRefusesEachDefect(t *testing.T) {
	long := append([]byte{0x99, 0x13, 0x88}, make([]byte, 5000)...) // 5000 items, past the budget
	deep := append([]byte(strings.Repeat("\x81", 18)), 0x00)
	accepted := map[string]string{
		"\x18\x19":                             "int:false:25",
		"\x19\x01\x00":                         "int:false:256",
		"\x1a\x00\x01\x00\x00":                 "int:false:65536",
		"\x1b\x00\x00\x00\x01\x00\x00\x00\x00": "int:false:4294967296",
		"\x20":                                 "int:true:0",
		"\x42\x01\x02":                         "bytes:0102",
		"\x62hi":                               `text:"hi"`,
		"\xf4":                                 "bool:false",
		"\xf5":                                 "bool:true",
		"\xf6":                                 "null",
		"\x82\x01\x02":                         "[int:false:1,int:false:2]",
		"\xa1\x61a\x02":                        `{text:"a"=int:false:2}`,
		"\xa1\x01\x02":                         "{int:false:1=int:false:2}",
	}
	for raw, want := range accepted {
		v, err := crcDecode([]byte(raw))
		if err != nil || crcRender(v) != want {
			t.Errorf("%x: %v %v, want %s", raw, v, err, want)
		}
	}
	refused := map[string][]byte{
		"empty":                  {},
		"a tag":                  {0xc0, 0x00},
		"a float":                {0xf9, 0x3c, 0x00},
		"undefined":              {0xf7},
		"reserved information":   {0x1c},
		"an indefinite length":   {0x5f},
		"truncated bytes":        {0x42, 0x01},
		"text that is not utf8":  {0x61, 0xff},
		"data after the item":    {0x00, 0x00},
		"a count past the data":  {0x84},
		"a map key of bytes":     {0xa1, 0x41, 0x00, 0x00},
		"a repeated key":         {0xa2, 0x01, 0x00, 0x01, 0x00},
		"a missing map value":    {0xa1, 0x01},
		"a truncated array":      {0x82, 0x01},
		"a head with no length":  {0x19, 0x01},
		"nesting too deep":       deep,
		"more items than budget": long,
	}
	for name, raw := range refused {
		if _, err := crcDecode(raw); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}
