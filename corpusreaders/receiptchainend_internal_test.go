package corpora

// Internal checks of the receipt-chain-end reader's JSON layer. A receipt's hash
// and signature are over the bytes CPython's
// json.dumps(separators=(",", ":"), ensure_ascii=False) writes for the parsed
// line, and the reader's comparisons follow Python's ==, so each case below is
// a value the Python reader would treat a certain way and a wrong port would not.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *rceVal {
	t.Helper()
	v, err := rceParse([]byte(raw))
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return v
}

func TestRCECompactMatchesCPython(t *testing.T) {
	cases := map[string]string{
		`{ "b": 1, "a": [true, false, null, "x"] }`: `{"b":1,"a":[true,false,null,"x"]}`,
		`{"k":"éé/<>&"}`:                            `{"k":"éé/<>&"}`,
		`{"k":"\u0001\n\t\"\\"}`:                    `{"k":"\u0001\n\t\"\\"}`,
		`{"a":1,"a":2,"b":3}`:                       `{"a":2,"b":3}`,
		`{"n":-0}`:                                  `{"n":0}`,
	}
	for in, want := range cases {
		got, err := mustParse(t, in).compact()
		if err != nil || string(got) != want {
			t.Errorf("compact(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
	if _, err := mustParse(t, `{"f":1.5}`).compact(); err == nil {
		t.Error("a float encoded without refusal")
	}
	for _, bad := range []string{`{"a":1} {}`, `{"a":`, `[1,`} {
		if _, err := rceParse([]byte(bad)); err == nil {
			t.Errorf("parse(%q) accepted", bad)
		}
	}
}

func TestRCEEqualIsPythonEquality(t *testing.T) {
	eq := []string{
		`[1, 1]`, `[1, true]`, `[0, false]`, `[0, 0.0]`, `[null, null]`, `["x", "x"]`,
		`[[1, [2]], [true, [2]]]`, `[{"a":1,"b":2}, {"b":2,"a":1}]`,
	}
	ne := []string{
		`[1, "1"]`, `[null, 0]`, `["x", "y"]`, `[[1], [1, 2]]`, `[[1], [2]]`,
		`[{"a":1}, {"a":1,"b":2}]`, `[{"a":1}, {"b":1}]`, `[{"a":1}, {"a":2}]`, `["x", [1]]`,
	}
	for _, pair := range eq {
		v := mustParse(t, pair)
		if !rceEqual(v.items[0], v.items[1]) {
			t.Errorf("%s: Python says equal", pair)
		}
	}
	for _, pair := range ne {
		v := mustParse(t, pair)
		if rceEqual(v.items[0], v.items[1]) {
			t.Errorf("%s: Python says not equal", pair)
		}
	}
	if !rceEqual(nil, mustParse(t, `null`)) || rceEqual(nil, mustParse(t, `0`)) {
		t.Error("an absent member must equal null and nothing else")
	}
}

func TestRCEPyStrAndInt(t *testing.T) {
	str := map[string]string{`"s"`: "s", `null`: "None", `true`: "True", `false`: "False",
		`-0`: "0", `7`: "7", `1.5`: "1.5", `[1]`: "[1]"}
	for in, want := range str {
		if got := rcePyStr(mustParse(t, in), "d"); got != want {
			t.Errorf("str(%s) = %q, want %q", in, got, want)
		}
	}
	if rcePyStr(nil, "d") != "d" {
		t.Error("an absent member must read as the default")
	}
	ints := map[string]int64{`30`: 30, `true`: 1, `false`: 0, `" 12 "`: 12, `2.9`: 2}
	for in, want := range ints {
		got, ok := rcePyInt(mustParse(t, in))
		if !ok || got.Int64() != want {
			t.Errorf("int(%s) = %v, %t; want %d", in, got, ok, want)
		}
	}
	for _, bad := range []string{`"x"`, `null`, `[1]`, `1e999`} {
		if _, ok := rcePyInt(mustParse(t, bad)); ok {
			t.Errorf("int(%s) accepted", bad)
		}
	}
	if n, ok := rcePyInt(nil); !ok || n.Sign() != 0 {
		t.Error("an absent heartbeat must read as 0")
	}
}

func TestRCESessionOpenGenesisRefusesWhatPythonRaisesOn(t *testing.T) {
	if _, ok := rceSessionOpenGenesis(mustParse(t, `{"heartbeat_seconds":"x"}`)); ok {
		t.Error("a heartbeat int() cannot read was accepted")
	}
	if _, ok := rceSessionOpenGenesis(mustParse(t, `{"heartbeat_seconds":1e30}`)); ok {
		t.Error("a heartbeat wider than eight bytes was accepted")
	}
	a, _ := rceSessionOpenGenesis(mustParse(t, `{"heartbeat_seconds":-5}`))
	b, _ := rceSessionOpenGenesis(mustParse(t, `{"heartbeat_seconds":0}`))
	if a != b {
		t.Error("a negative heartbeat must frame as 0")
	}
}

func TestRCESignatureInputsAreRefused(t *testing.T) {
	for _, r := range []string{
		`{"signature":"ed25519:00","signer_key":"00","action_record":{}}`,
		`{"signature":"rsa:00","signer_key":"` + strings.Repeat("00", 32) + `","action_record":{}}`,
		`{"signature":"ed25519:zz","signer_key":"` + strings.Repeat("00", 32) + `","action_record":{}}`,
		`{"signature":"ed25519:00","signer_key":"` + strings.Repeat("00", 32) + `","action_record":[]}`,
		`{"signature":"ed25519:00","signer_key":"` + strings.Repeat("00", 32) + `","action_record":{"f":1.5}}`,
	} {
		if rceReceiptVerifies(mustParse(t, r)) {
			t.Errorf("%s verified", r)
		}
	}
	for _, e := range []string{`[]`, `{"endorsement":"ed25519:00"}`,
		`{"endorsement":"ed25519:00","prior_signer_key":"` + strings.Repeat("00", 32) + `","x":1.5}`} {
		if rceEndorsementVerifies(mustParse(t, e)) {
			t.Errorf("%s verified", e)
		}
	}
}

func writeCase(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRCELoadRefusesUnreadableInputs(t *testing.T) {
	trust := `"trust":{"root_keys":[],"endorsements":["e.json"]}`
	cases := map[string]map[string]string{
		"no case file":       {},
		"no trust":           {"case.json": `{"chain":"c"}`},
		"chain missing":      {"case.json": `{"chain":"c",` + trust + `}`},
		"chain not objects":  {"case.json": `{"chain":"c",` + trust + `}`, "c": "[1]\n"},
		"head not a name":    {"case.json": `{"chain":"c","head":1,` + trust + `}`, "c": "{}\n"},
		"head missing":       {"case.json": `{"chain":"c","head":"h",` + trust + `}`, "c": "{}\n"},
		"head not an object": {"case.json": `{"chain":"c","head":"h",` + trust + `}`, "c": "{}\n", "h": "[]"},
		"endorsement absent": {"case.json": `{"chain":"c",` + trust + `}`, "c": "{}\n"},
		"endorsement name": {"case.json": `{"chain":"c","trust":{"endorsements":[1]}}`,
			"c": "{}\n"},
	}
	for name, files := range cases {
		if _, err := rceLoad(writeCase(t, files)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestRCEDecisionsOnDegenerateChains(t *testing.T) {
	empty := &rceInput{trust: mustParse(t, `{"root_keys":[]}`)}
	if got := rceVerify(empty); got.Reason != "signer_untrusted" {
		t.Errorf("an empty chain: %v", got)
	}
	float := &rceInput{trust: mustParse(t, `{}`), receipts: []*rceVal{mustParse(t, `{"x":1.5}`)}}
	if got := rceVerify(float); got.Decision != "error" {
		t.Errorf("a receipt that cannot be re-encoded: %v", got)
	}
	w, _ := rceNewWalk(nil)
	if w.endProvenByClose() || w.linksHold {
		t.Error("an empty chain proves nothing")
	}
}

func TestRCEJudgeReportsCorpusShape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "cases", "stray"), 0o750); err != nil {
		t.Fatal(err)
	}
	manifest := `{"corpusDigest":"x","vectors":[{"id":"a","path":"cases/a","files":{}},` +
		`{"id":"a","path":"elsewhere","files":{}}, 7]}`
	result, err := (receiptChainEnd{}).Judge(root, []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(result.Findings, "; ")
	for _, want := range []string{"duplicate vector identifier a", "does not parse",
		"unlisted [stray], absent [a]", "corpusDigest"} {
		if !strings.Contains(joined, want) {
			t.Errorf("want a finding containing %q, got %q", want, joined)
		}
	}
	if len(result.Members) != 2 || !strings.Contains(strings.Join(result.Members[1].Findings, ""), "does not match") {
		t.Errorf("members: %+v", result.Members)
	}
	if _, err := (receiptChainEnd{}).Judge(root, []byte("{")); err == nil {
		t.Error("an unparsable manifest was judged")
	}
	empty, _ := (receiptChainEnd{}).Judge(root, []byte(`{"vectors":[]}`))
	if !strings.Contains(strings.Join(empty.Findings, ""), "lists no vectors") {
		t.Errorf("an empty manifest: %v", empty.Findings)
	}
	if f := rceCaseDirectories(filepath.Join(root, "absent"), nil); !strings.Contains(f, "cannot be read") {
		t.Errorf("an absent cases directory: %q", f)
	}
	if f := rceFileFindings(filepath.Join(root, "absent"), nil); len(f) != 1 {
		t.Errorf("an absent case directory: %v", f)
	}
	stray := writeCase(t, map[string]string{"x": "1"})
	if f := strings.Join(rceFileFindings(stray, map[string]string{"y": "0"}), "; "); !strings.Contains(f, "x is present and not declared") || !strings.Contains(f, "y is declared and absent") {
		t.Errorf("file findings: %q", f)
	}
}
