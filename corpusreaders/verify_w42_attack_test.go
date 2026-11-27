package corpusreaders

// Attack tests of the W4-2 verifier: the Go readers against the Python readers as a
// differential over every corpus member and thousands of mutated members. The Python side
// (scripts/verify-w42-attack-gen.py) writes keys.jsonl, sigs.jsonl and records.jsonl into
// the directory named by AEV_W42_ATTACK; this test fails when that variable is unset, so a
// run that did not build the fixtures cannot pass.

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func attackFile(t *testing.T, name string) *bufio.Scanner {
	t.Helper()
	dir := os.Getenv("AEV_W42_ATTACK")
	if dir == "" {
		t.Fatal("AEV_W42_ATTACK is not set: the fixtures were not generated")
	}
	f, err := os.Open(filepath.Join(dir, name)) // #nosec G304 -- a test reading its own fixtures
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<26)
	return s
}

func TestAttackPrimeOrderAgreesWithPython(t *testing.T) {
	s := attackFile(t, "keys.jsonl")
	n, bad := 0, 0
	for s.Scan() {
		var c struct {
			Hex string `json:"hex"`
			Tag string `json:"tag"`
			Ok  bool   `json:"ok"`
		}
		if err := json.Unmarshal(s.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		raw, _ := hex.DecodeString(c.Hex)
		n++
		if got := hbPrimeOrder(raw); got != c.Ok {
			bad++
			if bad <= 20 {
				t.Errorf("key %s (%s): go %v, python %v", c.Hex, c.Tag, got, c.Ok)
			}
		}
	}
	t.Logf("keys compared: %d, differences: %d", n, bad)
	if n < 500 || bad > 0 {
		t.Fatalf("compared %d keys, %d differ", n, bad)
	}
}

func TestAttackSignatureAgreesWithPython(t *testing.T) {
	s := attackFile(t, "sigs.jsonl")
	n, bad := 0, 0
	for s.Scan() {
		var c struct {
			Tag, Key, Msg, Sig string
			Ok                 bool
		}
		if err := json.Unmarshal(s.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		key, _ := hex.DecodeString(c.Key)
		msg, _ := hex.DecodeString(c.Msg)
		sig, _ := hex.DecodeString(c.Sig)
		n++
		got := len(key) == 32 && len(sig) == 64 && ed25519.Verify(ed25519.PublicKey(key), msg, sig)
		if got != c.Ok {
			bad++
			t.Errorf("signature case %s: go %v, python %v", c.Tag, got, c.Ok)
		}
	}
	t.Logf("signatures compared: %d, differences: %d", n, bad)
	if n < 30 || bad > 0 {
		t.Fatalf("compared %d, %d differ", n, bad)
	}
}

func attackGo(suite string, text []byte, trust map[string]any) (got scDecision) {
	defer func() {
		if r := recover(); r != nil {
			got = scDecision{Decision: "GOPANIC", Reason: fmt.Sprint(r)}
		}
	}()
	malformed := scDecision{Decision: "reject", Reason: "record_malformed"}
	value, err := decodeJSONNumbers(text)
	record, isObject := value.(map[string]any)
	if err != nil || !isObject {
		return malformed
	}
	switch suite {
	case "hbc":
		return hbDecide(record)
	case "ial":
		return iaDecide(record)
	}
	return deDecide(record, trust)
}

func TestAttackReadersAgreeWithPythonOnEveryMutant(t *testing.T) {
	trustBytes, err := os.ReadFile(filepath.Join("..", "corpora", "vectors-destination-narrowed-exchange", "TRUST.json"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeJSONNumbers(trustBytes)
	trust, _ := value.(map[string]any)
	if err != nil || trust == nil {
		t.Fatal("TRUST.json does not parse")
	}
	s := attackFile(t, "records.jsonl")
	counts := map[string][2]int{}
	shown := map[string]int{}
	for s.Scan() {
		var c struct {
			Suite, Tag, Text, Decision, Reason string
		}
		if err := json.Unmarshal(s.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		got := attackGo(c.Suite, []byte(c.Text), trust)
		cnt := counts[c.Suite]
		cnt[0]++
		if got.Decision != c.Decision || got.Reason != c.Reason {
			cnt[1]++
			if shown[c.Suite] < 200 {
				shown[c.Suite]++
				t.Errorf("%s %s: go %s/%s, python %s/%s\n  text: %.300s", c.Suite, c.Tag, got.Decision, got.Reason, c.Decision, c.Reason, c.Text)
			}
		}
		counts[c.Suite] = cnt
	}
	for suite, cnt := range counts {
		t.Logf("%s: %d compared, %d differ", suite, cnt[0], cnt[1])
		if cnt[1] > 0 {
			t.Fail()
		}
	}
	if len(counts) != 3 {
		t.Fatalf("suites compared: %v", counts)
	}
}
