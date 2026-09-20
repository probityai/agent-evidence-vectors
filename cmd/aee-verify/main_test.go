package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aeetest"
)

func writeTemp(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "statement.json")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunValidStatementExit0(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{path}, &out, &errb); code != 0 {
		t.Fatalf("valid statement: exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("expected valid verdict, got:\n%s", out.String())
	}
}

func TestRunInvalidStatementExit1(t *testing.T) {
	// Result forced to "pass" against a caught row: recompute mismatch.
	path := writeTemp(t, aeetest.Build(aeetest.Options{Result: "pass"}))
	var out, errb bytes.Buffer
	code := run([]string{path}, &out, &errb)
	if code != 1 {
		t.Fatalf("invalid statement: exit %d (want 1), stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: invalid") {
		t.Fatalf("expected invalid verdict, got:\n%s", out.String())
	}
}

// harnessRead applies the conformance harness's own parse rule to stdout, byte
// for byte: packaging/run_vectors.py's run_external keeps the non-blank lines,
// takes the LAST one, and parses THAT LINE as the whole report. Anything this
// function cannot read, the harness cannot read either.
//
// It exists because "the output is JSON" is not the contract and testing that
// claim is how this CLI passed its own test suite while scoring 0 of 186 as an
// external rail: json.Unmarshal over the whole buffer accepts a pretty-printed
// object, and the harness never sees the whole buffer.
func harnessRead(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var lines []string
	for _, ln := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(ln) != "" {
			lines = append(lines, ln)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("-json must emit exactly one non-blank line (the harness reads only "+
			"the last one, so any earlier line is unreachable); got %d:\n%s",
			len(lines), stdout)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &report); err != nil {
		t.Fatalf("the last stdout line is not a JSON object, so the harness reads no "+
			"verdict, no codes, no result and no tiers from this rail: %v\nline: %s",
			err, lines[len(lines)-1])
	}
	return report
}

func TestJSONOutputIsOneLineTheHarnessCanRead(t *testing.T) {
	valid := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{"-json", valid}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	report := harnessRead(t, out.String())
	if report["verdict"] != "valid" {
		t.Fatalf("json verdict = %v, want valid", report["verdict"])
	}
	if report["result"] != "fail" {
		t.Fatalf("json result = %v, want fail", report["result"])
	}
	if _, ok := report["tiers"].([]any); !ok {
		t.Fatalf("a valid statement must carry a tiers array the harness can compare, got %v",
			report["tiers"])
	}

	// The reject side of the same contract: a rail that answers with a verdict
	// and no codes fails every reject vector in the corpus.
	out.Reset()
	errb.Reset()
	invalid := writeTemp(t, aeetest.Build(aeetest.Options{Result: "pass"}))
	if code := run([]string{"-json", invalid}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1, stderr=%q", code, errb.String())
	}
	report = harnessRead(t, out.String())
	if report["verdict"] != "invalid" {
		t.Fatalf("json verdict = %v, want invalid", report["verdict"])
	}
	codes, ok := report["codes"].([]any)
	if !ok || len(codes) == 0 {
		t.Fatalf("an invalid statement must carry a non-empty codes array, got %v",
			report["codes"])
	}
}

func TestSubstrateKeysEnvSuppliesTheConsumerPolicy(t *testing.T) {
	// The harness fixes argv to `<cmd> <vector-file>` and hands the key policy
	// over in this variable, running each vector once with it and once without.
	// Without this fallback the no-pinned-key tier column is the only one an
	// external rail can ever produce, which is what made ok-024's
	// tierWithoutKey expectation bind the first-party rails alone.
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	right := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey))
	wrong := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey))

	t.Setenv(EnvSubstrateKeys, right)
	var out, errb bytes.Buffer
	if code := run([]string{"-json", statement}, &out, &errb); code != 0 {
		t.Fatalf("env-supplied covering key: exit %d, stderr=%q", code, errb.String())
	}
	if tiers := harnessRead(t, out.String())["tiers"]; !reflect.DeepEqual(tiers, []any{"attested"}) {
		t.Fatalf("$%s must pin the key: tiers = %v, want [attested]", EnvSubstrateKeys, tiers)
	}

	// An explicit -keys outranks the variable, so a harness environment can
	// never silently override a policy the operator named.
	t.Setenv(EnvSubstrateKeys, wrong)
	out.Reset()
	errb.Reset()
	if code := run([]string{"-json", "-keys", right, statement}, &out, &errb); code != 0 {
		t.Fatalf("-keys over env: exit %d, stderr=%q", code, errb.String())
	}
	if tiers := harnessRead(t, out.String())["tiers"]; !reflect.DeepEqual(tiers, []any{"attested"}) {
		t.Fatalf("-keys must outrank $%s: tiers = %v, want [attested]", EnvSubstrateKeys, tiers)
	}

	// Unset, the same argv is bare conformance-replay mode: no TOFU, so the
	// substrate row derives unattested and no admission decision is printed.
	t.Setenv(EnvSubstrateKeys, "")
	out.Reset()
	errb.Reset()
	if code := run([]string{"-json", statement}, &out, &errb); code != 0 {
		t.Fatalf("no policy: exit %d, stderr=%q", code, errb.String())
	}
	report := harnessRead(t, out.String())
	if tiers := report["tiers"]; !reflect.DeepEqual(tiers, []any{"unattested"}) {
		t.Fatalf("no pinned key must derive unattested (no TOFU): tiers = %v", tiers)
	}
}

func TestRunMissingFileExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{filepath.Join(t.TempDir(), "nope.json")}, &out, &errb); code != 2 {
		t.Fatalf("missing file: exit %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "aee-verify:") {
		t.Fatalf("expected an error diagnostic on stderr, got %q", errb.String())
	}
}

func TestRunUsageExit2(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("args %v: exit %d, want 2 (usage)", args, code)
		}
	}
}

func TestRunUnknownFlagExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-nope", "x"}, &out, &errb); code != 2 {
		t.Fatalf("unknown flag: exit %d, want 2", code)
	}
}

func keyPolicyFile(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	body := fmt.Sprintf(`{"substrateObservationKeys":[{"keyid":"k1","publicKeyHex":%q}]}`,
		hex.EncodeToString(pub))
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunPinnedKeyAttestedAdmitted(t *testing.T) {
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)
	var out, errb bytes.Buffer
	if code := run([]string{"-keys", keys, statement}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "attested") {
		t.Fatalf("pinned covering key should derive attested, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "admitted: true") {
		t.Fatalf("expected admitted: true, got:\n%s", out.String())
	}
}

func TestRunWrongKeyUnattestedNotAdmitted(t *testing.T) {
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	// A different key than the record signer: the covering record cannot
	// verify, the row derives unattested, and with a policy supplied the
	// exit status binds to the admission result, not bare validity.
	pub := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)
	var out, errb bytes.Buffer
	if code := run([]string{"-keys", keys, statement}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1 (valid but not admitted), stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("statement stays byte-pure valid, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "unattested") {
		t.Fatalf("wrong key should derive unattested, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "admitted: false") {
		t.Fatalf("expected admitted: false, got:\n%s", out.String())
	}
}

// corpusAndSubstrateDigests reads the carried anchor digests out of a built
// statement, so the anchor tests compare against exactly what travels.
func corpusAndSubstrateDigests(t *testing.T, body []byte) (corpus, substrate string) {
	t.Helper()
	var stmt struct {
		Predicate struct {
			Env struct {
				Corpus struct {
					Digest map[string]string `json:"digest"`
				} `json:"corpus"`
				Substrate struct {
					Digest map[string]string `json:"digest"`
				} `json:"substrate"`
			} `json:"observationEnvironment"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	return stmt.Predicate.Env.Corpus.Digest["sha256"], stmt.Predicate.Env.Substrate.Digest["sha256"]
}

func TestRunAnchorsBindExitToAdmission(t *testing.T) {
	body := aeetest.Build(aeetest.Options{})
	statement := writeTemp(t, body)
	corpus, substrate := corpusAndSubstrateDigests(t, body)
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	keys := keyPolicyFile(t, pub)

	// Matching anchors + covering key: admitted, exit 0.
	var out, errb bytes.Buffer
	code := run([]string{"-keys", keys,
		"-expected-corpus-digest", corpus,
		"-expected-substrate-digest", substrate, statement}, &out, &errb)
	if code != 0 {
		t.Fatalf("matching anchors: exit %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "corpus anchor: match") ||
		!strings.Contains(out.String(), "substrate anchor: match") {
		t.Fatalf("expected anchor match lines, got:\n%s", out.String())
	}

	// Mismatched corpus anchor: still valid, not admitted, exit 1.
	out.Reset()
	errb.Reset()
	code = run([]string{"-keys", keys,
		"-expected-corpus-digest", strings.Repeat("0", 64), statement}, &out, &errb)
	if code != 1 {
		t.Fatalf("mismatched anchor: exit %d, want 1, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "verdict: valid") {
		t.Fatalf("anchor mismatch must not fail validity, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "corpus-anchor-mismatch") {
		t.Fatalf("expected the corpus-anchor-mismatch code surfaced, got:\n%s", out.String())
	}

	// An anchor flag alone supplies a policy: with no keys the substrate row
	// derives unattested, so the statement is not admitted even though the
	// anchor matches.
	out.Reset()
	errb.Reset()
	code = run([]string{"-expected-corpus-digest", corpus, statement}, &out, &errb)
	if code != 1 {
		t.Fatalf("anchor-only policy on a substrate statement: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "tier policy: NOT satisfied") {
		t.Fatalf("expected the tier-policy fact, got:\n%s", out.String())
	}
}

func TestRunBareModeBindsExitToValidity(t *testing.T) {
	// Bare conformance-replay mode: no policy supplied, so a valid statement
	// exits 0 even though its substrate row is unattested under no-TOFU.
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	var out, errb bytes.Buffer
	if code := run([]string{statement}, &out, &errb); code != 0 {
		t.Fatalf("bare mode valid statement: exit %d, stderr=%q", code, errb.String())
	}
	if strings.Contains(out.String(), "admitted:") {
		t.Fatalf("bare mode must not print an admission decision, got:\n%s", out.String())
	}
}

func TestLoadPolicy(t *testing.T) {
	// nothing supplied -> no policy, no error
	if p, err := loadPolicy("", "", ""); p != nil || err != nil {
		t.Fatalf("no policy inputs: got (%v,%v), want (nil,nil)", p, err)
	}
	// anchors without a key file still form a policy
	if p, err := loadPolicy("", "aa", "bb"); err != nil || p == nil ||
		p.ExpectedCorpusDigest != "aa" || p.ExpectedSubstrateDigest != "bb" ||
		len(p.SubstrateObservationKeys) != 0 {
		t.Fatalf("anchor-only policy: got (%+v,%v)", p, err)
	}
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "k.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// malformed JSON
	if _, err := loadPolicy(write("{"), "", ""); err == nil {
		t.Fatal("malformed JSON policy should error")
	}
	// non-hex public key
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"zz"}]}`), "", ""); err == nil {
		t.Fatal("non-hex publicKeyHex should error")
	}
	// wrong-length key (valid hex, too short)
	if _, err := loadPolicy(write(`{"substrateObservationKeys":[{"publicKeyHex":"aabb"}]}`), "", ""); err == nil {
		t.Fatal("short publicKeyHex should error")
	}
	// valid key
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	p, err := loadPolicy(keyPolicyFile(t, pub), "", "")
	if err != nil || p == nil || len(p.SubstrateObservationKeys) != 1 {
		t.Fatalf("valid policy: got (%v,%v)", p, err)
	}
}
