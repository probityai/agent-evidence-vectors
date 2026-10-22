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

// statementPins reads the anchors a built statement carries, so a policy can
// pin exactly what travels.
func statementPins(t *testing.T, body []byte) (corpus, substrate, subject string, classes []string) {
	t.Helper()
	var stmt struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			Env struct {
				Corpus struct {
					Digest map[string]string `json:"digest"`
				} `json:"corpus"`
				Substrate struct {
					Digest map[string]string `json:"digest"`
				} `json:"substrate"`
			} `json:"observationEnvironment"`
			Coverage struct {
				AssessedClasses []string `json:"assessedClasses"`
			} `json:"coverage"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	return stmt.Predicate.Env.Corpus.Digest["sha256"], stmt.Predicate.Env.Substrate.Digest["sha256"],
		stmt.Subject[0].Digest["sha256"], stmt.Predicate.Coverage.AssessedClasses
}

// fullPolicyFile writes a consumer policy pinning every anchor the statement
// carries, the classes it assessed, and the pinned observation key: the policy
// under which a clean, attested statement is admitted.
func fullPolicyFile(t *testing.T, body []byte, extra map[string]any) string {
	t.Helper()
	corpus, substrate, subject, classes := statementPins(t, body)
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	doc := map[string]any{
		"substrateObservationKeys": []map[string]string{{"publicKeyHex": hex.EncodeToString(pub)}},
		"expectedCorpusDigest":     corpus,
		"expectedSubstrateDigest":  substrate,
		"expectedSubjectDigest":    subject,
		"demandedClasses":          classes,
		"allowPublishedTestKeys":   true,
	}
	for k, v := range extra {
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoPolicyIsNeverAPass(t *testing.T) {
	// The defect this command shipped: a valid statement, no policy, exit 0
	// and "result":"pass" while nothing was attested. It must refuse, and name
	// every pin that is missing.
	t.Setenv(EnvSubstrateKeys, "")
	t.Setenv(EnvConsumerPolicy, "")
	path := writeTemp(t, aeetest.Build(aeetest.Options{Clean: true}))
	var out, errb bytes.Buffer
	if code := run([]string{"-json", path}, &out, &errb); code != 1 {
		t.Fatalf("no policy: exit %d, want 1, stderr=%q", code, errb.String())
	}
	report := harnessRead(t, out.String())
	if report["admitted"] != false || report["mode"] != "admission" {
		t.Fatalf("no policy must be an unadmitted admission run, got %v", report)
	}
	codes := fmt.Sprint(report["policyCodes"])
	for _, want := range []string{"corpus-anchor-unpinned", "substrate-anchor-unpinned",
		"subject-anchor-unpinned", "scope-unpinned", "substrate-row-unattested"} {
		if !strings.Contains(codes, want) {
			t.Fatalf("policy codes %s lack %s", codes, want)
		}
	}
}

func TestEveryPinSuppliedIsAdmitted(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	path := writeTemp(t, body)
	var out, errb bytes.Buffer
	if code := run([]string{"-policy", fullPolicyFile(t, body, nil), path}, &out, &errb); code != 0 {
		t.Fatalf("every pin supplied: exit %d, stderr=%q\n%s", code, errb.String(), out.String())
	}
	for _, want := range []string{"admitted: true", "observer-signed arming instants: " + aeetest.ArmedAt,
		"producer-asserted, bound by no observer:", "predicate.issuedAt",
		"not established by this run: envelope-signature"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestValidityOnlyAnswersValidityAndSaysSo(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{Clean: true}))
	var out, errb bytes.Buffer
	if code := run([]string{"-validity-only", "-json", path}, &out, &errb); code != 0 {
		t.Fatalf("valid statement: exit %d, stderr=%q", code, errb.String())
	}
	report := harnessRead(t, out.String())
	if report["mode"] != "validity-only" || report["admitted"] != false || report["policyCodes"] != nil {
		t.Fatalf("validity-only report must say so and admit nothing, got %v", report)
	}
	if !strings.Contains(fmt.Sprint(report["notEstablished"]), "admission") {
		t.Fatalf("validity-only must list admission as not established, got %v", report["notEstablished"])
	}
	invalid := writeTemp(t, aeetest.Build(aeetest.Options{Result: "pass"}))
	out.Reset()
	if code := run([]string{"-validity-only", invalid}, &out, &errb); code != 1 {
		t.Fatalf("invalid statement: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "verdict: invalid") {
		t.Fatalf("expected invalid verdict, got:\n%s", out.String())
	}
}

func TestValidityOnlyRefusesAdmissionInputs(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{Clean: true}))
	for _, args := range [][]string{
		{"-validity-only", "-expected-corpus-digest", strings.Repeat("a", 64), path},
		{"-validity-only", "-demand-classes", "XA", path},
		{"-validity-only", "-policy", "p.json", path},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
	t.Setenv(EnvConsumerPolicy, "p.json")
	var out, errb bytes.Buffer
	if code := run([]string{"-validity-only", path}, &out, &errb); code != 2 {
		t.Fatalf("validity-only under $%s: exit %d, want 2", EnvConsumerPolicy, code)
	}
}

func TestRenamedSubjectIsRefusedByTheDigestPin(t *testing.T) {
	// The producer renames the subject and moves issuedAt after the run; every
	// record still verifies because neither is a binding input. The consumer
	// pins the digest of the artifact it deploys, and the name is never read.
	body := aeetest.Build(aeetest.Options{Clean: true})
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc["subject"].([]any)[0].(map[string]any)["name"] = "payments-agent-prod"
	doc["predicate"].(map[string]any)["issuedAt"] = "2026-09-26T00:00:00Z"
	relabelled, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, relabelled)
	other := strings.Repeat("c", 64)
	cases := []struct {
		name  string
		extra map[string]any
		code  int
		want  string
	}{
		{"digest of another artifact", map[string]any{"expectedSubjectDigest": other}, 1, "subject-anchor-mismatch"},
		{"the digest the observer bound", nil, 0, "admitted: true"},
		{"a one-day issuance lag", map[string]any{"maxIssuanceLagSeconds": 86400}, 1, "issuance-lag-exceeded"},
	}
	for _, tc := range cases {
		var out, errb bytes.Buffer
		code := run([]string{"-policy", fullPolicyFile(t, relabelled, tc.extra), path}, &out, &errb)
		if code != tc.code || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%s: exit %d (want %d), report lacks %q:\n%s%s", tc.name, code, tc.code, tc.want, out.String(), errb.String())
		}
	}
}

func TestFlagsAndDocumentMustAgree(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	path := writeTemp(t, body)
	policy := fullPolicyFile(t, body, nil)
	corpus, _, subject, _ := statementPins(t, body)
	var out, errb bytes.Buffer
	if code := run([]string{"-policy", policy, "-expected-corpus-digest", strings.Repeat("0", 64), path}, &out, &errb); code != 2 {
		t.Fatalf("conflicting corpus pin: exit %d, want 2", code)
	}
	out.Reset()
	if code := run([]string{"-policy", policy, "-expected-corpus-digest", corpus, "-expected-subject-digest", subject, path}, &out, &errb); code != 0 {
		t.Fatalf("agreeing pins: exit %d, want 0, stderr=%q", code, errb.String())
	}
	keys := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey))
	if code := run([]string{"-policy", policy, "-keys", keys, path}, &out, &errb); code != 2 {
		t.Fatalf("two policy documents: exit %d, want 2", code)
	}
	for _, args := range [][]string{
		{"-admit-unintercepted-clean-rows", "yes", path},
		{"-max-issuance-lag", "-1s", path},
	} {
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestSingleFlagsBuildAnAdmittingPolicy(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	path := writeTemp(t, body)
	corpus, substrate, subject, classes := statementPins(t, body)
	keys := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey))
	var out, errb bytes.Buffer
	code := run([]string{"-keys", keys, "-expected-corpus-digest", corpus, "-expected-substrate-digest", substrate,
		"-expected-subject-digest", subject, "-demand-classes", strings.Join(classes, ","),
		"-accept-results", "pass", "-admit-unintercepted-clean-rows", "false",
		"-max-issuance-lag", "24h", "-max-evidence-age", "876000h", "-allow-published-test-keys", path}, &out, &errb)
	if code != 0 {
		t.Fatalf("every pin by flag: exit %d, stderr=%q\n%s", code, errb.String(), out.String())
	}
	out.Reset()
	code = run([]string{"-keys", keys, "-allow-unpinned-anchors", "-allow-unpinned-scope", "-allow-published-test-keys", path}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), "admitted: true") {
		t.Fatalf("pins declined by name: exit %d\n%s", code, out.String())
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
	if !strings.Contains(out.String(), "verdict: invalid") || !strings.Contains(out.String(), "admitted: false") {
		t.Fatalf("expected an invalid, unadmitted report, got:\n%s", out.String())
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
	if code := run([]string{"-validity-only", "-json", valid}, &out, &errb); code != 0 {
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
	if code := run([]string{"-validity-only", "-json", invalid}, &out, &errb); code != 1 {
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

func TestSubstrateKeysEnvSuppliesTheKeys(t *testing.T) {
	// The harness fixes argv to `<cmd> <vector-file>` and hands the key policy
	// over in this variable, running each vector once with it and once without.
	statement := writeTemp(t, aeetest.Build(aeetest.Options{}))
	right := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey))
	wrong := keyPolicyFile(t, aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey))

	t.Setenv(EnvSubstrateKeys, right)
	var out, errb bytes.Buffer
	if code := run([]string{"-validity-only", "-json", statement}, &out, &errb); code != 0 {
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
	if code := run([]string{"-validity-only", "-json", "-keys", right, statement}, &out, &errb); code != 0 {
		t.Fatalf("-keys over env: exit %d, stderr=%q", code, errb.String())
	}
	if tiers := harnessRead(t, out.String())["tiers"]; !reflect.DeepEqual(tiers, []any{"attested"}) {
		t.Fatalf("-keys must outrank $%s: tiers = %v, want [attested]", EnvSubstrateKeys, tiers)
	}

	// Unset, no TOFU: the substrate row derives unattested.
	t.Setenv(EnvSubstrateKeys, "")
	out.Reset()
	errb.Reset()
	if code := run([]string{"-validity-only", "-json", statement}, &out, &errb); code != 0 {
		t.Fatalf("no key: exit %d, stderr=%q", code, errb.String())
	}
	if tiers := harnessRead(t, out.String())["tiers"]; !reflect.DeepEqual(tiers, []any{"unattested"}) {
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

func TestRunWrongKeyUnattestedNotAdmitted(t *testing.T) {
	body := aeetest.Build(aeetest.Options{Clean: true})
	statement := writeTemp(t, body)
	wrong := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	policy := fullPolicyFile(t, body, map[string]any{
		"substrateObservationKeys": []map[string]string{{"publicKeyHex": hex.EncodeToString(wrong)}},
	})
	var out, errb bytes.Buffer
	if code := run([]string{"-policy", policy, statement}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1 (valid but not admitted), stderr=%q", code, errb.String())
	}
	for _, want := range []string{"verdict: valid", "unattested", "refused: substrate-row-unattested", "admitted: false"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, out.String())
		}
	}
}

func TestPolicyDocumentErrorsExit2(t *testing.T) {
	path := writeTemp(t, aeetest.Build(aeetest.Options{Clean: true}))
	write := func(s string) string {
		p := filepath.Join(t.TempDir(), "k.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, doc := range []string{
		"{",
		`{"substrateObservationKeys":[{"publicKeyHex":"zz"}]}`,
		`{"substrateObservationKeys":[{"publicKeyHex":"aabb"}]}`,
		`{"expectedSubjectDigests":"aa"}`,
		`{"maxIssuanceLagSeconds":0}`,
	} {
		var out, errb bytes.Buffer
		if code := run([]string{"-policy", write(doc), path}, &out, &errb); code != 2 {
			t.Fatalf("policy %s: exit %d, want 2", doc, code)
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-policy", filepath.Join(t.TempDir(), "absent.json"), path}, &out, &errb); code != 2 {
		t.Fatalf("absent policy file: exit %d, want 2", code)
	}
}
