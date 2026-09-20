package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aeetest"
)

func writeKeys(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, "keys.json")
	body := map[string]any{
		"substrateObservationKeys": []map[string]string{
			{"keyid": aeetest.KeyID(pub), "publicKeyHex": hex.EncodeToString(pub)},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write keys: %v", err)
	}
	return path
}

// corpus builds a two-vector suite in the accept/ + reject/ layout mutrun reads.
func corpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// One flat directory, matching the corpus this harness reads. The fixture
	// used to build the per-verdict layout, which is the layout that told a
	// rail the verdict from the path and which mutrun no longer reads at all.
	for _, sub := range []string{"statements"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	good := aeetest.Build(aeetest.Options{})
	if err := os.WriteFile(filepath.Join(dir, "statements", "v0000000000000000.json"), good, 0o600); err != nil {
		t.Fatalf("write accept: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "statements", "v1111111111111111.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write reject: %v", err)
	}
	return dir
}

func replay(t *testing.T, vectors, keys string) []observation {
	t.Helper()
	var out, errs bytes.Buffer
	if code := run([]string{vectors, keys}, &out, &errs); code != 0 {
		t.Fatalf("mutrun exited %d: %s", code, errs.String())
	}
	var obs []observation
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var o observation
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		obs = append(obs, o)
	}
	return obs
}

func TestReplayEmitsOneLinePerVectorInOrder(t *testing.T) {
	dir := corpus(t)
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	obs := replay(t, dir, writeKeys(t, t.TempDir(), pub))

	if len(obs) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(obs))
	}
	if obs[0].ID != "v0000000000000000" || obs[1].ID != "v1111111111111111" {
		t.Fatalf("ids or ordering wrong: %q, %q", obs[0].ID, obs[1].ID)
	}
	if obs[0].Verdict != "valid" {
		t.Errorf("a well-formed statement replayed as %q: %v", obs[0].Verdict, obs[0].Codes)
	}
	if obs[1].Verdict != "invalid" || len(obs[1].Codes) == 0 {
		t.Errorf("a malformed statement replayed as %q with codes %v", obs[1].Verdict, obs[1].Codes)
	}
}

// The whole reason mutrun runs each vector twice. A replay that answered only the
// pinned-key pass would report nothing for the no-key tier column, and the
// harness skips a column it was handed nothing for -- so the corpus's only
// statement of the no-TOFU rule would be compared against nothing.
func TestBothKeyPassesAreReportedAndDiffer(t *testing.T) {
	dir := corpus(t)
	pub := aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey)
	obs := replay(t, dir, writeKeys(t, t.TempDir(), pub))
	accept := obs[0]

	if len(accept.Tiers) == 0 {
		t.Fatal("the pinned-key pass reported no tier column")
	}
	if len(accept.TiersWithoutKey) == 0 {
		t.Fatal("the no-key pass reported no tier column, so the no-TOFU rule would compare against nothing")
	}
	attested := false
	for _, tier := range accept.Tiers {
		if tier == "attested" {
			attested = true
		}
	}
	if !attested {
		t.Fatalf("the pinned key derived no attested row: %v", accept.Tiers)
	}
	for _, tier := range accept.TiersWithoutKey {
		if tier != "unattested" {
			t.Errorf("a consumer with no pinned key derived %q; no substrate root may be inferred from the predicate", tier)
		}
	}
	if accept.ResultWithoutKey != accept.Result {
		t.Errorf("tier derivation altered result: %q with a key, %q without", accept.Result, accept.ResultWithoutKey)
	}
}

// A wrong key must not silently produce the pinned-key answer, or the fast path
// would report a policy it was never handed.
func TestAWrongKeyDerivesUnattested(t *testing.T) {
	dir := corpus(t)
	wrong := aeetest.TestKey(aeetest.RoleWrongSigner).Public().(ed25519.PublicKey)
	obs := replay(t, dir, writeKeys(t, t.TempDir(), wrong))
	for _, tier := range obs[0].Tiers {
		if tier != "unattested" {
			t.Errorf("a wrong pinned key derived %q", tier)
		}
	}
}

func TestUsageAndIOFailures(t *testing.T) {
	dir := corpus(t)
	keys := writeKeys(t, t.TempDir(), aeetest.TestKey(aeetest.RoleSubstrateObservation).Public().(ed25519.PublicKey))
	missing := filepath.Join(t.TempDir(), "absent")

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "usage:"},
		{"one argument", []string{dir}, "usage:"},
		{"missing key file", []string{dir, missing}, "no such file"},
		{"empty corpus", []string{t.TempDir(), keys}, "no vectors under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			if code := run(tc.args, &out, &errs); code != 2 {
				t.Fatalf("exited %d, want 2", code)
			}
			if !strings.Contains(errs.String(), tc.want) {
				t.Errorf("stderr %q does not carry %q", errs.String(), tc.want)
			}
		})
	}
}

func TestUnparseableKeyPolicyIsRefused(t *testing.T) {
	dir := corpus(t)
	bad := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{dir, bad}, &out, &errs); code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
	if !strings.Contains(errs.String(), "does not parse") {
		t.Errorf("stderr %q does not name the parse failure", errs.String())
	}
}

func TestNonHexKeyIsRefused(t *testing.T) {
	dir := corpus(t)
	bad := filepath.Join(t.TempDir(), "keys.json")
	body := `{"substrateObservationKeys":[{"keyid":"k","publicKeyHex":"zzzz"}]}`
	if err := os.WriteFile(bad, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{dir, bad}, &out, &errs); code != 2 {
		t.Fatalf("exited %d, want 2", code)
	}
	if !strings.Contains(errs.String(), "not hex") {
		t.Errorf("stderr %q does not name the bad key", errs.String())
	}
}

func TestVectorIDStripsDirectoryAndExtension(t *testing.T) {
	if got := vectorID("/a/b/reject/bad-001-x.json"); got != "bad-001-x" {
		t.Errorf("vectorID = %q", got)
	}
}

func TestTierStringsPreservesNil(t *testing.T) {
	if tierStrings(nil) != nil {
		t.Error("a nil tier column must stay nil: the CLI omits it and the harness reads None")
	}
}
