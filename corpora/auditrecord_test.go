package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const arCorpusDir = "../vectors-agent-audit-record"

func arLoad(t *testing.T) (arManifest, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(arCorpusDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest arManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	bodies := map[string][]byte{}
	for _, v := range manifest.Vectors {
		body, err := os.ReadFile(filepath.Join(arCorpusDir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		bodies[v.ID] = body
	}
	return manifest, bodies
}

// TestAuditRecordCorpusBehaves: every member reaches the verdict, the first
// refusal and the recomputed tier its manifest entry declares, on this rail.
func TestAuditRecordCorpusBehaves(t *testing.T) {
	result, err := Judge(arCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		for _, m := range result.Members {
			for _, f := range m.Findings {
				t.Errorf("%s: %s", m.ID, f)
			}
		}
		for _, f := range result.Findings {
			t.Errorf("corpus: %s", f)
		}
	}
	if len(result.Members) != 63 {
		t.Fatalf("expected the 63 Appendix B rows, read %d", len(result.Members))
	}
}

// TestAuditRecordRulesAreLoadBearing disables one rule at a time. Each must
// change what some reject member is refused for, and none may refuse an
// accept member when it is switched off.
func TestAuditRecordRulesAreLoadBearing(t *testing.T) {
	manifest, bodies := arLoad(t)
	key := manifest.Keys.Observer.PublicKey
	full := map[string]arReport{}
	for _, v := range manifest.Vectors {
		full[v.ID] = arVerify(bodies[v.ID], manifest.PredicateType, key, "")
	}
	names := []string{"signature"}
	for _, rule := range arRules(manifest.PredicateType) {
		if rule.name != "statement" { // no Appendix B row reaches it
			names = append(names, rule.name)
		}
	}
	for _, name := range names {
		moved := false
		for _, v := range manifest.Vectors {
			got := arVerify(bodies[v.ID], manifest.PredicateType, key, name)
			if v.Kind == "accept" && got.verdict != "valid" {
				t.Errorf("disabling %s refuses accept member %s", name, v.DraftID)
			}
			if v.Kind == "reject" && (got.verdict != full[v.ID].verdict || got.code != full[v.ID].code) {
				moved = true
			}
		}
		if !moved {
			t.Errorf("rule %s is inert: disabling it changes no reject member", name)
		}
	}
}

// TestAuditRecordRefusesForeignShapes covers the refusals no corpus member
// reaches: an unreadable envelope, a foreign payload type, a wrong predicate
// type, a non-object statement and a mistyped member.
func TestAuditRecordRefusesForeignShapes(t *testing.T) {
	manifest, bodies := arLoad(t)
	key := manifest.Keys.Observer.PublicKey
	var accept []byte
	for _, v := range manifest.Vectors {
		if v.DraftID == "A1" {
			accept = bodies[v.ID]
		}
	}
	cases := map[string][]byte{
		"not json":          []byte("{"),
		"foreign type":      []byte(strings.Replace(string(accept), "application/vnd.in-toto+json", "text/plain", 1)),
		"bad base64":        []byte(`{"payload":"@@","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
		"array statement":   []byte(`{"payload":"W10=","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
		"float statement":   []byte(`{"payload":"eyJhIjoxLjV9","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
		"garbage statement": []byte(`{"payload":"e30x","payloadType":"application/vnd.in-toto+json","signatures":[]}`),
	}
	for name, body := range cases {
		if got := arVerify(body, manifest.PredicateType, key, ""); got.verdict != "malformed" {
			t.Errorf("%s: expected malformed, got %s", name, got.verdict)
		}
	}
	if got := arVerify(accept, "urn:other", key, ""); got.code != "predicate-type-mismatch" {
		t.Errorf("wrong predicate type: got %q", got.code)
	}
	if got := arVerify(accept, manifest.PredicateType, "zz", ""); got.code != "signature-invalid" {
		t.Errorf("unreadable key: got %q", got.code)
	}
	if got := arVerify(accept, manifest.PredicateType, key, "signature"); got.verdict != "valid" {
		t.Errorf("A1 with the signature rule off: got %s", got.verdict)
	}
}

func TestAuditRecordHelpers(t *testing.T) {
	if !arUnder("/srv/ledger/a", "/srv/ledger/") || arUnder("/srv/ledgers/a", "/srv/ledger") {
		t.Error("segment-boundary containment")
	}
	if !arUnder("/x", "/") || !arUnder("/srv/ledger", "/srv/ledger/") {
		t.Error("universal scope and the scope itself")
	}
	if _, err := arInstant("yesterday"); err == nil {
		t.Error("a non-RFC 3339 time must refuse")
	}
	for _, c := range []struct{ reported, observed, want string }{
		{"permit", "occurred", "agree"}, {"deny", "none", "agree"}, {"deny", "occurred", "disagree"},
		{"permit", "none", "not-exercised"}, {"deny", "unknown", "indeterminate"},
	} {
		if got := arDeriveAgreement(c.reported, c.observed); got != c.want {
			t.Errorf("%s beside %s: got %s, want %s", c.reported, c.observed, got, c.want)
		}
	}
	if arRun(func(*arState) error { panic("mistyped member") }, &arState{}) == nil {
		t.Error("a panicking rule must refuse rather than crash the replay")
	}
	if arHasAll(nil, []string{"a"}) {
		t.Error("a missing object carries no members")
	}
}
