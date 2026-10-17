package corpora

import (
	"encoding/json"
	"math"
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
	if len(result.Members) != 92 {
		t.Fatalf("expected the 55 Appendix B rows, 16 section members and 21 freshness members, read %d",
			len(result.Members))
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

// arFailingDraftIDs judges the corpus and returns the identifier of every
// member with a finding, in manifest order.
func arFailingDraftIDs(t *testing.T) []string {
	t.Helper()
	result, err := Judge(arCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	var failing []string
	for _, m := range result.Members {
		if len(m.Findings) > 0 {
			label, _, _ := strings.Cut(m.Findings[0], ":")
			failing = append(failing, label)
		}
	}
	return failing
}

// TestAuditRecordClosedSetsAreForced: a reader that knows only the one value of
// each closed set Appendix B's accept rows carry (standing-source, check) fails
// this corpus, and fails it on exactly the members that carry the other values.
// Without them it scored every Appendix B row.
func TestAuditRecordClosedSetsAreForced(t *testing.T) {
	if got := arFailingDraftIDs(t); len(got) != 0 {
		t.Fatalf("the tracked corpus must judge clean first, failing: %v", got)
	}
	inputs := arUnavailableInputs
	arUnavailableInputs = []string{"standing-source"}
	got := strings.Join(arFailingDraftIDs(t), ",")
	arUnavailableInputs = inputs
	// FR7 names key-source where its fresh entry derives none: still refused,
	// but at the vocabulary check rather than the pinned set mismatch.
	if got != "A12,A13,A14,FR7" {
		t.Errorf("unavailableInput hard-coded to standing-source: failing %q, want A12,A13,A14,FR7", got)
	}
	var acts *[]string
	for i := range arVocabularies {
		if arVocabularies[i].path == "oversight.act" {
			acts = &arVocabularies[i].allowed
		}
	}
	if acts == nil {
		t.Fatal("no oversight.act vocabulary")
	}
	saved := *acts
	*acts = []string{"check"}
	got = strings.Join(arFailingDraftIDs(t), ",")
	*acts = saved
	if got != "A15,A16,A17" {
		t.Errorf("oversight.act hard-coded to check: failing %q, want A15,A16,A17", got)
	}
}

// TestAuditRecordFreshness pins the Section 5.4 sentences one at a time: an age
// equal to maxAge is fresh and one second more is stale, an input never held is
// unavailable, a lastResult up to the skew tolerance after reportedAt is fresh
// and one second past it is malformed, and maxAge is a non-negative integer.
func TestAuditRecordFreshness(t *testing.T) {
	reportedAt, err := arInstant("2026-09-19T11:04:02Z")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		last        string
		maxAge      int64
		unavailable bool
		code        string
	}{
		{"2026-09-19T10:04:02Z", 3600, false, ""},
		{"2026-09-19T10:04:01Z", 3600, true, ""},
		{arNeverHeld, 3600, true, ""},
		{"2026-09-19T11:09:02Z", 0, false, ""},
		{"2026-09-19T11:09:03Z", 3600, false, "evaluation-result-after-decision"},
		{"2026-09-19T10:00:00Z", math.MaxInt64, false, ""},
		{"yesterday", 3600, false, "timestamp-malformed"},
	}
	for _, c := range cases {
		got, err := arEntryUnavailable(map[string]any{"lastResult": c.last}, c.maxAge, reportedAt)
		code := ""
		if err != nil {
			code = err.Error()
		}
		if got != c.unavailable || code != c.code {
			t.Errorf("lastResult %s, maxAge %d: got (%v, %q), want (%v, %q)",
				c.last, c.maxAge, got, code, c.unavailable, c.code)
		}
	}
	for _, c := range []struct {
		value any
		ok    bool
	}{
		{json.Number("0"), true}, {json.Number("3600"), true}, {json.Number("-1"), false},
		{json.Number("1.5"), false}, {"3600", false}, {nil, false},
	} {
		if _, ok := arMaxAge(c.value); ok != c.ok {
			t.Errorf("maxAge %#v: accepted %v, want %v", c.value, ok, c.ok)
		}
	}
}
