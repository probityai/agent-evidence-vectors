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
		if v.Expected.Dating != nil {
			// A retained member's file is the envelope beside its retention
			// entry; the record rules judge the envelope.
			if body, _, err = arUnwrapRetained(body); err != nil {
				t.Fatal(err)
			}
		}
		if v.Expected.Set != nil {
			// A set member's file is a bundle of envelopes; the record rules
			// judge its first, and TestAuditRecordSetRulesAreLoadBearing the set.
			envelopes, err := arSetRecords(body)
			if err != nil || len(envelopes) == 0 {
				t.Fatalf("%s: the set carries no readable record", v.DraftID)
			}
			body = envelopes[0]
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
	// The judge must reach every member the manifest lists, once each; the
	// expected count is the manifest's own, never a number typed here.
	manifest, _ := arLoad(t)
	judged := map[string]int{}
	for _, m := range result.Members {
		judged[m.ID]++
	}
	for _, v := range manifest.Vectors {
		if judged[v.ID] != 1 {
			t.Errorf("%s: judged %d times, want once", v.ID, judged[v.ID])
		}
	}
	if len(result.Members) != len(manifest.Vectors) || len(judged) != len(manifest.Vectors) {
		t.Fatalf("manifest lists %d members, the judge read %d (%d distinct)",
			len(manifest.Vectors), len(result.Members), len(judged))
	}
}

// TestAuditRecordDatingRulesAreLoadBearing disables one dating rule at a time.
// Each must move some retained member off its declared dating result, and none
// may move a retained member's record verdict.
func TestAuditRecordDatingRulesAreLoadBearing(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(arCorpusDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest arManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	heads := arHeads(&manifest)
	key := manifest.Keys.Observer.PublicKey
	retained := 0
	for _, name := range arDatingRuleNames() {
		if name == "entry-envelope-digest" { // no Appendix B row reaches it
			continue
		}
		moved := false
		for _, v := range manifest.Vectors {
			if v.Expected.Dating == nil {
				continue
			}
			retained++
			body, err := os.ReadFile(filepath.Join(arCorpusDir, v.File))
			if err != nil {
				t.Fatal(err)
			}
			report, dated := arVerifyRetained(body, manifest.PredicateType, key, heads, name)
			if report.verdict != "valid" {
				t.Errorf("disabling %s moves %s's verdict to %s", name, v.DraftID, report.verdict)
			}
			if !dated.equal(*v.Expected.Dating) {
				moved = true
			}
		}
		if !moved {
			t.Errorf("dating rule %s is inert: disabling it moves no retained member", name)
		}
	}
	if retained == 0 {
		t.Fatal("the corpus carries no retained member")
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

// TestAuditRecordIssuedAtRule: issuedAt must parse as an instant and must not
// be earlier than effect.interval.sealedAt, however far earlier (IS1, IS2).
func TestAuditRecordIssuedAtRule(t *testing.T) {
	for _, c := range []struct {
		issued any
		want   string
	}{
		{"2026-09-19T11:04:06Z", ""},
		{"2026-09-19T11:04:11Z", ""},
		{"2026-09-19T13:04:06+02:00", ""},
		{"2026-09-19T11:04:05Z", "issued-before-sealed"},
		{"2026-09-18T11:04:06Z", "issued-before-sealed"},
		{"2026-09-19T12:04:05+02:00", "issued-before-sealed"},
		{"yesterday", "timestamp-malformed"},
		{"2026-09-19", "timestamp-malformed"},
		{"2026-09-19T11:04:11", "timestamp-malformed"},
		{"", "timestamp-malformed"},
		{20260919, "timestamp-malformed"},
		{nil, "timestamp-malformed"},
	} {
		state := &arState{pred: map[string]any{
			"issuedAt": c.issued,
			"effect":   map[string]any{"interval": map[string]any{"sealedAt": "2026-09-19T11:04:06Z"}},
		}}
		err := arRuleIssuedAfterSealed(state)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if !strings.Contains(got, c.want) || (c.want == "" && got != "") {
			t.Errorf("issuedAt %v: got %q, want %q", c.issued, got, c.want)
		}
	}
	state := &arState{pred: map[string]any{
		"issuedAt": "2026-09-19T11:04:11Z",
		"effect":   map[string]any{"interval": map[string]any{"sealedAt": "later"}},
	}}
	if arRuleIssuedAfterSealed(state) == nil {
		t.Error("an unparsable sealedAt leaves the two times uncomparable and must refuse")
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
	// A18 to A20 name policy-source, key-source and consumption-state. FR7
	// names key-source where its fresh entry derives none: still refused, but
	// at the vocabulary check rather than the pinned set mismatch.
	if got != "A12,A13,A14,A18,A19,A20,FR7" {
		t.Errorf("unavailableInput hard-coded to standing-source: failing %q, want A12,A13,A14,A18,A19,A20,FR7", got)
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
