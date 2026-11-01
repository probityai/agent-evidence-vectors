package corpora

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const adCorpusDir = "../vectors-agent-decision"

func adLoad(t *testing.T) (adManifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(adCorpusDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m adManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m, raw
}

func adMember(t *testing.T, v adVector) ([]byte, []byte) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(adCorpusDir, v.File))
	if err != nil {
		t.Fatal(err)
	}
	var arguments []byte
	if v.Arguments != "" {
		if arguments, err = os.ReadFile(filepath.Join(adCorpusDir, v.Arguments)); err != nil {
			t.Fatal(err)
		}
	}
	return body, arguments
}

// TestAgentDecisionCorpusBehaves: every member reaches the verdict and first
// refusal its manifest entry declares, on this rail.
func TestAgentDecisionCorpusBehaves(t *testing.T) {
	result, err := Judge(adCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range result.Members {
		for _, f := range m.Findings {
			t.Errorf("%s: %s", m.ID, f)
		}
	}
	for _, f := range result.Findings {
		t.Errorf("corpus: %s", f)
	}
	if len(result.Members) != 41 {
		t.Fatalf("expected 41 members, read %d", len(result.Members))
	}
}

// TestAgentDecisionRulesAreLoadBearing disables one rule at a time. Each must
// admit exactly the reject members the Python rail's sweep reports for it, and
// none may refuse an accept member. Matching the Python sets member for member
// is what shows the two rails replace a disabled admission rule with the same
// library behaviour.
func TestAgentDecisionRulesAreLoadBearing(t *testing.T) {
	want := map[string][]string{
		"signature":           {"payload-edited-after-signing"},
		"statement":           {"statement-type-v0-1"},
		"predicate-shape":     {"decision-outside-set", "tool-calls-empty"},
		"args-state":          {"state-absent", "state-unknown"},
		"args-hash-presence":  {"not-recorded-with-hash", "recorded-without-hash", "redacted-without-hash", "unavailable-with-hash"},
		"args-hash-format":    {"hash-uppercase"},
		"arguments-json":      {"arguments-not-an-object"},
		"arguments-duplicate": {"duplicate-amount"},
		"arguments-integer":   {"integer-1e21-digits", "integer-2-53", "integer-2-53-plus-1"},
		"arguments-overflow":  {"overflow-1e400"},
		"args-hash-match": {"member-order-code-point", "number-1-point-0-drift", "number-1e-6-drift",
			"number-1e-7-drift", "number-1e16-drift", "number-1e21-drift", "number-negative-zero-drift"},
	}
	m, _ := adLoad(t)
	for _, rule := range adRules {
		var admitted []string
		for _, v := range m.Vectors {
			body, arguments := adMember(t, v)
			report := adVerify(body, arguments, &m, rule)
			if v.Kind == "accept" && report.verdict != "valid" {
				t.Errorf("disabling %s refuses accept member %s", rule, v.Slug)
			}
			if v.Kind == "reject" && report.verdict == "valid" {
				admitted = append(admitted, v.Slug)
			}
		}
		sort.Strings(admitted)
		if !reflect.DeepEqual(admitted, want[rule]) {
			t.Errorf("disabling %s admits %v, the Python rail admits %v", rule, admitted, want[rule])
		}
	}
}

func TestAgentDecisionES6(t *testing.T) {
	cases := map[float64]string{
		1e21: "1e+21", 1e20: "100000000000000000000", 1e16: "10000000000000000", 1: "1",
		1e-6: "0.000001", 1e-7: "1e-7", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
		123.456: "123.456", -1.5e-9: "-1.5e-9", 9007199254740993.0: "9007199254740992", 0.1: "0.1",
	}
	for in, want := range cases {
		if got, err := adES6(in); err != nil || got != want {
			t.Errorf("adES6(%v) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, err := adES6(math.Copysign(0, -1)); err != nil || got != "0" {
		t.Errorf("negative zero = %q, %v", got, err)
	}
}

func TestAgentDecisionCanonical(t *testing.T) {
	cases := map[string]string{
		`{"b":1,"a":[true,false,null,"x"]}`:       `{"a":[true,false,null,"x"],"b":1}`,
		"{\"＄\":1,\"\U0001f4b6\":2}":              "{\"\U0001f4b6\":2,\"＄\":1}",
		`{"s":"q\"\\\b\f\n\r\t\u0001\u007f"}`:     "{\"s\":\"q\\\"\\\\\\b\\f\\n\\r\\t\\u0001\u007f\"}",
		`{"n":-0,"d":1E21,"e":1.0,"f":[{"g":2}]}`: `{"d":1e+21,"e":1,"f":[{"g":2}],"n":0}`,
	}
	for in, want := range cases {
		value, err := adAdmit([]byte(in), "")
		if err != nil {
			t.Fatalf("adAdmit(%s): %v", in, err)
		}
		got, err := adCanonical(value)
		if err != nil || string(got) != want {
			t.Errorf("canonical(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
}

func TestAgentDecisionAdmissionRefusals(t *testing.T) {
	cases := map[string]string{
		"\xff":                         "arguments-not-json",
		`{"a":1} trailing`:             "arguments-not-json",
		`{"a":NaN}`:                    "arguments-not-json",
		`[1]`:                          "arguments-not-json",
		`{"a":1,"a":2}`:                "arguments-duplicate-member",
		`{"a":{"b":1,"b":1}}`:          "arguments-duplicate-member",
		`{"a":-9007199254740992}`:      "arguments-integer-unsafe",
		`{"a":[1e400]}`:                "arguments-number-overflow",
		strings.Repeat("[", 200) + "1": "arguments-not-json",
	}
	for in, want := range cases {
		_, err := adAdmit([]byte(in), "")
		var refused *adRefusal
		if err == nil || !errorsAs(err, &refused) || refused.code != want {
			t.Errorf("adAdmit(%.40q) = %v; want %s", in, err, want)
		}
	}
	if _, err := adAdmit([]byte(`{"a":-9007199254740991}`), ""); err != nil {
		t.Errorf("the smallest safe integer is refused: %v", err)
	}
}

// TestAgentDecisionEnvelopeRefusals reaches the refusals no corpus member is
// built for: an envelope that is not JSON, one that is not an object, and a
// signature block of the wrong shape.
func TestAgentDecisionEnvelopeRefusals(t *testing.T) {
	m, _ := adLoad(t)
	cases := map[string]adReport{
		`not json`:            {"malformed", "statement-malformed"},
		`[]`:                  {"invalid", "signature-invalid"},
		`{"payloadType": 3`:   {"malformed", "statement-malformed"},
		`{"payloadType":"x"}`: {"invalid", "signature-invalid"},
		`{"payloadType":"` + m.PayloadType + `"}`:                                                {"invalid", "signature-invalid"},
		`{"payloadType":"` + m.PayloadType + `","payload":"e30=","signatures":[]}`:               {"invalid", "signature-invalid"},
		`{"payloadType":"` + m.PayloadType + `","payload":"e30=","signatures":[{"sig":"!!"}]}`:   {"invalid", "signature-invalid"},
		`{"payloadType":"` + m.PayloadType + `","payload":"e30=","signatures":[{"sig":"AAAA"}]}`: {"invalid", "signature-invalid"},
	}
	for in, want := range cases {
		if got := adVerify([]byte(in), nil, &m, ""); got != want {
			t.Errorf("adVerify(%s) = %+v; want %+v", in, got, want)
		}
	}
	if got := adVerify([]byte(`{"payload":"e30="}`), nil, &m, "signature"); got.code != "statement-malformed" {
		t.Errorf("an empty statement with the signature rule off reached %+v", got)
	}
}

// TestAgentDecisionStatementShapes judges statements directly, past the
// signature, so each malformed shape reaches the rule that names it.
func TestAgentDecisionStatementShapes(t *testing.T) {
	m, _ := adLoad(t)
	good := `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + m.PredicateType +
		`","subject":[{"name":"t","digest":{"sha256":"00"}}],"predicate":%s}`
	predicate := `{"agent_id":"a","principal":{"subject":"p"},"policy_evaluations":[{"policy":"x",` +
		`"decision":"allow","reason":"r"}],"tool_calls":[%s],"decided_at":"2026-10-04T00:00:00Z"}`
	check := func(stmt string, want adReport) {
		t.Helper()
		err := func() error {
			parsed, err := adStatement([]byte(stmt), m.PredicateType)
			if err != nil {
				return err
			}
			calls, err := adCalls(parsed["predicate"], "")
			if err != nil {
				return err
			}
			for _, c := range calls {
				if err := adCall(c.(map[string]any), nil, ""); err != nil {
					return err
				}
			}
			return nil
		}()
		got := adReport{verdict: "valid"}
		var refused *adRefusal
		if errorsAs(err, &refused) {
			got = adReport{refused.verdict, refused.code}
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", stmt, got, want)
		}
	}
	call := `{"name":"t","args_state":"unavailable"}`
	check(strings.Replace(good, "%s", strings.Replace(predicate, "%s", call, 1), 1), adReport{verdict: "valid"})
	check(`[]`, adReport{"malformed", "statement-malformed"})
	check(`{"subject":[{"name":"t","digest":{}}]}`, adReport{"malformed", "statement-malformed"})
	check(`{"subject":["t"]}`, adReport{"malformed", "statement-malformed"})
	bad := []string{
		`{}`,
		`{"agent_id":"a","principal":"p"}`,
		`{"agent_id":"a","principal":{"subject":"p"},"policy_evaluations":[]}`,
		`{"agent_id":"a","principal":{"subject":"p"},"policy_evaluations":[{"policy":"x","decision":"allow"}]}`,
		strings.Replace(predicate, "%s", `"t"`, 1),
		strings.Replace(strings.Replace(predicate, "%s", call, 1), "2026-10-04T00:00:00Z", "yesterday", 1),
	}
	for _, p := range bad {
		check(strings.Replace(good, "%s", p, 1), adReport{"malformed", "predicate-malformed"})
	}
	check(strings.Replace(good, "%s", strings.Replace(predicate, "%s", `{"name":"t","args_state":"recorded","args_hash":7}`, 1), 1),
		adReport{"malformed", "args-hash-format"})
}

// TestAgentDecisionCorpusFindings: a manifest whose counts, digest or parent
// disagree with the tree is refused at the corpus level, naming what failed.
func TestAgentDecisionCorpusFindings(t *testing.T) {
	_, raw := adLoad(t)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["corpusDigest"] = strings.Repeat("0", 64)
	doc["counts"] = map[string]int{"accept": 1}
	vectors := doc["vectors"].([]any)
	for _, v := range vectors {
		entry := v.(map[string]any)
		if entry["kind"] == "reject" {
			entry["parent"] = "vnotamember"
			break
		}
	}
	for _, v := range vectors {
		entry := v.(map[string]any)
		if _, ok := entry["canonicalArguments"]; ok {
			entry["canonicalArguments"] = "{}"
			break
		}
	}
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	result, err := agentDecision{}.Judge(adCorpusDir, tampered)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(result.Findings, "\n")
	for _, want := range []string{"counts", "corpusDigest"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no corpus finding names %s: %v", want, result.Findings)
		}
	}
	var memberFindings []string
	for _, m := range result.Members {
		memberFindings = append(memberFindings, m.Findings...)
	}
	all := strings.Join(memberFindings, "\n")
	for _, want := range []string{"parent is not an accept member", "canonicalArguments disagrees"} {
		if !strings.Contains(all, want) {
			t.Errorf("no member finding says %q", want)
		}
	}
	if _, err := (agentDecision{}).Judge(adCorpusDir, []byte("{")); err == nil {
		t.Error("an unparseable manifest was judged")
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
