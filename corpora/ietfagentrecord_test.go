package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

const iarCorpusDir = "../vectors-ietf-agent-record-drafts"

// TestIETFAgentRecordCorpusBehaves: every member reaches the verdict and first
// refusal its manifest entry declares on this rail, and the draft's own
// procedure reaches the recorded draftReading.
func TestIETFAgentRecordCorpusBehaves(t *testing.T) {
	result, err := Judge(iarCorpusDir)
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
	if len(result.Members) == 0 {
		t.Fatal("no member was read, so this test asserted nothing")
	}
}

// TestIETFAgentRecordRulesAreLoadBearing disables one rule at a time. Each must
// admit exactly the reject members the Python rail's sweep reports for it, and
// none may refuse an accept member.
func TestIETFAgentRecordRulesAreLoadBearing(t *testing.T) {
	want := map[string][]string{
		iarDraftAIR + " cose-shape":             {"air-cwt-sub-missing"},
		iarDraftAIR + " signature":              {"air-signed-by-other-key"},
		iarDraftAIR + " content-hash":           {"air-content-hash-mismatch"},
		iarDraftAIR + " chain-hash":             {"air-chain-hash-mismatch"},
		iarDraftAIR + " sequence":               {"air-sequence-gap"},
		iarDraftAIR + " header-payload":         {"air-header-payload-time-differ"},
		iarDraftAIR + " prev-chain-link":        {"air-prev-chain-hash-mismatch"},
		iarDraftAIR + " time-order":             {"air-timestamp-before-predecessor"},
		iarDraftAIR + " position-unique":        {"air-two-records-one-position"},
		iarDraftCLL + " deterministic-encoding": {"cll-commitment-key-repeated"},
		iarDraftCLL + " cose-shape":             {"cll-sub-missing"},
		iarDraftCLL + " signature":              {"cll-signed-by-other-key"},
		iarDraftCLL + " claims":                 {"cll-kind-wrong"},
		iarDraftCLL + " continuity":             {"cll-not-continuous"},
		iarDraftCLL + " issued-at-order":        {"cll-issued-at-regression"},
		iarDraftCLL + " registration-time":      {"cll-cp4-registered-two-weeks-late"},
		iarDraftCLL + " history-fork":           {"cll-second-history-same-identity"},
		iarDraftSID + " duplicate-key":          {"sid-protected-header-key-repeated"},
		iarDraftSID + " signature":              {"sid-signature-other-key"},
		iarDraftSID + " identity":               {"sid-different-payload"},
	}
	raw, err := os.ReadFile(filepath.Join(iarCorpusDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m iarManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys, err := iarLoadKeys(&m)
	if err != nil {
		t.Fatal(err)
	}
	for draft, rules := range iarRules {
		for _, rule := range rules {
			var admitted []string
			for _, v := range m.Vectors {
				if v.Draft != draft || v.Kind == "indeterminate" {
					continue
				}
				body, err := os.ReadFile(filepath.Join(iarCorpusDir, v.File))
				if err != nil {
					t.Fatal(err)
				}
				report := iarVerify(body, keys, map[string]bool{rule: true})
				if v.Kind == "accept" && report.verdict != "valid" {
					t.Errorf("disabling %s %s refuses accept member %s", draft, rule, v.Slug)
				}
				if v.Kind == "reject" && report.verdict == "valid" {
					admitted = append(admitted, v.Slug)
				}
			}
			sort.Strings(admitted)
			if expect := want[draft+" "+rule]; !reflect.DeepEqual(admitted, expect) {
				t.Errorf("disabling %s %s admits %v, the Python rail admits %v", draft, rule, admitted, expect)
			}
		}
	}
}

// TestIETFAgentRecordStrictDecoder pins the strict decoder on the shapes the
// deterministic encoding never writes, and the two lenient readings of a
// repeated key.
func TestIETFAgentRecordStrictDecoder(t *testing.T) {
	cases := map[string][]byte{
		"repeated key":      {0xa2, 0x01, 0x01, 0x01, 0x02},
		"unsorted keys":     {0xa2, 0x02, 0x01, 0x01, 0x02},
		"non-shortest head": {0x18, 0x05},
		"trailing bytes":    {0x01, 0x02},
	}
	for name, data := range cases {
		if _, err := iarDecode(data, "strict"); err == nil {
			t.Errorf("%s: the strict decoder accepted %x", name, data)
		}
	}
	repeated := []byte{0xa2, 0x01, 0x01, 0x01, 0x02}
	first, err := iarDecode(repeated, "first")
	if err != nil || first.(map[any]any)[int64(1)] != int64(1) {
		t.Errorf("first-wins read %v, %v", first, err)
	}
	last, err := iarDecode(repeated, "last")
	if err != nil || last.(map[any]any)[int64(1)] != int64(2) {
		t.Errorf("last-wins read %v, %v", last, err)
	}
	if !iarRepeatedKey(repeated) || iarRepeatedKey([]byte{0xa2, 0x01, 0x01, 0x02, 0x02}) {
		t.Error("the repeated-key walk does not tell a repeated key from two distinct ones")
	}
}
