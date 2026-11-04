package corpusreaders_test

// The containment-journal reader derives every decision from the case's own
// bytes. A denied member's journal or receipt moved into a control must give
// that member's reason, a control's moved into a denied member must give
// allow, and a journal edited after the fact must be refused.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const (
	cjDir            = "vectors-containment-journal"
	cjControl        = "allow-enforced-drop-over-removed-edge"
	cjReceiptControl = "allow-blast-radius-receipt-recomputes"
)

type cjRow struct {
	ID       string            `json:"id"`
	Files    map[string]string `json:"files"`
	Expected struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"expected"`
}

func cjRows(t *testing.T) []cjRow {
	t.Helper()
	var manifest struct {
		Vectors []cjRow `json:"vectors"`
	}
	body, err := os.ReadFile(filepath.Join(corpusPath(cjDir), "MANIFEST.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Vectors
}

func cjFile(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(cjDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// cjStage copies the corpus and writes the given files into one member.
func cjStage(t *testing.T, member string, files map[string][]byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), cjDir)
	copyTree(t, corpusPath(cjDir), copied)
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copied
}

func cjDerivedFor(t *testing.T, member string, files map[string][]byte) string {
	t.Helper()
	return scDerived(t, cjStage(t, member, files), member)
}

func TestContainmentJournalCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(cjDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != len(cjRows(t)) {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

// Every denied member's own bytes, judged in a control's place, give that
// member's reason: the Go rail reaches each reason off the record, not the
// manifest row.
func TestContainmentJournalEveryDeniedRecordGivesItsReason(t *testing.T) {
	for _, row := range cjRows(t) {
		if row.Expected.Decision != "deny" {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			control := cjControl
			files := map[string][]byte{"record.json": cjFile(t, row.ID, "record.json")}
			if _, receipt := row.Files["receipt.json"]; receipt {
				control = cjReceiptControl
				files["receipt.json"] = cjFile(t, row.ID, "receipt.json")
			}
			want := "derived deny/" + row.Expected.Reason + ","
			if got := cjDerivedFor(t, control, files); !strings.Contains(got, want) {
				t.Fatalf("want %q, got %q", want, got)
			}
		})
	}
}

func TestContainmentJournalAControlRecordInADeniedMemberIsAllowed(t *testing.T) {
	got := cjDerivedFor(t, "reject-chain-broken", map[string][]byte{"record.json": cjFile(t, cjControl, "record.json")})
	if !strings.Contains(got, "derived allow/containment_consistent") {
		t.Fatalf("want a derived allow, got %q", got)
	}
	got = cjDerivedFor(t, "reject-blast-radius-overstated",
		map[string][]byte{"receipt.json": cjFile(t, cjReceiptControl, "receipt.json")})
	if !strings.Contains(got, "derived allow/blast_radius_consistent") {
		t.Fatalf("want a derived allow, got %q", got)
	}
}

func TestContainmentJournalUnreadableInputsAreFindings(t *testing.T) {
	cases := map[string]map[string][]byte{
		"record.json does not parse":  {"record.json": []byte("{")},
		"not UTF-8":                   {"record.json": []byte("{\"a\": \"\xff\"}")},
		"trailing data":               {"record.json": []byte("{} {}")},
		"receipt.json does not parse": {"receipt.json": []byte("[")},
	}
	for want, files := range cases {
		member := cjControl
		if _, receipt := files["receipt.json"]; receipt {
			member = cjReceiptControl
		}
		if got := cjDerivedFor(t, member, files); !strings.Contains(got, want) {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
}

// Each way out of the canonical subset, and a date that is no date, written
// into the control's bytes.
func TestContainmentJournalNonCanonicalAndMalformedBytes(t *testing.T) {
	control := string(cjFile(t, cjControl, "record.json"))
	edits := []struct{ old, new, want string }{
		{`"runId": "run-drop"`, `"runId": "run-drop", "runId": "run-drop"`, "record_not_canonical"},
		{"\"seq\": 1\n", "\"seq\": 1.0\n", "record_not_canonical"},
		{"\"seq\": 1\n", "\"seq\": NaN\n", "record_not_canonical"},
		{"\"seq\": 1\n", "\"seq\": -Infinity\n", "record_not_canonical"},
		{"\"seq\": 1\n", "\"seq\": 9007199254740992\n", "record_not_canonical"},
		{`"runId": "run-drop"`, `"runId": "run-dröp"`, "record_not_canonical"},
		{`"runId": "run-drop"`, `"runId": "NaN \"Infinity\" run"`, "containment_consistent"},
		{`"at": "2026-11-03T09:00:10Z"`, `"at": "2026-02-30T09:00:10Z"`, "record_malformed"},
		{`"runId": "run-drop"`, `"runId": 7`, "record_malformed"},
		{`"enforcement": "enforced"`, `"enforcement": "strict"`, "closed_vocabulary_violation"},
		{`"contractId": "`, `"contractId": 7, "x": "`, "contract_id_unknown"},
	}
	for _, edit := range edits {
		if !strings.Contains(control, edit.old) {
			t.Fatalf("the control has no %q", edit.old)
		}
		body := strings.Replace(control, edit.old, edit.new, 1)
		got := cjDerivedFor(t, cjControl, map[string][]byte{"record.json": []byte(body)})
		// The control is allowed, so an allowed edit derives no disagreement at all.
		agrees := strings.Contains(got, "derived deny/"+edit.want+",") ||
			(edit.want == "containment_consistent" && !strings.Contains(got, "derived"))
		if !agrees {
			t.Fatalf("%s -> %s: want %s, got %q", edit.old, edit.new, edit.want, got)
		}
	}
	for _, body := range []string{`[]`, `{"agents": []}`} {
		got := cjDerivedFor(t, cjControl, map[string][]byte{"record.json": []byte(body)})
		if !strings.Contains(got, "derived deny/contract_id_missing") {
			t.Fatalf("%s: want contract_id_missing, got %q", body, got)
		}
	}
}

func cjEncode(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func cjDecodeRecord(t *testing.T, body []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var record map[string]any
	if err := dec.Decode(&record); err != nil {
		t.Fatal(err)
	}
	return record
}

// Dropping any entry the journal does not end on moves the verdict; the
// receipt's head also catches the last one.
func TestContainmentJournalDroppingAnEntryMovesTheVerdict(t *testing.T) {
	for _, member := range []string{cjControl, cjReceiptControl} {
		count := len(cjDecodeRecord(t, cjFile(t, member, "record.json"))["entries"].([]any))
		last := count - 1
		if member == cjReceiptControl {
			last = count
		}
		for index := 0; index < last; index++ {
			record := cjDecodeRecord(t, cjFile(t, member, "record.json"))
			entries := record["entries"].([]any)
			record["entries"] = append(entries[:index:index], entries[index+1:]...)
			got := cjDerivedFor(t, member, map[string][]byte{"record.json": cjEncode(t, record)})
			if !strings.Contains(got, "derived deny/") {
				t.Fatalf("%s without entry %d: want a deny, got %q", member, index, got)
			}
		}
	}
}

// One bit of one entry's seconds flipped breaks the chain at the next entry,
// and at the receipt's head for the last.
func TestContainmentJournalFlippingAByteMovesTheVerdict(t *testing.T) {
	body := cjFile(t, cjReceiptControl, "record.json")
	marker := []byte(`"at": "`)
	flipped := 0
	for start := bytes.Index(body, marker); start >= 0; {
		position := start + bytes.IndexByte(body[start:], 'Z') - 1
		mutated := append([]byte{}, body...)
		mutated[position] ^= 0x01
		got := cjDerivedFor(t, cjReceiptControl, map[string][]byte{"record.json": mutated})
		if !strings.Contains(got, "derived deny/") {
			t.Fatalf("flip at %d: want a deny, got %q", position, got)
		}
		flipped++
		next := bytes.Index(body[start+1:], marker)
		if next < 0 {
			break
		}
		start += next + 1
	}
	receipt := cjFile(t, cjReceiptControl, "receipt.json")
	for _, member := range []string{`"deliveries": `, `"toolCalls": `, `"agent-`} {
		mutated := append([]byte{}, receipt...)
		mutated[bytes.Index(receipt, []byte(member))+len(member)] ^= 0x01
		got := cjDerivedFor(t, cjReceiptControl, map[string][]byte{"receipt.json": mutated})
		if !strings.Contains(got, "derived deny/") {
			t.Fatalf("receipt flip after %s: want a deny, got %q", member, got)
		}
	}
	if flipped == 0 {
		t.Fatalf("no entry time found in %s", cjReceiptControl)
	}
}

// One structured edit: the member and file it changes, the JSON path, the new
// value as JSON, and the reason the edited case must give.
type cjEdit struct{ member, file, path, value, want string }

var cjEdits = []cjEdit{
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",0,"edges"]`, `[["agent-b","agent-a"],["agent-a","agent-b"]]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",0,"edges"]`, `[["agent-a","agent-a"]]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",0,"edges"]`, `"none"`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",0,"edges"]`, `[["agent-a","agent-z"]]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",0,"edges"]`, `[["agent-a"]]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",2,"bodyDigest"]`, `"sha256:00"`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["agents"]`, `["agent-b","agent-a","agent-c","agent-d"]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["agents"]`, `["agent-a"]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["claims"]`, `{"unknown":true}`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["claims"]`, `[]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["claims","responseBoundSeconds"]`, `-1`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["claims","channelsClosed"]`, `1`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries"]`, `[]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",1]`, `5`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",2,"extra"]`, `true`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",2,"event"]`, `"teleport"`, "closed_vocabulary_violation"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["messageFields"]`, `["sender","body"]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",2,"seq"]`, `true`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",1,"isolated"]`, `["agent-c","agent-a"]`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",1,"basis"]`, `5`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["entries",2,"edgeInForce"]`, `"no"`, "record_malformed"},
	{"allow-enforced-drop-over-removed-edge", "record.json", `["extra"]`, `1`, "record_malformed"},
	{"reject-decision-not-supported-by-estimates", "record.json", `["entries",1,"riskEstimates","agent-a"]`, `"0.5"`, "record_malformed"},
	{"reject-decision-not-supported-by-estimates", "record.json", `["entries",1,"riskEstimates"]`, `{"agent-a":"0.500000"}`, "record_malformed"},
	{"reject-decision-not-supported-by-estimates", "record.json", `["entries",1,"riskEstimates"]`, `[]`, "record_malformed"},
	{"reject-decision-not-supported-by-estimates", "record.json", `["entries",1,"detectorInputs"]`, `["sender","body"]`, "record_malformed"},
	{"reject-decision-not-supported-by-estimates", "record.json", `["entries",1,"detectorInputs"]`, `"body"`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",5,"evidence"]`, `["not a digest"]`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",5,"evidence"]`, `"x"`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",5,"threshold"]`, `11`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",5,"admitted"]`, `"yes"`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",4,"score"]`, `-1`, "record_malformed"},
	{"allow-restoration-gated-on-external-score", "record.json", `["entries",3,"configAfter"]`, `"config"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["entries",4,"refused"]`, `false`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["entries",4,"refused"]`, `"true"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["entries",3,"refusalReason"]`, `"x"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["entries",3,"grantChainDigest"]`, `"x"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["componentProfileDigest"]`, `"x"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "record.json", `["claims","authorityChainChecked"]`, `"yes"`, "record_malformed"},
	{"allow-isolated-agents-tool-call-refused", "receipt.json", `["reached","toolCalls"]`, `2`, "blast_radius_overstated"},
	{"allow-retrieval-inside-snapshot", "record.json", `["snapshotRoot"]`, `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`, "retrieval_admitted_outside_snapshot"},
	{"allow-retrieval-inside-snapshot", "record.json", `["snapshotRoot"]`, `"x"`, "record_malformed"},
	{"allow-refusal-over-present-edge", "record.json", `["entries",1,"reasonCode"]`, `"private_policy_rule_7"`, "closed_vocabulary_violation"},
	{"allow-refusal-over-present-edge", "record.json", `["entries",1,"reasonCode"]`, `7`, "record_malformed"},
	{"allow-blast-radius-counts-delivery-to-tainted-receiver", "receipt.json", `["reached","deliveries"]`, `1`, "blast_radius_understated"},
	{"allow-blast-radius-from-later-entry", "receipt.json", `["reached","toolCalls"]`, `0`, "blast_radius_understated"},
	{"allow-retrieval-inside-snapshot", "record.json", `["entries",1,"proof",0,0]`, `"middle"`, "closed_vocabulary_violation"},
	{"allow-retrieval-inside-snapshot", "record.json", `["entries",1,"proof"]`, `"x"`, "record_malformed"},
	{"allow-retrieval-inside-snapshot", "record.json", `["entries",1,"proof",0]`, `["left"]`, "record_malformed"},
	{"allow-retrieval-inside-snapshot", "record.json", `["entries",1,"documentDigest"]`, `"x"`, "record_malformed"},
	{"allow-retrieval-inside-snapshot", "record.json", `["claims","retrievalAttested"]`, `1`, "record_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `[]`, `[]`, "receipt_contract_id_missing"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["journal"]`, `5`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["journal","head"]`, `"x"`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["journal","runId"]`, `"run-other"`, "receipt_journal_mismatch"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["reached"]`, `{"agents":["agent-a"]}`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["reached","agents"]`, `["agent-a","agent-b","agent-c"]`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["reached","deliveries"]`, `-1`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["reached","toolCalls"]`, `0`, "blast_radius_understated"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["reached","deliveries"]`, `9`, "blast_radius_overstated"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["fromSeq"]`, `6`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["fromSeq"]`, `2`, "blast_radius_overstated"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["subject"]`, `3`, "receipt_malformed"},
	{"allow-blast-radius-receipt-recomputes", "receipt.json", `["extra"]`, `1`, "receipt_malformed"},
}

func cjJSON(t *testing.T, text string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return value
}

// cjSet replaces the value at path, or the whole value when path is empty.
func cjSet(t *testing.T, root any, path []any, value any) any {
	t.Helper()
	if len(path) == 0 {
		return value
	}
	switch node := root.(type) {
	case map[string]any:
		key := path[0].(string)
		node[key] = cjSet(t, node[key], path[1:], value)
	case []any:
		index, err := path[0].(json.Number).Int64()
		if err != nil {
			t.Fatal(err)
		}
		node[index] = cjSet(t, node[index], path[1:], value)
	default:
		t.Fatalf("path %v runs through a %T", path, root)
	}
	return root
}

func TestContainmentJournalStructuredEditsGiveTheirReasons(t *testing.T) {
	for _, edit := range cjEdits {
		t.Run(edit.member+" "+edit.path+"="+edit.value, func(t *testing.T) {
			root := cjJSON(t, string(cjFile(t, edit.member, edit.file)))
			path, _ := cjJSON(t, edit.path).([]any)
			files := map[string][]byte{edit.file: cjEncode(t, cjSet(t, root, path, cjJSON(t, edit.value)))}
			if got := cjDerivedFor(t, edit.member, files); !strings.Contains(got, "/"+edit.want+",") {
				t.Fatalf("want %s, got %q", edit.want, got)
			}
		})
	}
}

func TestContainmentJournalUnreadableManifestRows(t *testing.T) {
	dir := cjStage(t, cjControl, nil)
	manifest := filepath.Join(dir, "MANIFEST.json")
	body, err := os.ReadFile(manifest) // #nosec G304 -- a staged copy of the test's own corpus
	if err != nil {
		t.Fatal(err)
	}
	broken := bytes.Replace(body, []byte(`"vectors": [`), []byte(`"vectors": [7,`), 1)
	if err := os.WriteFile(manifest, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !strings.Contains(strings.Join(result.Findings, "; "), "a manifest row does not parse") {
		t.Fatalf("want a row finding, got %v", result.Findings)
	}
	if err := os.WriteFile(manifest, []byte(`{"suite": "containment-journal/v1", "vectors": 7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpusreaders.Judge(dir); err == nil {
		t.Fatal("want an error for a manifest that does not parse")
	}
}
