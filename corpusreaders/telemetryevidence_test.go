package corpusreaders_test

// The telemetry-evidence reader derives every decision and reason from the
// record alone. Swapping a control member's record for a refusing member's must
// move the derived verdict, so a reader that lacks a rule fails a test here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const teDir = "vectors-telemetry-evidence"

func teStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), teDir)
	copyTree(t, corpusPath(teDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func teRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(teDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// teEdit returns a member's record after the edit has changed its parsed form.
func teEdit(t *testing.T, member string, edit func(record map[string]any)) string {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(teRead(t, member)), &record); err != nil {
		t.Fatal(err)
	}
	edit(record)
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// teWant stages the control with the given record and requires the derived
// verdict in the control's findings.
func teWant(t *testing.T, control, body, want string) {
	t.Helper()
	dir := teStage(t, control, body)
	if got := scDerived(t, dir, control); !strings.Contains(got, "derived "+want+",") {
		t.Fatalf("want derived %s, got %q", want, got)
	}
}

func TestTelemetryEvidenceCommittedCorpusIsClean(t *testing.T) {
	result, err := corpusreaders.Judge(corpusPath(teDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) != 35 {
		t.Fatalf("findings: %v members: %d", result.Findings, len(result.Members))
	}
	counts := result.CountsByVerdict()
	for _, verdict := range []string{"agrees", "contradicted", "cannot-tell"} {
		if counts[verdict] == 0 {
			t.Fatalf("every verdict must be present: %v", counts)
		}
	}
}

func TestTelemetryEvidenceEachDigestRuleMovesTheVerdict(t *testing.T) {
	control := "digest-jcs-positive"
	for from, want := range map[string]string{
		"evidence-ref-duplicate-member":     "contradicted/no_duplicate_member",
		"signed-id-flipped-reference":       "contradicted/signature",
		"signed-id-self-carried-key":        "contradicted/signer_pinned",
		"evidence-ref-duplicate-reference":  "contradicted/no_duplicate_reference",
		"evidence-ref-zero-of-n":            "contradicted/coverage",
		"digest-cbor-non-shortest-negative": "contradicted/canonical_form",
		"digest-python-default-separators":  "contradicted/consumed_copy_bound",
		"digest-float-repr-negative":        "contradicted/consumed_copy_bound",
		"digest-non-ascii-escaped-negative": "contradicted/consumed_copy_bound",
		"evidence-ref-zero-of-zero":         "cannot-tell/empty_denominator",
		"digest-undeclared-canonical-form":  "cannot-tell/undeclared_canonical_form",
		"signed-id-no-pin":                  "cannot-tell/signer_not_established",
		"signed-id-unsigned-required":       "cannot-tell/unsigned_manifest",
		"signed-id-null-signature":          "contradicted/record_shape",
	} {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			teWant(t, control, teRead(t, from), want)
		})
	}
	for _, from := range []string{"signed-id-pinned-key", "digest-cbor-deterministic-positive",
		"digest-raw-sha512-positive", "digest-astral-positive", "digest-empty-body-positive"} {
		dir := teStage(t, "signed-id-self-carried-key", teRead(t, from))
		if got := scDerived(t, dir, "signed-id-self-carried-key"); !strings.Contains(got, "derived agrees/digests_bind_consumed_copy,") {
			t.Fatalf("%s: want a derived agrees, got %q", from, got)
		}
	}
}

func TestTelemetryEvidenceUnreadableDigestRecordsAreRefusedOrFindings(t *testing.T) {
	control := "digest-jcs-positive"
	teWant(t, control, teEdit(t, control, func(r map[string]any) { r["manifest_text"] = "{" }),
		"contradicted/record_shape")
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		r["manifest_text"] = `{"schema_version":"other","refs":[]}`
	}), "contradicted/record_shape")
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		consumed := r["consumed"].(map[string]any)
		first := ""
		for k := range consumed {
			first = k
			break
		}
		consumed[first] = nil
	}), "cannot-tell/consumed_copy_unavailable")
	dir := teStage(t, control, "{")
	if got := scDerived(t, dir, control); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	dir = teStage(t, control, teEdit(t, control, func(r map[string]any) { delete(r, "manifest_text") }))
	if got := scDerived(t, dir, control); !strings.Contains(got, "the record cannot be judged") {
		t.Fatalf("want a cannot-be-judged finding, got %q", got)
	}
}

func TestTelemetryEvidenceEachLogRuleMovesTheVerdict(t *testing.T) {
	control := "log-clean"
	for from, want := range map[string]string{
		"log-outside-coverage-boundary": "contradicted/coverage_boundary",
		"log-resigned-other-key":        "contradicted/signer_pinned",
		"log-drop":                      "contradicted/sequence",
		"log-swap":                      "contradicted/sequence",
		"log-status-flip":               "contradicted/chain_order",
		"log-link-rewrite":              "contradicted/chain_order",
		"log-body-edit":                 "contradicted/chain_order",
		"log-tail-truncation":           "contradicted/head_anchor",
		"log-relinked-rewrite":          "contradicted/head_anchor",
		"log-no-head":                   "cannot-tell/head_not_anchored",
		"log-empty":                     "cannot-tell/empty_denominator",
	} {
		t.Run("the control with the record of "+from, func(t *testing.T) {
			teWant(t, control, teRead(t, from), want)
		})
	}
	dir := teStage(t, "log-drop", teRead(t, "log-boundary-first-seq-offset"))
	if got := scDerived(t, dir, "log-drop"); !strings.Contains(got, "derived agrees/event_log_complete,") {
		t.Fatalf("want a derived agrees, got %q", got)
	}
}

func TestTelemetryEvidenceLogEdgesNotInTheCorpus(t *testing.T) {
	control := "log-clean"
	// A repeated line is a repeated event digest, which is refused before the order is read.
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		line := strings.SplitN(r["events_text"].(string), "\n", 2)[0]
		r["events_text"] = line + "\n" + line
	}), "contradicted/no_duplicate_event")
	// A head whose count was edited no longer verifies under its signature.
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		var head map[string]any
		if err := json.Unmarshal([]byte(r["head_text"].(string)), &head); err != nil {
			t.Fatal(err)
		}
		head["count"] = 1
		body, err := json.Marshal(head)
		if err != nil {
			t.Fatal(err)
		}
		r["head_text"] = string(body)
	}), "contradicted/signature")
	// An event whose seq is a float is not a log event.
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		r["events_text"] = `{"seq":1.5,"prev":"` + strings.Repeat("0", 64) + `"}`
	}), "contradicted/record_shape")
	// A repeated member inside one event is refused before anything else is read.
	teWant(t, control, teEdit(t, control, func(r map[string]any) {
		r["events_text"] = `{"seq":1,"seq":2,"prev":"` + strings.Repeat("0", 64) + `"}`
	}), "contradicted/no_duplicate_member")
}
