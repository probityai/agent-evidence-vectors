package corpora_test

// The converted-argument-binding reader derives every decision from the case's
// files. Swapping one member's file for another's must move the derived
// decision, and the reader must report the move.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const cabDir = "vectors-converted-argument-binding"

func cabStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), cabDir)
	copyTree(t, corpusPath(cabDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

// cabStageShown replaces allow-unchanged's shown.json and re-binds the approval
// to the new bytes, so only the storable-bytes check can refuse it.
func cabStageShown(t *testing.T, body []byte) string {
	t.Helper()
	dir := cabStage(t, "allow-unchanged", "shown.json", body)
	path := filepath.Join(dir, "cases", "allow-unchanged", "record.json")
	record, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256(cabRead(t, "allow-unchanged", "shown.json"))
	fresh := sha256.Sum256(body)
	rebound := strings.Replace(string(record), hex.EncodeToString(old[:]), hex.EncodeToString(fresh[:]), 1)
	if rebound == string(record) {
		t.Fatal("the record does not carry the shown digest")
	}
	if err := os.WriteFile(path, []byte(rebound), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cabRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(cabDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestConvertedArgsCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(cabDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestConvertedArgsEachCheckMovesTheVerdict(t *testing.T) {
	// Each denied member's record, or one of its argument files, put into the
	// allowed member must move its derived decision to the denial.
	swaps := []struct{ member, file, want string }{
		{"contract-id-missing", "record.json", "derived deny/"},
		{"contract-id-unknown", "record.json", "derived deny/"},
		{"approved-digest-not-shown", "record.json", "derived deny/approval_not_bound_to_shown"},
		{"invalid-enum-approved", "raw.json", "derived deny/invalid_call_approved"},
		{"clock-default-rebuilds-differently", "rebuilt.json", "derived deny/rebuild_not_identical"},
		{"approver-edited-in-place", "record.json", "derived deny/call_mutated_after_approval"},
		{"bool-string-coerced", "executed.json", "derived deny/shown_not_executed"},
		{"float-truncated-to-int", "executed.json", "derived deny/shown_not_executed"},
		{"dict-repr-to-string", "executed.json", "derived deny/shown_not_executed"},
		{"constructor-default-hidden", "executed.json", "derived deny/shown_not_executed"},
	}
	for _, sw := range swaps {
		t.Run("allow-unchanged with "+sw.file+" of "+sw.member, func(t *testing.T) {
			dir := cabStage(t, "allow-unchanged", sw.file, cabRead(t, sw.member, sw.file))
			if got := cabDerived(t, dir, "allow-unchanged"); !strings.Contains(got, sw.want) {
				t.Fatalf("want %q in %q", sw.want, got)
			}
		})
	}
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := cabStage(t, "approver-edited-in-place", "record.json", cabRead(t, "allow-unchanged", "record.json"))
		if got := cabDerived(t, dir, "approver-edited-in-place"); !strings.Contains(got, "derived allow/bound") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
	t.Run("a replacement that drops the defaulted field", func(t *testing.T) {
		dir := cabStage(t, "allow-modify-full-call", "modified.json", cabRead(t, "modify-drops-defaulted-field", "modified.json"))
		if got := cabDerived(t, dir, "allow-modify-full-call"); !strings.Contains(got, "derived deny/modify_not_full_call") {
			t.Fatalf("want modify_not_full_call, got %q", got)
		}
	})
	t.Run("the executed key order alone does not move the verdict", func(t *testing.T) {
		dir := cabStage(t, "allow-unchanged", "executed.json", cabRead(t, "executed-key-order-only", "executed.json"))
		if got := cabDerived(t, dir, "allow-unchanged"); strings.Contains(got, "derived") ||
			strings.Contains(got, "shown equals executed") {
			t.Fatalf("a reordered executed file must stay allowed, got %q", got)
		}
	})
}

func cabDerived(t *testing.T, dir, id string) string {
	t.Helper()
	result, err := corpora.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	for _, m := range result.Members {
		if m.ID == id {
			return strings.Join(m.Findings, "; ")
		}
	}
	t.Fatalf("member %s is not in the result", id)
	return ""
}

func TestConvertedArgsStorableBytesAreRefused(t *testing.T) {
	cases := []struct{ name, body string }{
		{"duplicate member", `{"a": 1, "a": 2}`},
		{"NaN", `{"a": NaN}`},
		{"unpaired surrogate", `{"a": "\ud800"}`},
		{"integer past 2^53", `{"a": 9007199254740993}`},
		{"negative integer past 2^53", `{"a": [1, {"b": -9007199254740992}]}`},
		{"trailing data", `{"a": 1} {"b": 2}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cabDerived(t, cabStageShown(t, []byte(tc.body)), "allow-unchanged")
			if !strings.Contains(got, "derived deny/shown_not_storable") {
				t.Fatalf("want shown_not_storable, got %q", got)
			}
		})
	}
	t.Run("the largest safe integer is storable", func(t *testing.T) {
		got := cabDerived(t, cabStageShown(t, []byte(`{"a": 9007199254740991}`)), "allow-unchanged")
		if strings.Contains(got, "shown_not_storable") {
			t.Fatalf("got %q", got)
		}
	})
}

func TestConvertedArgsUnreadableInputsAreFindings(t *testing.T) {
	dir := cabStage(t, "allow-unchanged", "record.json", []byte("{"))
	if got := cabDerived(t, dir, "allow-unchanged"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("got %q", got)
	}
}

func TestConvertedArgsDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), cabDir)
	copyTree(t, corpusPath(cabDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"bound"`, `"bound "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("want a corpusDigest finding")
	}
	if err := os.WriteFile(path, []byte(`{"suite":"converted-argument-binding/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
