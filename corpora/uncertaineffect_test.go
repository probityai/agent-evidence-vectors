package corpora_test

// The uncertain-effect reader derives every decision from the record alone.
// Swapping one member's record for another's must move the derived decision,
// and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const ueDir = "vectors-uncertain-effect"

func ueStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ueDir)
	copyTree(t, corpusPath(ueDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ueRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ueDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestUncertainEffectCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(ueDir))
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

func TestUncertainEffectEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "identity-missing-key",
		"identity-missing-args-digest", "key-reused-args-changed", "dispatch-after-lease-expired",
		"dispatch-with-superseded-token", "retry-after-commit-timeout", "retry-under-new-key",
		"retry-after-lookup-not-final", "retry-after-key-retention-expired",
		"duplicate-effect-despite-deduplication", "unknown-released-at-expiry",
		"timeout-reported-committed", "timeout-reported-not-run",
		"reconciled-absent-reported-committed", "reconciled-present-still-unknown"}
	for _, from := range denied {
		t.Run("allow-confirmed-first-attempt with the record of "+from, func(t *testing.T) {
			dir := ueStage(t, "allow-confirmed-first-attempt", ueRead(t, from))
			if got := scDerived(t, dir, "allow-confirmed-first-attempt"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := ueStage(t, "retry-after-commit-timeout", ueRead(t, "allow-commit-timeout-reconciled-present"))
		if got := scDerived(t, dir, "retry-after-commit-timeout"); !strings.Contains(got, "derived allow/effect_held") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}

func TestUncertainEffectUnreadableInputsAreFindings(t *testing.T) {
	dir := ueStage(t, "allow-confirmed-first-attempt", "{")
	if got := scDerived(t, dir, "allow-confirmed-first-attempt"); !strings.Contains(got, "record.json does not parse") {
		t.Fatalf("want a parse finding, got %q", got)
	}
	later := strings.Replace(ueRead(t, "allow-confirmed-first-attempt"), "2026-10-28T12:00:01Z", "yesterday", 1)
	dir = ueStage(t, "allow-confirmed-first-attempt", later)
	if got := scDerived(t, dir, "allow-confirmed-first-attempt"); !strings.Contains(got, "not RFC 3339") {
		t.Fatalf("want a timestamp finding, got %q", got)
	}
}

func TestUncertainEffectDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), ueDir)
	copyTree(t, corpusPath(ueDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"effect_held"`, `"effect_held "`, 1)
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
	if err := os.WriteFile(path, []byte(`{"suite":"uncertain-effect/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
