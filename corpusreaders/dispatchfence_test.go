package corpora_test

// The dispatch-fence reader derives every decision from the record alone.
// Swapping one member's record for another's must move the derived decision,
// and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const dfDir = "vectors-dispatch-fence"

func dfStage(t *testing.T, member, body string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), dfDir)
	copyTree(t, corpusPath(dfDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "record.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func dfRead(t *testing.T, member string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(dfDir), "cases", member, "record.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestDispatchFenceCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(dfDir))
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

func TestDispatchFenceEachCheckMovesTheVerdict(t *testing.T) {
	denied := []string{"contract-id-missing", "contract-id-unknown", "fence-rereads-state",
		"label-raised-between-check-and-fence", "declared-runtime-exceeds-ttl", "tool-outlives-hold",
		"second-dispatch-after-expiry", "commit-after-own-hold-expired"}
	for _, from := range denied {
		t.Run("allow-single-read with the record of "+from, func(t *testing.T) {
			dir := dfStage(t, "allow-single-read", dfRead(t, from))
			if got := scDerived(t, dir, "allow-single-read"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("a denied record with the allowed record", func(t *testing.T) {
		dir := dfStage(t, "tool-outlives-hold", dfRead(t, "allow-single-read"))
		if got := scDerived(t, dir, "tool-outlives-hold"); !strings.Contains(got, "derived allow/exclusive") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
	t.Run("the effect ending at the expiry is allowed and one second later is not", func(t *testing.T) {
		later := strings.Replace(dfRead(t, "allow-effect-ends-at-expiry"),
			`"endedAt": "2026-10-24T12:02:00Z"`, `"endedAt": "2026-10-24T12:02:01Z"`, 1)
		dir := dfStage(t, "allow-effect-ends-at-expiry", later)
		got := scDerived(t, dir, "allow-effect-ends-at-expiry")
		for _, want := range []string{"derived deny/hold_expired_before_effect_ended", "hold covers commit: false"} {
			if !strings.Contains(got, want) {
				t.Fatalf("want %q in %q", want, got)
			}
		}
	})
}

func TestDispatchFenceUnreadableInputsAreFindings(t *testing.T) {
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"contractId":"https://probityai.github.io/agent-evidence-observer/contract/dispatch-fence/v1",` +
			`"fence":{"acquiredAt":"soon","ttlSeconds":1},"effect":{"endedAt":"later"},"commit":{"at":"now"}}`,
			"does not parse"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := dfStage(t, "allow-single-read", tc.body)
			if got := scDerived(t, dir, "allow-single-read"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
}

func TestDispatchFenceDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), dfDir)
	copyTree(t, corpusPath(dfDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"exclusive"`, `"exclusive "`, 1)
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
	if err := os.WriteFile(path, []byte(`{"suite":"dispatch-fence/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
